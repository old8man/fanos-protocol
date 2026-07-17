//! System-metric acquisition — the node's raw local vitals (CPU, memory, disk, network).
//!
//! These raw signals are the *sensory input* to a node's self-model: each node's resource
//! [`pressure`](SystemSample::pressure) becomes its scalar in the cell's coherence correlation, so
//! correlated stress across a cell surfaces as a falling `Φ` and, ultimately, a syndrome. Acquisition
//! must be cheap — it runs every observation window on every node — so the design is:
//!
//! * **Pure parsers, platform-independent.** The `/proc` parsers and the rate math below take bytes
//!   and numbers, never touch the OS, and are unit-tested with fixtures on every platform. Only a
//!   thin I/O shim is platform-gated, so the load-bearing logic is always compiled and covered
//!   (important here: CI runs on macOS + wasm, where the Linux I/O path is never built).
//! * **Linux: direct `/proc`, cached handles, reused buffer.** [`linux::ProcProbe`] holds its `/proc`
//!   files open and re-reads them into one reused buffer each sample — the maximally efficient path
//!   on the dominant server platform: no process spawning, no per-sample file opens, no allocation.
//!   It is `#![forbid(unsafe_code)]`-clean (pure file I/O).
//! * **Other platforms via the [`SystemProbe`] trait.** A `sysinfo`-backed probe (opt-in) or a custom
//!   backend plugs in behind the trait without changing any caller; the default off-Linux probe
//!   reports `available = false` rather than guessing.
//!
//! The probe is a *driver-side sensor*, not part of the pure engine: it may read the OS clock and
//! files. Its output ([`SystemSample`]) is what crosses into the sans-I/O engine as an input.

/// A node's raw local vitals at one instant. Rates are per second since the previous sample.
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub struct SystemSample {
    /// Fraction of CPU time busy since the previous sample, in `[0, 1]`.
    pub cpu_busy: f32,
    /// Fraction of physical memory in use, in `[0, 1]`.
    pub mem_used: f32,
    /// 1-minute load average normalized per core (`1.0` = one core-equivalent fully queued).
    pub load_per_core: f32,
    /// Bytes/second received across all non-loopback interfaces.
    pub net_rx_bps: f64,
    /// Bytes/second transmitted across all non-loopback interfaces.
    pub net_tx_bps: f64,
    /// Bytes/second read from block devices.
    pub disk_read_bps: f64,
    /// Bytes/second written to block devices.
    pub disk_write_bps: f64,
    /// This process's resident set size in bytes (`0` if unknown).
    pub proc_rss: u64,
    /// Whether a real platform probe produced this sample (`false` = unavailable / stub).
    pub available: bool,
}

impl SystemSample {
    /// A single scalar in `[0, 1]` summarizing resource pressure — the node's default health signal
    /// for the cell correlation. A weighted blend of CPU, memory, and (core-normalized, clamped)
    /// load. This is the sensor reading the coherence layer folds into the cell's `Γ`.
    #[must_use]
    pub fn pressure(&self) -> f64 {
        let cpu = f64::from(self.cpu_busy).clamp(0.0, 1.0);
        let mem = f64::from(self.mem_used).clamp(0.0, 1.0);
        let load = f64::from(self.load_per_core).clamp(0.0, 1.0);
        (0.5 * cpu + 0.3 * mem + 0.2 * load).clamp(0.0, 1.0)
    }
}

/// A source of [`SystemSample`]s — the platform-optimal backend, behind one trait so callers are
/// platform-agnostic and a better backend can be swapped in without touching them.
pub trait SystemProbe {
    /// Sample the node's vitals now. `now_nanos` is a monotonic nanosecond clock the driver supplies
    /// (so rate computation stays deterministic and testable); the probe stores the previous reading.
    fn sample(&mut self, now_nanos: u64) -> SystemSample;
}

/// A probe that always reports "unavailable" — the honest default where no optimized backend exists
/// (rather than fabricating numbers). Also the deterministic choice for tests and the simulator.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullProbe;

impl SystemProbe for NullProbe {
    fn sample(&mut self, _now_nanos: u64) -> SystemSample {
        SystemSample::default()
    }
}

/// A per-second rate from two monotonically-increasing counters and the elapsed time. `0.0` if the
/// clock did not advance or the counter went backwards (a wrap or reset — never a negative rate).
#[must_use]
#[allow(clippy::cast_precision_loss)] // counters within f64's exact-integer range in practice
pub fn rate(prev: u64, now: u64, dt_nanos: u64) -> f64 {
    if dt_nanos == 0 || now < prev {
        return 0.0;
    }
    (now - prev) as f64 * 1_000_000_000.0 / (dt_nanos as f64)
}

/// Aggregate CPU times from `/proc/stat`'s first line, in USER_HZ jiffies.
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub struct CpuTimes {
    /// Idle + iowait jiffies.
    pub idle: u64,
    /// All jiffies (idle + busy).
    pub total: u64,
}

impl CpuTimes {
    /// Busy fraction between an earlier and a later reading, in `[0, 1]`; `0.0` if time did not move.
    #[must_use]
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    pub fn busy_fraction(prev: Self, now: Self) -> f32 {
        let dt = now.total.wrapping_sub(prev.total);
        let di = now.idle.wrapping_sub(prev.idle);
        if dt == 0 || di > dt {
            return 0.0;
        }
        ((dt - di) as f64 / dt as f64) as f32
    }
}

/// Parse `/proc/stat`'s aggregate `cpu` line (`cpu user nice system idle iowait irq softirq steal
/// …`). `idle = idle + iowait`; `total` = the sum of all fields. `None` if it is not a `cpu` line.
#[must_use]
pub fn parse_proc_stat_cpu(contents: &str) -> Option<CpuTimes> {
    let line = contents.lines().next()?;
    let mut it = line.split_ascii_whitespace();
    if it.next()? != "cpu" {
        return None;
    }
    let mut fields = [0u64; 8];
    for slot in &mut fields {
        // Missing trailing fields (older kernels) default to 0.
        *slot = it.next().and_then(|t| t.parse().ok()).unwrap_or(0);
    }
    let idle = fields.get(3)?.saturating_add(*fields.get(4)?); // idle + iowait
    let total = fields.iter().fold(0u64, |a, &x| a.saturating_add(x));
    Some(CpuTimes { idle, total })
}

/// Parse `/proc/meminfo` for `(MemTotal, MemAvailable)` in kB. `None` if `MemTotal` is absent.
#[must_use]
pub fn parse_meminfo(contents: &str) -> Option<(u64, u64)> {
    let mut total = None;
    let mut avail = None;
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = rest
                .split_ascii_whitespace()
                .next()
                .and_then(|t| t.parse().ok());
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            avail = rest
                .split_ascii_whitespace()
                .next()
                .and_then(|t| t.parse().ok());
        }
    }
    let total = total?;
    // Fall back to MemTotal (0% used) if MemAvailable is missing (very old kernels).
    Some((total, avail.unwrap_or(total)))
}

/// Memory-used fraction `1 − avail/total` in `[0, 1]` from a `(total_kb, avail_kb)` pair.
#[must_use]
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
pub fn mem_used_fraction(total_kb: u64, avail_kb: u64) -> f32 {
    if total_kb == 0 {
        return 0.0;
    }
    let used = total_kb.saturating_sub(avail_kb) as f64 / total_kb as f64;
    used.clamp(0.0, 1.0) as f32
}

/// Sum `(rx_bytes, tx_bytes)` across all non-loopback interfaces in `/proc/net/dev`. Header lines
/// (no colon) and the `lo` interface are skipped; each data line is `iface: rx_bytes … tx_bytes …`
/// with `rx_bytes` at post-colon index 0 and `tx_bytes` at index 8.
#[must_use]
pub fn parse_net_dev(contents: &str) -> (u64, u64) {
    let mut rx = 0u64;
    let mut tx = 0u64;
    for line in contents.lines() {
        let Some((iface, rest)) = line.split_once(':') else {
            continue;
        };
        if iface.trim() == "lo" {
            continue;
        }
        let mut fields = rest.split_ascii_whitespace();
        let rx_bytes = fields.next().and_then(|t| t.parse::<u64>().ok());
        let tx_bytes = fields.nth(7).and_then(|t| t.parse::<u64>().ok()); // index 8 after next()
        if let (Some(r), Some(t)) = (rx_bytes, tx_bytes) {
            rx = rx.saturating_add(r);
            tx = tx.saturating_add(t);
        }
    }
    (rx, tx)
}

/// Parse `/proc/loadavg`'s first field (the 1-minute load average). `None` if malformed.
#[must_use]
pub fn parse_loadavg(contents: &str) -> Option<f32> {
    contents
        .split_ascii_whitespace()
        .next()
        .and_then(|t| t.parse().ok())
}

/// Parse resident pages from `/proc/self/statm` (field index 1 = resident set size in pages). `None`
/// if malformed. Multiply by the page size for bytes.
#[must_use]
pub fn parse_statm_resident_pages(contents: &str) -> Option<u64> {
    contents
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|t| t.parse().ok())
}

/// Sum `(bytes_read, bytes_written)` across physical block devices in `/proc/diskstats`. Sectors are
/// 512 bytes. Partition and virtual lines are skipped so whole-disk I/O is not double-counted.
/// Fields: `major minor name(2) reads rmerge sectors_read(5) … writes wmerge sectors_written(9) …`.
#[must_use]
pub fn parse_diskstats(contents: &str) -> (u64, u64) {
    let mut read = 0u64;
    let mut written = 0u64;
    for line in contents.lines() {
        let mut it = line.split_ascii_whitespace();
        let Some(name) = it.by_ref().nth(2) else {
            continue; // consumes indices 0,1,2 → name at 2
        };
        let sectors_read = it.nth(2).and_then(|t| t.parse::<u64>().ok()); // now at 3 → index 5
        let sectors_written = it.nth(3).and_then(|t| t.parse::<u64>().ok()); // now at 6 → index 9
        let (Some(rs), Some(ws)) = (sectors_read, sectors_written) else {
            continue;
        };
        if is_virtual_or_partition(name) {
            continue;
        }
        read = read.saturating_add(rs);
        written = written.saturating_add(ws);
    }
    (read.saturating_mul(512), written.saturating_mul(512))
}

/// Whether a `/proc/diskstats` device name is a partition or virtual device we skip (to avoid
/// double-counting whole-disk I/O): `loop*`, `ram*`, `dm-*`, `zram*`, and `sdaN`/`nvme0n1pN` partitions.
fn is_virtual_or_partition(name: &str) -> bool {
    if name.starts_with("loop")
        || name.starts_with("ram")
        || name.starts_with("dm-")
        || name.starts_with("zram")
    {
        return true;
    }
    // A trailing digit marks a partition on `sd*`/`vd*`/`hd*`, or `pN` on `nvme*`/`mmcblk*`.
    if name.chars().last().is_some_and(|c| c.is_ascii_digit()) {
        if name.starts_with("nvme") || name.starts_with("mmcblk") {
            return name.contains('p');
        }
        return name.starts_with("sd") || name.starts_with("vd") || name.starts_with("hd");
    }
    false
}

/// The best system probe for the platform this was compiled for: an optimized `ProcProbe` on Linux,
/// otherwise a [`NullProbe`] (until an opt-in backend is enabled). Boxed so callers stay agnostic.
#[cfg(feature = "std")]
#[must_use]
pub fn platform_probe() -> Box<dyn SystemProbe + Send> {
    #[cfg(target_os = "linux")]
    if let Some(p) = linux::ProcProbe::open() {
        return Box::new(p);
    }
    Box::new(NullProbe)
}

#[cfg(all(feature = "std", target_os = "linux"))]
pub mod linux {
    //! The Linux `/proc` probe: open the vitals files once, re-read into one reused buffer each sample.

    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    use super::{
        CpuTimes, SystemProbe, SystemSample, mem_used_fraction, parse_diskstats, parse_loadavg,
        parse_meminfo, parse_net_dev, parse_proc_stat_cpu, parse_statm_resident_pages, rate,
    };

    /// A cached-handle `/proc` reader. Holds each vitals file open and one reusable buffer, so a
    /// sample is a set of `seek(0) + read` calls with no opens and no allocation.
    pub struct ProcProbe {
        stat: File,
        meminfo: File,
        net_dev: File,
        diskstats: File,
        loadavg: File,
        statm: File,
        buf: String,
        page_size: u64,
        prev: Option<Prev>,
    }

    struct Prev {
        cpu: CpuTimes,
        net_rx: u64,
        net_tx: u64,
        disk_read: u64,
        disk_write: u64,
        at_nanos: u64,
    }

    impl ProcProbe {
        /// Open the `/proc` vitals files. `None` if `/proc` is unavailable.
        #[must_use]
        pub fn open() -> Option<Self> {
            Some(Self {
                stat: File::open("/proc/stat").ok()?,
                meminfo: File::open("/proc/meminfo").ok()?,
                net_dev: File::open("/proc/net/dev").ok()?,
                diskstats: File::open("/proc/diskstats").ok()?,
                loadavg: File::open("/proc/loadavg").ok()?,
                statm: File::open("/proc/self/statm").ok()?,
                buf: String::with_capacity(8192),
                page_size: 4096, // mainstream Linux page size; a syscall would need `unsafe`.
                prev: None,
            })
        }
    }

    /// Rewind and read a `/proc` file into `out`, tolerating errors (parsers handle empty input).
    fn slurp(f: &mut File, out: &mut String) {
        out.clear();
        if f.seek(SeekFrom::Start(0)).is_ok() {
            let _ = f.read_to_string(out);
        }
    }

    impl SystemProbe for ProcProbe {
        #[allow(clippy::cast_precision_loss)]
        fn sample(&mut self, now_nanos: u64) -> SystemSample {
            // Each file is slurped into the shared buffer and parsed into owned values before the next.
            slurp(&mut self.stat, &mut self.buf);
            let cpu = parse_proc_stat_cpu(&self.buf).unwrap_or_default();
            slurp(&mut self.meminfo, &mut self.buf);
            let (mem_total, mem_avail) = parse_meminfo(&self.buf).unwrap_or((0, 0));
            slurp(&mut self.net_dev, &mut self.buf);
            let (net_rx, net_tx) = parse_net_dev(&self.buf);
            slurp(&mut self.diskstats, &mut self.buf);
            let (disk_read, disk_write) = parse_diskstats(&self.buf);
            slurp(&mut self.loadavg, &mut self.buf);
            let load = parse_loadavg(&self.buf).unwrap_or(0.0);
            slurp(&mut self.statm, &mut self.buf);
            let rss_pages = parse_statm_resident_pages(&self.buf).unwrap_or(0);

            let cores = std::thread::available_parallelism().map_or(1.0, |n| n.get() as f32);
            let mut s = SystemSample {
                cpu_busy: 0.0,
                mem_used: mem_used_fraction(mem_total, mem_avail),
                load_per_core: load / cores,
                net_rx_bps: 0.0,
                net_tx_bps: 0.0,
                disk_read_bps: 0.0,
                disk_write_bps: 0.0,
                proc_rss: rss_pages.saturating_mul(self.page_size),
                available: true,
            };
            if let Some(prev) = &self.prev {
                let dt = now_nanos.saturating_sub(prev.at_nanos);
                s.cpu_busy = CpuTimes::busy_fraction(prev.cpu, cpu);
                s.net_rx_bps = rate(prev.net_rx, net_rx, dt);
                s.net_tx_bps = rate(prev.net_tx, net_tx, dt);
                s.disk_read_bps = rate(prev.disk_read, disk_read, dt);
                s.disk_write_bps = rate(prev.disk_write, disk_write, dt);
            }
            self.prev = Some(Prev {
                cpu,
                net_rx,
                net_tx,
                disk_read,
                disk_write,
                at_nanos: now_nanos,
            });
            s
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn cpu_line_parses_and_busy_fraction_is_correct() {
        let prev = parse_proc_stat_cpu("cpu  100 0 100 800 0 0 0 0 0 0\nintr ...").unwrap();
        assert_eq!(prev.total, 1000, "sum of the first 8 fields (100+100+800)");
        assert_eq!(prev.idle, 800);
        let now = parse_proc_stat_cpu("cpu  150 0 150 900 0 0 0 0 0 0").unwrap();
        // total 1200, idle 900 → Δtotal = 200, Δidle = 100 → busy = 100/200 = 0.5.
        assert_eq!(CpuTimes::busy_fraction(prev, now), 0.5);
    }

    #[test]
    fn non_cpu_first_line_is_rejected() {
        assert!(parse_proc_stat_cpu("intr 1 2 3").is_none());
    }

    #[test]
    fn meminfo_used_fraction() {
        let (total, avail) =
            parse_meminfo("MemTotal:       16000 kB\nMemFree: 100 kB\nMemAvailable:    4000 kB\n")
                .unwrap();
        assert_eq!((total, avail), (16000, 4000));
        assert_eq!(mem_used_fraction(total, avail), 0.75); // 1 - 4000/16000
        assert_eq!(mem_used_fraction(0, 0), 0.0);
    }

    #[test]
    fn net_dev_sums_non_loopback() {
        let sample = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs
    lo: 1000       10    0    0    0     0          0         0   2000       10    0
  eth0: 5000       50    0    0    0     0          0         0   7000       70    0
  eth1: 100        1     0    0    0     0          0         0    200        2    0
";
        let (rx, tx) = parse_net_dev(sample);
        assert_eq!(rx, 5100, "eth0+eth1 rx, lo excluded");
        assert_eq!(tx, 7200, "eth0+eth1 tx");
    }

    #[test]
    fn diskstats_sums_physical_only() {
        let sample = "\
   8       0 sda 100 0 2000 0 50 0 1000 0 0 0 0
   8       1 sda1 90 0 1800 0 40 0 800 0 0 0 0
 259       0 nvme0n1 200 0 4000 0 60 0 2000 0 0 0 0
 259       1 nvme0n1p1 190 0 3800 0 55 0 1900 0 0 0 0
   7       0 loop0 1 0 8 0 0 0 0 0 0 0 0
";
        let (read, written) = parse_diskstats(sample);
        // Only sda + nvme0n1 whole disks: sectors read 2000+4000, written 1000+2000, ×512.
        assert_eq!(read, 6000 * 512);
        assert_eq!(written, 3000 * 512);
    }

    #[test]
    fn virtual_and_partition_detection() {
        assert!(is_virtual_or_partition("loop0"));
        assert!(is_virtual_or_partition("dm-1"));
        assert!(is_virtual_or_partition("sda1"));
        assert!(is_virtual_or_partition("nvme0n1p2"));
        assert!(!is_virtual_or_partition("sda"));
        assert!(!is_virtual_or_partition("nvme0n1"));
        assert!(!is_virtual_or_partition("vdb"));
    }

    #[test]
    fn loadavg_and_statm() {
        assert_eq!(parse_loadavg("0.75 0.50 0.30 1/234 5678").unwrap(), 0.75);
        assert_eq!(
            parse_statm_resident_pages("1000 512 128 10 0 300 0").unwrap(),
            512
        );
    }

    #[test]
    fn rate_is_per_second_and_never_negative() {
        assert_eq!(rate(0, 1000, 500_000_000), 2000.0); // 1000 B / 0.5 s
        assert_eq!(rate(1000, 500, 1_000_000_000), 0.0, "counter reset → 0");
        assert_eq!(rate(0, 1000, 0), 0.0, "no elapsed time → 0");
    }

    #[test]
    fn pressure_blends_and_clamps() {
        let s = SystemSample {
            cpu_busy: 1.0,
            mem_used: 1.0,
            load_per_core: 2.0,
            ..Default::default()
        };
        assert_eq!(s.pressure(), 1.0, "saturated resources → full pressure");
        assert_eq!(SystemSample::default().pressure(), 0.0);
    }

    #[test]
    fn null_probe_is_unavailable() {
        assert!(!NullProbe.sample(0).available);
    }
}
