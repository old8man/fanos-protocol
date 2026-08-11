//! Node configuration: listen address, persistent identity, bootstrap peers, and roles.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use fanos_calypso::hosting::Share;
use fanos_core::roles::{Role, RoleSet as CoreRoleSet};
use fanos_geometry::Triple;
use fanos_keygen::recovery::RecoveryAuthoritySet;
use fanos_quic::{Environment, Morph};
use fanos_pqcrypto::sig::HybridVerifier;
use fanos_vrf::vss::{VssCommitment, VssShare};

use crate::error::NodeError;
use crate::poros::DescriptorBinding;

/// The default beacon epoch period (§7.6). Ten minutes is a conservative moving-target cadence: long
/// enough that per-epoch coordinate reshuffle + re-handshake churn is modest, short enough that a
/// grinded seat or a censor's traffic-shape classifier is invalidated well within an attack window.
/// A deployment tunes it via [`NodeConfig::epoch_period`]; all nodes on a network should share it so
/// their epochs stay aligned.
pub const DEFAULT_EPOCH_PERIOD: Duration = Duration::from_secs(600);

/// Default mean Poisson mixing delay a **relay** holds each forwarded onion hop for (spec §L5/V7): a batch of
/// onions then leaves **reordered**, so which cell is which is not readable from arrival order.
/// Non-zero by default so the shipping relay actually defends (closing audit S1-H1); an operator trading
/// anonymity for latency can lower it, and it is inert on a non-relay (only a relay runs the mixnet).
///
/// **Measured correction (2026-07-26).** This constant used to claim it breaks "the per-hop timing correlation a global
/// passive adversary (T2) uses". **It does not, and the measurement is flat.** Sweeping it against the GPA's
/// input-rate/output-rate correlation (`fanos-sim/tests/traffic_analysis.rs`) gives *the same* `r = 0.643` at 50 ms,
/// 120 ms, 250 ms, 500 ms, 1000 ms and 2000 ms, against 1.000 with no mixing at all. The reason is structural: a relay emits on **cover slots**, so emission
/// *times* are set by [`DEFAULT_COVER_INTERVAL`], never by this value.
///
/// **Second correction (2026-08-07, #181).** The sentence that stood here went on to say the mix delay "only chooses
/// *which* queued cell fills a slot", crediting it with intra-batch reordering. **It does not do that either.** The
/// queued cell is picked by `cover_prf_unit` — a PRF keyed on the router's secret `mix_seed`, at
/// `threshold_router.rs:379` — and `mean_delay` is not an input to it. With cover on, this value moves neither the
/// emission times nor the order, and `forward_send` never reads it: the cover branch returns first.
///
/// So what it is, stated plainly: **the mixing mode for a relay with cover OFF.** `forward_send`'s own doc says so
/// exactly. Both defaults are non-zero as defence in depth — an operator who zeroes `cover_interval` to save
/// bandwidth still gets a per-cell exponential delay rather than an immediate forward. It is not a second defence
/// running alongside cover; it is the one that takes over when cover stops.
///
/// Measured, not argued: delivery through a composed relay cell takes 200 ms at means of 0, 1 s, 5 s, 60 s **and
/// 600 s** with cover on (`fanos-sim/tests/composed_relay.rs`). A 600 s mean cannot produce 200 ms.
///
/// # Provenance, and why this constant cannot be re-derived today (#187, UHM `316edd9`)
///
/// **The `120 ms` came from a knee sweep on `PG(2,7)`** (`252815b`, 2026-07-26). The very next commit
/// (`4ba78c3`, 2026-07-27) landed the fixed-slot onion layout, which made `depth_for(8) == 1` — so the
/// sweep's own 2-hop circuit stopped building, and the commit after that formalised the `#[ignore]` class
/// that keeps the breakage from ever being run into. **One day** between the number shipping and its
/// derivation becoming unbuildable, and it has stayed unbuildable since.
///
/// There is nowhere to port it. `Node::start` dispatches only `q ∈ {2, 4, 7, 31}`, and Fano — the sole
/// dispatchable plane whose `depth_for` still reaches 2 — has `K = 2` distinct-combiner circuits, so its
/// linkability floor is `1/2`: a knee sweep there *starts at chance* and cannot discriminate a schedule.
///
/// So by UHM's own name for it this is a **fossil**: a constant with no incoming observations is a fixed
/// point of any transmission chain, because its only source is itself. The discipline that rule prescribes
/// is a *revision clock*, and this one has it —
/// [`the_mixnet_defaults_revision_clock_has_not_rung`](self::tests) fails the moment the sweep becomes
/// buildable again, so the obligation cannot become satisfiable unnoticed.
///
/// **What unblocks it:** `THRESHOLD_ONION_LEN` large enough that `depth_for(slot_len(8)) ≥ 2`. The clock
/// computes that from the two functions rather than restating a number, so it moves when they do.
pub const DEFAULT_MIX_DELAY: Duration = Duration::from_millis(120);

/// Default mean interval between a **relay**'s constant-size **cover cells** (spec §L5/V8): the router's send
/// rate and packet size then reveal nothing about whether it is carrying real traffic (audit E1/S1-H1). Non-zero
/// by default so the GPA defence is on; an operator trading anonymity for bandwidth can raise or zero it.
///
/// **This constant, not the mix delay, is the timing defence** — and the trade is steep enough to be chosen against data
/// rather than picked.
///
/// ## ⚠️ RETRACTION — my GPA timing measurement was not a valid test, and its conclusion is withdrawn
///
/// An earlier version of this comment reported that the shipping configuration reduces a global passive adversary's
/// per-hop timing correlation only from `1.000` to `0.975`, called the timing channel "essentially undefended", and said
/// it contradicted spec §8.2. **That conclusion is withdrawn: the metric measured something no design can defend.**
///
/// Two independent errors, both mine:
///
/// 1. **The metric penalises conservation, not weak mixing.** A relay neither drops nor manufactures real cells, so over
///    any window much longer than the mix delay, cells-out *must* equal cells-in. Maximising in/out rate correlation over
///    the adversary's bin width therefore drives it toward 1 for *any* finite delay. Checked against an **ideal**
///    independent-exponential mix: mean 50 ms leaves `r = 0.712` at 100 ms bins, and the correlation only vanishes once
///    the mean exceeds the bin. The shipping router is performing about as well as a perfect mix at its mean — the number
///    was measuring the mean, and the conservation law, not a defect.
/// 2. **A single flow has an anonymity set of one.** My harness pushed one flow through the cell and asked whether it was
///    visible. It is, necessarily. Anonymity is not "is a lone flow invisible" but "among several concurrent flows, can
///    the adversary *match* inputs to outputs better than chance". Cover and mixing exist to create that confusion, and a
///    one-flow experiment removes the very thing being tested.
///
/// So the correct experiment is a **linkability** measurement over concurrent flows, and it has not been run. What
/// survives from the work is narrower and still worth having: the **volume** channel is genuinely masked (leak slope
/// 0.000, displacement being rate-independent), measured on both engines; and the mix delay's original doc claim — that it
/// breaks per-hop timing correlation — remains wrong for the reason below, since that correlation is not what it moves.
///
/// The lesson, since it cost three revisions: a metric that an *ideal* implementation also fails is measuring the
/// physics, not the implementation. Check the ideal reference before reporting a defect.
///
/// For reference, the same metric on the *Lite* `NyxNode` engine
/// (`fanos-sim/tests/traffic_analysis.rs::sweep_timing_correlation_against_the_mix_delay`), with the mix delay held at
/// this crate's [`DEFAULT_MIX_DELAY`] — better than the shipping router, but still far from zero:
///
/// | cover interval | GPA rate correlation |
/// |---|---|
/// | 150 ms | 0.500 |
/// | 300 ms | **0.475 — the minimum measured** |
/// | **500 ms (this default)** | **0.546** |
/// | 1000 ms | 0.643 |
/// | 3000 ms | 1.000 — no defence at all |
///
/// **This table was stale for two months and said so in bold (#187).** It marked the 1000 ms row "(this default)" and
/// quoted 0.643 as the shipping exposure; `252815b` had moved the default to 500 ms, and 500 was in no sweep at all —
/// the sweep held its mix axis at the *former* 50 ms and its cover axis at 150/300/1000/3000. The measurement now
/// imports these constants instead of copying them, and folds the live value into every axis, so the shipped point
/// cannot fall out of a hand-written list again.
///
/// The correlation is **maximised over the adversary's observation timescale**, because the adversary picks it — and
/// restricted to bin widths with at least 30 samples, because Pearson over a handful of points reaches 1.000 by chance.
/// Both constraints matter and both were got wrong first: a single 100 ms bin **understates** the exposure (0.445 at
/// this schedule) since it is not the attacker's choice, and an unconstrained maximum **overstates** it (0.999 on
/// 2000 ms bins) on five-sample bins.
///
/// The honest reading is worse than "a substantial residual", and it is not what §8.2's "strong against a GPA" implies:
/// **no configuration measured brings this channel near zero.** The best tested value leaves `r ≈ 0.48`, this default
/// `r ≈ 0.55`, and 3 s removes the defence entirely. The volume channel *is* fully masked at all of these (leak slope
/// 0.000 — displacement does not depend on rate), which makes timing the binding constraint and this table the real GPA
/// exposure.
///
/// **The curve is not monotone, which is the reason this is not a dial.** Halving the interval to 300 ms buys
/// `0.546 → 0.475` for 1.67× the cover bandwidth; halving it *again* to 150 ms makes the channel **worse** (0.500).
/// Spending more does not keep buying less exposure, so there is no operator trade to expose here — the conclusion is
/// that **constant-rate cover on a fixed clock is the wrong instrument for the timing channel.** A relay's emission
/// times track its input envelope at some timescale regardless of the slot period, because the queue length does.
/// Closing this needs emission **decoupled from arrival** — a continuous-time (Poisson) mix, where each cell's delay is
/// independently exponential and cover is itself Poisson, so the output process is independent of the input rate.
/// Recorded as an open design gap, not a dial.
///
/// # Provenance: the same fossil, same day, same sweep (#187, UHM `316edd9`)
///
/// The `500 ms` was set by the identical `PG(2,7)` knee sweep as [`DEFAULT_MIX_DELAY`], in the same commit,
/// and became unreproducible on the same day and for the same reason. See that constant's provenance
/// section for the mechanism and the unblocking condition; the revision clock covers both, because one
/// sweep produced both and one measurement will have to re-derive both.
///
/// Re-measured since at the live mix delay (`e26dbc5`): exposure `0.546` at this default, and the curve is
/// **non-monotone** — `300 ms` reads `0.475`, better than the shipping value. That is a live reason to
/// re-derive, not merely a stale provenance.
pub const DEFAULT_COVER_INTERVAL: Duration = Duration::from_millis(500);

/// The distributed-beacon parameters a node needs to run the live epoch clock (§7.6, #108). With
/// `beacon = Some(..)` the node composes an [`OverlayBeaconNode`](crate::OverlayBeaconNode): it
/// verifies and adopts the threshold-DVRF rounds the anchors flood — needing only the public
/// `commitment` and `threshold` — and advances its epoch as the network beacon advances (which in turn
/// rotates rendezvous lines, cover schedules, and the coordinate reshuffle). `share = Some(..)`
/// additionally makes it an **anchor** that contributes partials; `None` is a pure **consumer**. With
/// `beacon = None` the node runs a bare [`OverlayNode`](fanos_runtime::OverlayNode), pinned at genesis
/// (the pre-beacon behaviour), so this is fully backward-compatible.
#[derive(Clone)]
pub struct BeaconParams {
    /// This network's **public name** — the value epoch 0's coordinates are drawn against.
    ///
    /// Independent of `commitment` on purpose; see [`NetworkId`](crate::NetworkId) for why the two were the
    /// same value and what separating them does and does not buy (#98).
    pub network_id: crate::NetworkId,
    /// The beacon group's public commitment — a genesis parameter shared across the network.
    pub commitment: VssCommitment,
    /// The DVRF reconstruction threshold `t`.
    pub threshold: usize,
    /// This node's beacon share if it is an anchor; `None` for a pure consumer.
    pub share: Option<VssShare>,
    /// The **recovery authority committee** — the trust root that may order a threshold change.
    ///
    /// A *committee*, not a key, and the asymmetry that forced it is worth stating where an operator
    /// provisions it: the beacon secret is `t`-of-`n` so no single party holds it, and until this became a
    /// set, the authority that could order that key REPLACED was one verifier — one file on one founder's
    /// disk. Coordinates derive from the beacon (`docs/design-governance.md` §2.1), so that file was the
    /// placement of every node in the cell. The quorum is a strict majority and is **derived from the member
    /// count, never configured** ([`fanos_keygen::recovery::authority_quorum`]) — a quorum field one value
    /// too loose is the `CellParams` fork all over again.
    ///
    /// Without it a beacon refuses every reshare trigger and every re-genesis
    /// (`BeaconNode::on_reshare_trigger` and `rebootstrap` both return early on `authority: None`), which is
    /// safe — it fails closed — and leaves the cell with **no way out of a beacon freeze**. Lose `n − t + 1`
    /// anchors and the epoch clock stops forever, which is the R-C1 cliff the resharing machinery was built to
    /// close. That machinery, and the node-side detector that escalates into it, were both finished in July
    /// 2026 with no wire between them: there was no field here, no config key, and `with_recovery_authority`
    /// had no caller outside the simulator.
    ///
    /// It is deliberately the *verifiers*, never the secrets. A node holds no authority key and cannot
    /// self-issue a trigger; it detects the stall, elects a coordinator and escalates, and a quorum of
    /// operators (or the parent cell) signs. This is the public half every member needs to check those
    /// signatures.
    pub authority: Option<RecoveryAuthoritySet>,
}

impl fmt::Debug for BeaconParams {
    /// Hand-written because [`HybridVerifier`] is not `Debug` — and deriving it on the key would be the wrong
    /// fix, since the *share* below is a secret and a derived `Debug` on this struct is exactly how one leaks
    /// into a log line. Only presence is reported, never material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BeaconParams")
            .field("threshold", &self.threshold)
            .field("anchor", &self.share.is_some())
            .field("authority", &self.authority.is_some())
            // Non-exhaustive on purpose, and the lint that asks for every field is the reason to say so out loud:
            // `commitment` is bulky group material and `share` is a secret, so this impl reports presence and never
            // content. Listing them to satisfy a lint is how the secret gets into a log line.
            .finish_non_exhaustive()
    }
}

impl BeaconParams {
    /// This network's **genesis seed**, `H("FANOS-v1/genesis-beacon" ‖ network_id)`.
    ///
    /// It used to hash the *commitment*, on the reasoning that it is the only per-network random value every
    /// participant necessarily holds before it can do anything — which is exactly what epoch 0 needs and had
    /// nothing to supply
    /// (`docs/design-genesis.md` §4). One derivation, in [`crate::node::genesis_seed`]; this is the
    /// ergonomic way to reach it from provisioning.
    #[must_use]
    pub fn genesis_seed(&self) -> fanos_primitives::BeaconSeed {
        crate::node::genesis_seed(&self.network_id)
    }

    /// Parse beacon provisioning from a `key = value` file (audit S1-H2), so a node can be handed its DKG
    /// output and run the **live epoch clock** (§7.6) — turning on E4 forward secrecy and E5 rotation — instead
    /// of pinning at genesis. Keys:
    /// - `network_id = <32 bytes of hex>` — this **network's public name**, the value epoch 0's coordinates
    ///   are drawn against. Required, and deliberately not derivable from anything else in this file: see
    ///   [`NetworkId`](crate::NetworkId). Two deployments that share it share every genesis coordinate, so it
    ///   is minted once per network and copied verbatim to every member;
    /// - `threshold = <t>` — the DVRF reconstruction threshold;
    /// - `commitment = <hex>` — the group's public [`VssCommitment`] (network-wide genesis material);
    /// - `share = <hex>` — THIS node's anchor [`VssShare`]; omit for a pure consumer (verifies + adopts only);
    /// - `authority = <hex>[,<hex>…]` — the recovery authority committee's [`HybridVerifier`]s, in the order
    ///   the founding ceremony fixed (a signature names its member by index into that order). Omit and the
    ///   cell can never reshape its beacon, so a freeze is permanent (see [`BeaconParams::authority`]). The
    ///   quorum is not written here: it is a strict majority of however many are listed, derived rather than
    ///   configured, so a file cannot quietly lower it.
    ///
    /// The share is this node's secret — protect the file. The commitment/threshold are public and identical
    /// network-wide. Generate a set with `fanos beacon-deal` (or an external DKG).
    pub fn from_config_str(text: &str) -> Result<Self, NodeError> {
        let mut threshold: Option<usize> = None;
        let mut commitment: Option<VssCommitment> = None;
        let mut share: Option<VssShare> = None;
        let mut authority: Option<RecoveryAuthoritySet> = None;
        let mut network_id: Option<crate::NetworkId> = None;
        for (n, raw) in text.lines().enumerate() {
            let l = raw.split('#').next().unwrap_or("").trim();
            if l.is_empty() {
                continue;
            }
            let (key, value) = l.split_once('=').ok_or_else(|| {
                NodeError::Config(format!("beacon config line {}: expected `key = value`", n + 1))
            })?;
            let value = value.trim();
            match key.trim() {
                "threshold" => {
                    threshold = Some(value.parse().map_err(|_| {
                        NodeError::Config(format!("bad beacon threshold '{value}'"))
                    })?);
                }
                "network_id" => {
                    let bytes: [u8; 32] = hex_decode(value)?.try_into().map_err(|_| {
                        NodeError::Config("bad network_id (expected 32 bytes of hex)".to_owned())
                    })?;
                    network_id = Some(crate::NetworkId::new(bytes));
                }
                "commitment" => {
                    commitment = Some(VssCommitment::from_bytes(&hex_decode(value)?).ok_or_else(|| {
                        NodeError::Config("bad beacon commitment (not a valid VssCommitment)".to_owned())
                    })?);
                }
                "share" => {
                    share = Some(VssShare::from_bytes(&hex_decode(value)?).ok_or_else(|| {
                        NodeError::Config("bad beacon share (not a valid VssShare)".to_owned())
                    })?);
                }
                "authority" => {
                    let members = value
                        .split(',')
                        .map(str::trim)
                        .filter(|m| !m.is_empty())
                        .map(|m| {
                            HybridVerifier::decode(&hex_decode(m)?).ok_or_else(|| {
                                NodeError::Config("bad beacon authority (not a valid HybridVerifier)".to_owned())
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    // An empty list is a provisioning mistake, not "no authority": writing `authority =` and
                    // silently getting a cell that can never recover is exactly the class of quiet no-op the
                    // provisioning ratchet exists for. Omit the key to mean none.
                    authority = Some(RecoveryAuthoritySet::new(members).ok_or_else(|| {
                        NodeError::Config(
                            "beacon authority is empty — omit the key entirely to disable recovery".to_owned(),
                        )
                    })?);
                }
                other => return Err(NodeError::Config(format!("unknown beacon config key '{other}'"))),
            }
        }
        Ok(Self {
            // Required, with no fallback to the commitment. Defaulting would keep the coupling #98 removes
            // for exactly the configurations that forgot the field — and a network whose name is a function
            // of its beacon can never retire that beacon without re-seating every node.
            network_id: network_id
                .ok_or_else(|| NodeError::Config("beacon config missing `network_id`".to_owned()))?,
            commitment: commitment
                .ok_or_else(|| NodeError::Config("beacon config missing `commitment`".to_owned()))?,
            threshold: threshold
                .ok_or_else(|| NodeError::Config("beacon config missing `threshold`".to_owned()))?,
            share,
            authority,
        })
    }

    /// Serialize to the `key = value` provisioning-file format ([`from_config_str`](Self::from_config_str) is
    /// the inverse). A file carrying `share` holds this node's secret — protect it; the commitment/threshold
    /// are public. A dealer writes one anchor file per share plus one share-less consumer file.
    #[must_use]
    pub fn to_config_string(&self) -> String {
        use core::fmt::Write as _;
        let mut s = String::new();
        // First, because it is the network's name: an operator diffing two provisioning files to answer
        // "are these the same network?" reads it before anything else.
        let _ = writeln!(s, "network_id = {}", hex_encode(self.network_id.as_bytes()));
        let _ = writeln!(s, "threshold = {}", self.threshold);
        let _ = writeln!(s, "commitment = {}", hex_encode(&self.commitment.to_bytes()));
        if let Some(share) = &self.share {
            let _ = writeln!(s, "share = {}", hex_encode(&share.to_bytes()));
        }
        if let Some(authority) = &self.authority {
            let members: Vec<String> =
                authority.members().iter().map(|vk| hex_encode(&vk.encode())).collect();
            let _ = writeln!(s, "authority = {}", members.join(","));
        }
        s
    }
}

/// The threshold-hosting parameters a node needs to serve a CALYPSO service line (spec §12.3, #99). With
/// `service = Some(..)` **and** the `service` role, the node composes a [`ServiceNode`](crate::ServiceNode):
/// it holds one member key of the service line, joins the line's threshold gather on each intro, and
/// surfaces the recovered request — no single host reads an intro alone.
///
/// The member key is carried as a **seed**, not the secret itself: a member's hybrid KEM secret is
/// deliberately non-serializable (it must not be spilled un-zeroized to a `Vec`; audit #124), so the node
/// regenerates it in memory from this seed via
/// [`HybridKemSecret::generate`](fanos_pqcrypto::HybridKemSecret::generate) — deterministically, so the
/// member's published public key stays stable across restarts (unlike a relay's forward-secure onion key,
/// which is fresh per run). Provisioned out-of-band, exactly like the beacon share: the operator generates
/// each member's seed, collects the derived publics into the published `ServiceLine`, and hands each
/// member its own seed. Set programmatically, not from the config file.
#[derive(Clone)]
pub struct ServiceParams {
    /// The seed this node regenerates its service-line member KEM keypair from. Secret material.
    pub seed: [u8; 32],
    /// The service line's member coordinates, in the client's seal order.
    pub line: Vec<Triple>,
    /// The reconstruction threshold `t` — how many members must cooperate to serve an intro.
    pub threshold: usize,
}

// The seed regenerates the member secret, so it is itself key material — redacted from `Debug` (which
// `NodeConfig` derives) so a config can be logged without leaking a service's hosting key.
impl fmt::Debug for ServiceParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceParams")
            .field("seed", &"<redacted>")
            .field("line", &self.line)
            .field("threshold", &self.threshold)
            .finish()
    }
}

/// The **POROS ingress** parameters a node needs to run the `ingress` role (`docs/design-anonymity-substrate.md`
/// §6): the community it serves, its own dealt descriptor share, and the dealing's public bindings.
///
/// Provisioned out-of-band by a **ceremony**, exactly like the beacon share and the service line: an operator
/// runs `fanos ingress-deal` once over the community's entry peers, which threshold-shards the descriptor across
/// the line and emits one file per member plus the public binding every member and every combiner is configured
/// with. The share is secret; the binding is not.
///
/// **The binding is not optional and is not separable from the share.** A POROS line reconstructs a *plaintext*,
/// so unlike every other threshold secret in the platform it has no AEAD tag to fail on a wrong reconstruction —
/// and Lagrange is linear, so one member could otherwise choose the entry peers the whole community bootstraps
/// from ([`fanos_node::DescriptorBinding`](crate::DescriptorBinding)). The two travel together for that reason.
#[derive(Clone)]
pub struct IngressParams {
    /// The community secret whose ingress line this node sits on — the enumeration-resistance input of the §6
    /// derivation. Secret material.
    pub community: Vec<u8>,
    /// This node's dealt descriptor share.
    pub share: Share,
    /// The dealing's public bindings (the descriptor commitment + the per-share commitments).
    pub binding: DescriptorBinding,
    /// The ingress line's member coordinates, in the order the shares were dealt (position = share index).
    pub line: Vec<Triple>,
    /// The reconstruction threshold `t` — how many members must cooperate to serve a bucket of entry peers.
    pub threshold: usize,
    /// The admission proof-of-work difficulty this line demands of a requester (the rate-limiter half of the
    /// Sybil gate; the cap half is the coherence layer's admitted set).
    pub difficulty: u32,
    /// The seed this node regenerates its hybrid-KEM keypair from, so it can OPEN sealed reshare sub-shares
    /// when the ingress line rotates. Secret material; the matching public is published in the line's roster.
    pub kem_seed: [u8; 32],
}

impl IngressParams {
    /// Render as the `key = value` provisioning file `fanos ingress-deal` writes and `fanos node` reads.
    ///
    /// Everything but `community`, `share` and `kem_seed` is public; those three are why the file is secret.
    /// The binding travels **in the same file as the share** on purpose: they are only correct as a pair (a
    /// share with no binding is a descriptor anyone on the line can rewrite), and a format that let an
    /// operator copy one without the other would be an invitation to do exactly that.
    #[must_use]
    pub fn to_config_string(&self) -> String {
        use core::fmt::Write as _;
        let mut s = String::new();
        let _ = writeln!(s, "threshold = {}", self.threshold);
        let _ = writeln!(s, "difficulty = {}", self.difficulty);
        let _ = writeln!(s, "community = {}", hex_encode(&self.community));
        let _ = writeln!(s, "share = {}{}", hex_encode(&[self.share.x()]), hex_encode(self.share.y()));
        let _ = writeln!(s, "binding = {}", hex_encode(&self.binding.to_bytes()));
        let _ = writeln!(s, "kem_seed = {}", hex_encode(&self.kem_seed));
        for coord in &self.line {
            let _ = writeln!(s, "member = {}:{}:{}", coord[0], coord[1], coord[2]);
        }
        s
    }

    /// Parse the file [`to_config_string`](Self::to_config_string) writes.
    ///
    /// # Errors
    /// [`NodeError::Config`] on a malformed line, a bad hex field, or a missing required key.
    pub fn from_config_str(text: &str) -> Result<Self, NodeError> {
        let mut threshold: Option<usize> = None;
        let mut difficulty: Option<u32> = None;
        let mut community: Option<Vec<u8>> = None;
        let mut share: Option<Share> = None;
        let mut binding: Option<DescriptorBinding> = None;
        let mut kem_seed: Option<[u8; 32]> = None;
        let mut line: Vec<Triple> = Vec::new();
        for (n, raw) in text.lines().enumerate() {
            let l = raw.split('#').next().unwrap_or("").trim();
            if l.is_empty() {
                continue;
            }
            let (key, value) = l.split_once('=').ok_or_else(|| {
                NodeError::Config(format!("ingress config line {}: expected `key = value`", n + 1))
            })?;
            let value = value.trim();
            match key.trim() {
                "threshold" => {
                    threshold = Some(value.parse().map_err(|_| {
                        NodeError::Config(format!("bad ingress threshold '{value}'"))
                    })?);
                }
                "difficulty" => {
                    difficulty = Some(value.parse().map_err(|_| {
                        NodeError::Config(format!("bad ingress difficulty '{value}'"))
                    })?);
                }
                "community" => community = Some(hex_decode(value)?),
                "share" => {
                    let bytes = hex_decode(value)?;
                    let (&x, y) = bytes.split_first().ok_or_else(|| {
                        NodeError::Config("bad ingress share (empty)".to_owned())
                    })?;
                    share = Some(Share::new(x, y.to_vec()));
                }
                "binding" => {
                    binding = Some(DescriptorBinding::from_bytes(&hex_decode(value)?).ok_or_else(|| {
                        NodeError::Config("bad ingress binding (not a valid DescriptorBinding)".to_owned())
                    })?);
                }
                "kem_seed" => {
                    kem_seed = Some(hex_decode(value)?.try_into().map_err(|_| {
                        NodeError::Config("bad ingress kem_seed (want 32 bytes)".to_owned())
                    })?);
                }
                "member" => line.push(parse_coord(value)?),
                other => return Err(NodeError::Config(format!("unknown ingress config key '{other}'"))),
            }
        }
        Ok(Self {
            community: community
                .ok_or_else(|| NodeError::Config("ingress config missing `community`".to_owned()))?,
            share: share.ok_or_else(|| NodeError::Config("ingress config missing `share`".to_owned()))?,
            binding: binding
                .ok_or_else(|| NodeError::Config("ingress config missing `binding`".to_owned()))?,
            line,
            threshold: threshold
                .ok_or_else(|| NodeError::Config("ingress config missing `threshold`".to_owned()))?,
            difficulty: difficulty
                .ok_or_else(|| NodeError::Config("ingress config missing `difficulty`".to_owned()))?,
            kem_seed: kem_seed
                .ok_or_else(|| NodeError::Config("ingress config missing `kem_seed`".to_owned()))?,
        })
    }
}

// `community`, `share` and `kem_seed` are all key material, and `NodeConfig` derives `Debug` — so a config can
// be logged without leaking a community's ingress hosting secrets.
impl fmt::Debug for IngressParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IngressParams")
            .field("community", &"<redacted>")
            .field("share", &"<redacted>")
            .field("binding", &self.binding)
            .field("line", &self.line)
            .field("threshold", &self.threshold)
            .field("difficulty", &self.difficulty)
            .field("kem_seed", &"<redacted>")
            .finish()
    }
}

/// The clearnet-exit parameters a node needs to run the `exit` role (roadmap §3): the DIAULOS service
/// identity clients dial the exit at, plus the [`ExitPolicy`](crate::ExitPolicy) bounding what it relays
/// to. Like a service member's key ([`ServiceParams`]) the identity is carried as a **seed** — the exit
/// regenerates its `StaticKeypair` in memory from it, deterministically, so its published public stays
/// stable across restarts (clients dial a fixed identity). `allowed_ports` empty means any port — an open
/// relay, which the operator opts into explicitly rather than by default.
#[derive(Clone)]
pub struct ExitParams {
    /// The seed the exit regenerates its DIAULOS service `StaticKeypair` from. Secret material.
    pub seed: [u8; 32],
    /// The destination ports this exit will relay to; empty = any port.
    pub allowed_ports: Vec<u16>,
}

// The seed regenerates the exit's service key, so it is redacted from `Debug` (which `NodeConfig` derives).
impl fmt::Debug for ExitParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExitParams")
            .field("seed", &"<redacted>")
            .field("allowed_ports", &self.allowed_ports)
            .finish()
    }
}

impl ExitParams {
    /// Parse exit parameters from a `key = value` text file: `seed` (64 hex chars, the service-key seed)
    /// and `ports` (comma-separated destination ports; omitted or empty = any port).
    ///
    /// # Errors
    /// [`NodeError::Config`] on a malformed line, an unknown key, or a bad value.
    pub fn from_config_str(text: &str) -> Result<Self, NodeError> {
        let mut seed: Option<[u8; 32]> = None;
        let mut allowed_ports: Vec<u16> = Vec::new();
        for (n, raw) in text.lines().enumerate() {
            let l = raw.split('#').next().unwrap_or("").trim();
            if l.is_empty() {
                continue;
            }
            let (key, value) = l.split_once('=').ok_or_else(|| {
                NodeError::Config(format!("exit config line {}: expected `key = value`", n + 1))
            })?;
            match key.trim() {
                "seed" => seed = Some(parse_seed_hex(value.trim())?),
                "ports" => {
                    for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                        allowed_ports.push(part.parse().map_err(|_| {
                            NodeError::Config(format!("bad exit port '{part}'"))
                        })?);
                    }
                }
                other => {
                    return Err(NodeError::Config(format!("unknown exit config key '{other}'")));
                }
            }
        }
        let seed = seed.ok_or_else(|| NodeError::Config("exit config missing `seed`".to_owned()))?;
        Ok(Self {
            seed,
            allowed_ports,
        })
    }
}

impl ServiceParams {
    /// Parse service parameters from a `key = value` text file — the out-of-band provisioning a service
    /// operator hands each line member. Recognised keys: `seed` (64 hex chars: the 32-byte member-key
    /// seed), `line` (comma-separated `x:y:z` member coordinates, in the client's seal order), and
    /// `threshold` (the reconstruction `t`). All three are required; an unrecognised key is an error.
    ///
    /// # Errors
    /// [`NodeError::Config`] on a malformed line, an unknown key, a bad value, or a missing key.
    pub fn from_config_str(text: &str) -> Result<Self, NodeError> {
        let mut seed: Option<[u8; 32]> = None;
        let mut line: Vec<Triple> = Vec::new();
        let mut threshold: Option<usize> = None;
        for (n, raw) in text.lines().enumerate() {
            let l = raw.split('#').next().unwrap_or("").trim();
            if l.is_empty() {
                continue;
            }
            let (key, value) = l.split_once('=').ok_or_else(|| {
                NodeError::Config(format!("service config line {}: expected `key = value`", n + 1))
            })?;
            match key.trim() {
                "seed" => seed = Some(parse_seed_hex(value.trim())?),
                "line" => {
                    for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                        line.push(parse_coord(part)?);
                    }
                }
                "threshold" => {
                    threshold = Some(value.trim().parse().map_err(|_| {
                        NodeError::Config(format!("bad service threshold '{}'", value.trim()))
                    })?);
                }
                other => {
                    return Err(NodeError::Config(format!(
                        "unknown service config key '{other}'"
                    )));
                }
            }
        }
        let seed = seed.ok_or_else(|| NodeError::Config("service config missing `seed`".to_owned()))?;
        let threshold =
            threshold.ok_or_else(|| NodeError::Config("service config missing `threshold`".to_owned()))?;
        if line.is_empty() {
            return Err(NodeError::Config(
                "service config `line` must list at least one member coordinate".to_owned(),
            ));
        }
        Ok(Self {
            seed,
            line,
            threshold,
        })
    }
}

/// Parse a `x:y:z` projective coordinate into a [`Triple`].
fn parse_coord(s: &str) -> Result<Triple, NodeError> {
    let mut it = s.split(':');
    let mut next = || {
        it.next()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .ok_or_else(|| NodeError::Config(format!("bad coordinate '{s}' (expected x:y:z)")))
    };
    let coord = [next()?, next()?, next()?];
    if it.next().is_some() {
        return Err(NodeError::Config(format!(
            "coordinate '{s}' must be exactly x:y:z"
        )));
    }
    Ok(coord)
}

/// Decode exactly 64 hex characters into a 32-byte seed.
/// Hex-encode bytes (lower-case) — the inverse of `hex_decode`, for writing beacon provisioning files.
/// Lowercase hex. Public so the CLI's beacon dealer can write the recovery-authority seed in the same
/// encoding the provisioning files use — one format for everything an operator handles by hand.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0xF), 16).unwrap_or('0'));
    }
    s
}

/// Decode an even-length hex string to bytes — for the variable-length crypto objects (`VssCommitment`,
/// `VssShare`) a beacon provisioning file carries (audit S1-H2).
pub fn hex_decode(s: &str) -> Result<Vec<u8>, NodeError> {
    let nibble = |c: u8| -> Result<u8, NodeError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(NodeError::Config("hex string contains a non-hex character".to_owned())),
        }
    };
    let (pairs, rem) = s.as_bytes().as_chunks::<2>();
    if !rem.is_empty() {
        return Err(NodeError::Config("hex string has an odd length".to_owned()));
    }
    pairs
        .iter()
        .map(|&[hi, lo]| Ok((nibble(hi)? << 4) | nibble(lo)?))
        .collect()
}

/// A whole-second duration from a config value, rejecting zero — a period of zero is never what an operator
/// meant, and taken literally it is a busy loop.
fn parse_duration_secs(value: &str, key: &str) -> Result<Duration, NodeError> {
    let n: u64 = value.parse().map_err(|_| NodeError::Config(format!("bad {key} '{value}' (expected seconds)")))?;
    if n == 0 {
        return Err(NodeError::Config(format!("{key} must be greater than zero")));
    }
    Ok(Duration::from_secs(n))
}

/// A millisecond duration from a config value. Zero **is** meaningful here (no mixing delay, no cover traffic),
/// so it is accepted — the operator is turning the mechanism off, which is a legitimate choice with a cost.
fn parse_duration_millis(value: &str, key: &str) -> Result<Duration, NodeError> {
    let n: u64 = value
        .parse()
        .map_err(|_| NodeError::Config(format!("bad {key} '{value}' (expected milliseconds)")))?;
    Ok(Duration::from_millis(n))
}

fn parse_seed_hex(s: &str) -> Result<[u8; 32], NodeError> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return Err(NodeError::Config(format!(
            "service seed must be 64 hex characters (got {})",
            bytes.len()
        )));
    }
    let nibble = |c: u8| -> Result<u8, NodeError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(NodeError::Config(
                "service seed contains a non-hex character".to_owned(),
            )),
        }
    };
    let mut seed = [0u8; 32];
    // 64 even bytes → exactly 32 two-byte chunks, zipped 1:1 with the 32 seed slots. The slice pattern
    // binds each pair without indexing; the `_` arm is unreachable given the length check.
    for (slot, pair) in seed.iter_mut().zip(bytes.chunks(2)) {
        match pair {
            [hi, lo] => *slot = (nibble(*hi)? << 4) | nibble(*lo)?,
            _ => return Err(NodeError::Config("service seed has an odd length".to_owned())),
        }
    }
    Ok(seed)
}

/// A bootstrap peer: a known overlay coordinate bound to a network address. The overlay routes on
/// coordinates; a fresh node seeds its address book with these so it can dial into the network
/// (`docs/design.md` §9 — derivation/seed, not a central directory).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Peer {
    /// The peer's overlay coordinate.
    pub coord: Triple,
    /// The peer's network address.
    pub addr: SocketAddr,
}

/// Seed a transport address book from a provisioned peer list, refusing a list that names one coordinate twice.
///
/// A duplicate coordinate is not a routing question, it is a **file** question: two entries for one seat mean the
/// operator wrote two addresses for one node, and an address book holds one. The write cannot report it — both
/// entries are unranked, an unranked incumbent yields to anyone (`Directory::supersedes`), so the later line wins
/// and the earlier peer is simply absent from the bootstrap set. The number of peers the operator listed and the
/// number the node can dial then differ, with nothing in between that says why (#241).
///
/// Fatal rather than a warning, and for `fanos keygen` the reason is sharper: the ceremony derives the network's
/// **name** from the roster it was handed, so a founder whose file repeats a coordinate computes the same name as
/// everyone else while holding one fewer reachable seat — the ceremony then stalls, and the only visible symptom
/// blames the network.
///
/// # Errors
/// [`NodeError::Config`] naming the repeated coordinate and both addresses claiming it.
pub fn seed_directory(peers: &[Peer], directory: &fanos_quic::Directory) -> Result<(), NodeError> {
    for peer in peers {
        // `resolve` rather than the write's outcome, because the outcome cannot carry this: the second unranked
        // write is `Bound`, which is the arbitration rule behaving exactly as designed. Only the *input* is wrong.
        if let Some(held) = directory.resolve(peer.coord)
            && held != peer.addr
        {
            return Err(NodeError::Config(format!(
                "coordinate {}:{}:{} is listed twice, at {held} and at {} — one seat cannot hold two addresses",
                peer.coord[0], peer.coord[1], peer.coord[2], peer.addr
            )));
        }
        // Discarded deliberately: into a directory this function is seeding, an unranked write over an unranked
        // incumbent always lands, and the one input that could make it not land is refused above.
        let _ = directory.insert(peer.coord, peer.addr);
        // **And the address again, without the coordinate** (#263). The binding above is perishable by
        // design: `coord` is where that peer sat when this file was written, §L3 redraws it every epoch, and
        // as an *unranked* entry it loses to every ranked write — including this node's own reseat onto the
        // same point, which then deletes the only address it was given. Measured: the arrival ends with
        // `known_peers = 1` in 2 runs of 5. The address alone is what does not perish, so it is kept where
        // no arbitration can reach it and the send ladder can fall back to it.
        directory.note_entry(peer.addr);
    }
    Ok(())
}

/// The inverse of [`Peer::parse`] — the `x:y:z@host:port` seed form.
impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}@{}", self.coord[0], self.coord[1], self.coord[2], self.addr)
    }
}

impl Peer {
    /// Parse a `x:y:z@host:port` seed string.
    ///
    /// # Errors
    /// [`NodeError::Config`] if the coordinate or address is malformed.
    pub fn parse(s: &str) -> Result<Self, NodeError> {
        let (coord_str, addr_str) = s
            .split_once('@')
            .ok_or_else(|| NodeError::Config(format!("peer '{s}' must be 'x:y:z@host:port'")))?;
        let mut it = coord_str.split(':');
        let mut next = || {
            it.next()
                .and_then(|v| v.parse::<u32>().ok())
                .ok_or_else(|| NodeError::Config(format!("bad coordinate in peer '{s}'")))
        };
        let coord = [next()?, next()?, next()?];
        if it.next().is_some() {
            return Err(NodeError::Config(format!(
                "coordinate in peer '{s}' must be x:y:z"
            )));
        }
        let addr = addr_str
            .parse::<SocketAddr>()
            .map_err(|_| NodeError::Config(format!("bad address in peer '{s}'")))?;
        Ok(Self { coord, addr })
    }
}

/// The roles a node **offers** (a capability set; spec §7.4 / `docs/design.md` §12), advertised via JOIN so the cell
/// learns it.
///
/// This is the *operator's declaration* — what the node is willing to do. It is deliberately distinct from
/// [`fanos_core::roles::RoleSet`], which is what the cell's self-organizing controller **assigns** from that offer
/// each epoch; config names roles in text, the controller reasons over a bitset. [`RoleSet::offered`] is the single
/// canonical bridge between them, and the two encodings are proven identical by a const assertion beside it, so the
/// duplication cannot drift into disagreement about what a bit means.
// Independent role flags are the natural shape of a declaration (they map 1:1 to the JOIN bitfield); a struct here
// reads better than an opaque bitmask at the call sites.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct RoleSet {
    /// Relays application traffic for others.
    pub relay: bool,
    /// Stores DHT (L4) shards for the cell.
    pub storage: bool,
    /// Hosts hidden services (CALYPSO).
    pub service: bool,
    /// Bridges to the clear net (an exit).
    pub exit: bool,
    /// Serves as a member of an anonymous **rendezvous line** — NOSTOS receiver anonymity and hidden-service
    /// hosting (`docs/design-anonymity-substrate.md` §3/§3b). Offering it lets the cell assign the node a point on
    /// a line; the service's anonymity set is that line's membership, so coverage is provisioned cell-wide rather
    /// than configured per host.
    pub rendezvous: bool,
    /// Serves as a member of a community's **POROS ingress line** — the censorship-resistant bootstrap entry
    /// (`docs/design-anonymity-substrate.md` §6). Offering it lets the cell seat this node on an ingress line;
    /// the seize-`< t`-reveals-nothing guarantee is a property of how much of that line is occupied, so
    /// coverage is provisioned cell-wide rather than configured per host.
    pub ingress: bool,
}

/// The inverse of [`RoleSet::parse`] — the comma list a config file carries.
///
/// Written as a `Display` rather than an `encode`-style method because the round trip is the point: a generated
/// config is read back by the daemon that wrote it, and a printer that disagrees with the parser produces a node
/// whose advertised roles quietly change at the next restart. Asserted both ways in `setup`'s tests.
impl fmt::Display for RoleSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = [
            ("relay", self.relay),
            ("storage", self.storage),
            ("service", self.service),
            ("exit", self.exit),
            ("rendezvous", self.rendezvous),
            ("ingress", self.ingress),
        ];
        let mut first = true;
        for (name, on) in names {
            if on {
                if !first {
                    f.write_str(",")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        // An empty set has no name in the grammar, and `role = ` would fail to parse. `none` is the honest token
        // for "advertises nothing", and it round-trips.
        if first { f.write_str("none") } else { Ok(()) }
    }
}

impl RoleSet {
    /// Whether any role is advertised.
    #[must_use]
    pub fn any(self) -> bool {
        self.relay || self.storage || self.service || self.exit || self.rendezvous || self.ingress
    }

    /// The offered set as the **core** [`fanos_core::roles::RoleSet`] the self-organizing controller assigns from —
    /// the one canonical bridge between the operator's declaration and the cell's assignment machinery.
    #[must_use]
    pub fn offered(self) -> CoreRoleSet {
        let mut set = CoreRoleSet::default();
        for (offered, role) in [
            (self.relay, Role::Relay),
            (self.storage, Role::Storage),
            (self.service, Role::Service),
            (self.exit, Role::Exit),
            (self.rendezvous, Role::Rendezvous),
            (self.ingress, Role::Ingress),
        ] {
            if offered {
                set.insert(role);
            }
        }
        set
    }

    /// A compact one-byte encoding for the JOIN announcement.
    #[must_use]
    pub fn encode(self) -> u8 {
        self.offered().bits()
    }

    /// Parse a comma-separated role list (`relay,storage,service,exit,rendezvous,ingress`).
    ///
    /// # Errors
    /// [`NodeError::Config`] on an unknown role name.
    pub fn parse(s: &str) -> Result<Self, NodeError> {
        let mut roles = Self::default();
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match part {
                // The token the printer emits for an empty set; without it a rendered `role = none` would fail to
                // parse and the round trip would break exactly where it is least visible.
                "none" => {}
                "relay" => roles.relay = true,
                "storage" => roles.storage = true,
                "service" => roles.service = true,
                "exit" => roles.exit = true,
                "rendezvous" => roles.rendezvous = true,
                "ingress" => roles.ingress = true,
                other => return Err(NodeError::Config(format!("unknown role '{other}'"))),
            }
        }
        Ok(roles)
    }
}

// The JOIN bitfield and the core bitset must mean the same thing bit for bit, or a peer's advertisement would be
// read as a different role set than the cell assigns from. `encode` is now defined *through* `offered`, so they
// cannot diverge by construction; this pins the bit positions themselves so the wire format is stable too.
const _: () = {
    assert!(CoreRoleSet::BIT_RELAY == 1 << 0, "JOIN bit 0 is relay");
    assert!(CoreRoleSet::BIT_STORAGE == 1 << 1, "JOIN bit 1 is storage");
    assert!(CoreRoleSet::BIT_SERVICE == 1 << 2, "JOIN bit 2 is service");
    assert!(CoreRoleSet::BIT_EXIT == 1 << 3, "JOIN bit 3 is exit");
    assert!(CoreRoleSet::BIT_RENDEZVOUS == 1 << 4, "JOIN bit 4 is rendezvous");
    assert!(CoreRoleSet::BIT_INGRESS == 1 << 5, "JOIN bit 5 is ingress");
};

/// A node's runtime configuration.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// The address to bind the QUIC endpoint to (e.g. `0.0.0.0:9000`).
    pub listen: SocketAddr,
    /// The projective plane order `q` this node's cell runs on — `PG(2, q)` has `q² + q + 1` points, one per node.
    ///
    /// **This exists because the binary was pinned to `q = 2`.** `Node::start` has always been generic over the plane, but
    /// `fanos.rs` instantiated `F2` at every call site, so every deployment ran the **smallest possible cell: 7 points,
    /// 3-point lines, threshold 2**. For anonymity that is the binding constraint — a mixnet's protection is bounded by the
    /// size of the set a flow hides in, and no schedule tuning reaches past 7 relays. The library being general while the
    /// binary pinned the minimum is the "libraries ahead, wiring behind" pattern this project's audits keep finding, and
    /// here it capped a headline property rather than an internal one.
    ///
    /// Supported orders are prime powers (`PG(2,q)` exists only then): 2, 4, 7, 31.
    ///
    /// ## Why `q = 2` cannot provide anonymity, with the number
    ///
    /// The adversary's floor in a linkability measurement is `1/K` for `K` concurrent circuits, and `K` is a property of
    /// the **plane**, not of the schedule. Measured
    /// (`fanos-sim/tests/threshold_routing.rs::measure_what_the_default_plane_actually_delivers`):
    ///
    /// | plane | points | lines with *distinct* combiners | concurrent circuits | adversary's floor |
    /// |---|---|---|---|---|
    /// | **`PG(2,2)` (this default)** | 7 | **4** | **2** | **0.50 — a coin flip** |
    /// | `PG(2,7)` | 57 | 10+ | 5 | 0.20 |
    ///
    /// Only 4 of `PG(2,2)`'s 7 lines have distinct combiners, because line-derived combiners collide — so a default
    /// deployment supports **two** circuits and the best any schedule can achieve is a **coin flip**. The mixnet defaults
    /// tuned on measurement reach 0.000 on `PG(2,7)`; on `PG(2,2)` they cannot go below 0.50, because there is nothing to
    /// hide among.
    ///
    /// So `q = 2` is a **test fixture**, and this is the quantitative form of that: the plane order dominates the schedule
    /// entirely. It remains the default only so no existing deployment changes behaviour silently, and a deployment that
    /// wants the anonymity the spec claims must raise it.
    pub plane_order: u32,
    /// The **ε** for differentially-private telemetry export, or `None` to publish nothing (audit C7).
    ///
    /// Opt-in on purpose, and the default is silence. A node's coherence readings — its Φ, purity, the healing sequence —
    /// describe the cell it sits in, so publishing them is a decision an operator makes rather than a behaviour an upgrade
    /// introduces. `Some(ε)` starts the publisher in `telemetry_dir`, which routes every frame through
    /// `CoherenceFrame::export` (privatize, then encode) at that budget.
    ///
    /// Smaller ε is more private and noisier; the mechanism's own docs carry the calibration. There is deliberately no
    /// default value here — picking one would be choosing a privacy/utility trade-off on the operator's behalf, and the
    /// honest options are "off" or "a number you chose".
    pub telemetry_epsilon: Option<f64>,
    /// Where to persist the self-certifying identity; `None` = ephemeral (new identity each run).
    pub identity_path: Option<PathBuf>,
    /// Where the `service` role's provisioning file lives, when one was configured (#90).
    ///
    /// The *path*, kept beside the parsed [`service`](Self::service), so the renderer can write the setting
    /// back. Without it the round trip would silently drop a configured role — the class the round-trip test
    /// exists to catch, and which these three were exempt from by not being expressible at all.
    pub service_path: Option<PathBuf>,
    /// Where the `exit` role's provisioning file lives — see [`service_path`](Self::service_path).
    pub exit_path: Option<PathBuf>,
    /// Where the `ingress` role's provisioning file lives — see [`service_path`](Self::service_path).
    pub ingress_path: Option<PathBuf>,
    /// Where to keep this node's **durable store** — the erasure shards it is custodian of, the expiry
    /// schedule, and the loss ledger. `None` = keep nothing, and lose it all on restart.
    ///
    /// **`None` was the only behaviour, and it is what task #77 named.** A node persisted its identity and
    /// nothing else, so a restart returned a member that had forgotten every shard it was holding for the
    /// cell. One node doing that is survivable by construction — the `[7,3,4]` code re-heals from three of
    /// seven homes — but the survival is a repair budget being spent, not a property, and a rolling restart
    /// of a whole cell spends all of it at once.
    ///
    /// Written by `fanos init` to the platform's state directory, so a deployed node has it; `None` stays
    /// the default because an ephemeral node (a test, a proxy-only client) should not litter a disk.
    pub state_path: Option<PathBuf>,
    /// Bootstrap peers seeded into the address book.
    pub bootstrap: Vec<Peer>,
    /// The advertised role set.
    pub roles: RoleSet,
    /// Mean Poisson mixing delay a **relay** holds each forwarded onion for (spec §L5/V7, audit S1-H1). Zero
    /// forwards immediately (no mixing, no T2 defence). Inert on a non-relay. Default [`DEFAULT_MIX_DELAY`].
    pub mix_mean_delay: Duration,
    /// Mean interval a **relay** emits constant-size cover cells at (spec §L5/V8, audit S1-H1/E1). Zero disables
    /// cover. Inert on a non-relay. Default [`DEFAULT_COVER_INTERVAL`].
    pub cover_interval: Duration,
    /// Whether to begin liveness heartbeats on start.
    pub start_heartbeat: bool,
    /// The distributed-beacon parameters. `Some(..)` runs the live epoch clock (§7.6); `None` (the
    /// default) runs a bare overlay pinned at genesis — see [`BeaconParams`].
    pub beacon: Option<BeaconParams>,
    /// How often the node issues the root `AdvanceEpoch` tick that drives the live epoch clock: each
    /// period the beacon advances a round, rotating the VRF coordinate, the PROTEUS wire shape, and the
    /// forward-secure onion keys (the moving-target defence, §L3/§7.6). Only used when `beacon` is
    /// `Some` (a bare overlay has no clock to drive). Network-wide — all nodes should share it so their
    /// epochs stay aligned. Default: [`DEFAULT_EPOCH_PERIOD`].
    pub epoch_period: Duration,
    /// PoW **Sybil-admission** difficulty (spec §L3). `Some(d)` makes the node run proof-of-work admission:
    /// it prices every join at ~`2^d` hashes (re-paid each epoch as the coordinate reshuffles), rejects an
    /// announcing peer with no valid proof (`SYBIL_REJECT`), and attaches its own solved proof — closing the
    /// free-identity gap that self-certifying coordinates alone leave open (`sybil_cost`). `None` (the
    /// default) charges no admission cost, backward-compatible with the pre-admission behaviour. Pick `d`
    /// for the deployment's join-latency vs Sybil-cost trade-off; it must match across the network.
    pub admission_difficulty: Option<u32>,
    /// The threshold-hosting parameters. Required by (and only used with) the `service` role: `Some(..)`
    /// composes a [`ServiceNode`](crate::ServiceNode) hosting one member of a service line — see
    /// [`ServiceParams`]. `None` (the default) hosts no service.
    pub service: Option<ServiceParams>,
    /// The clearnet-exit parameters. Required by (and only used with) the `exit` role: `Some(..)` runs a
    /// [`serve_exit`](crate::serve_exit) relay under a stable service identity — see [`ExitParams`]. `None`
    /// (the default) runs no exit.
    pub exit: Option<ExitParams>,
    /// The POROS ingress parameters. Required by (and only used with) the `ingress` role: `Some(..)` composes
    /// an [`IngressNode`](crate::IngressNode) hosting one member of a community's ingress line — see
    /// [`IngressParams`]. `None` (the default) hosts no ingress.
    pub ingress: Option<IngressParams>,
    /// PROTEUS censorship-resistance (§13.4). `Some(secret)` shapes every wire frame with the shared
    /// community secret so the transport carries no static FANOS signature, and the shape **rotates each
    /// epoch** (the moving-target defence); `None` (the default) is plaintext QUIC. All peers that must
    /// interoperate share the same secret — it is a bridge/community password, not a per-node key.
    pub proteus_secret: Option<Vec<u8>>,
    /// The PROTEUS morph selecting the wire codec and traffic-shaping profile (§13.3): the flagship
    /// [`Morph::Polymorph`] ("look like nothing", the default) or an explicit shaping morph. Only takes
    /// effect when [`proteus_secret`](Self::proteus_secret) is set, and is ignored when
    /// [`proteus_environment`](Self::proteus_environment) enables auto-fallback (which picks the morph).
    pub proteus_morph: Morph,
    /// The PROTEUS environment policy enabling **morph auto-fallback** (§13.7): `Some(env)` rotates through
    /// the environment's morph chain when the current morph starts failing (a connection-failure spike);
    /// `None` (the default) pins the fixed [`proteus_morph`](Self::proteus_morph). Only with a secret set.
    pub proteus_environment: Option<Environment>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], 0)),
            // `q = 2` for continuity — see the field's note on why that is a fixture and not a recommendation.
            plane_order: 2,
            telemetry_epsilon: None, // silence by default: publishing a cell's coherence readings is an operator's decision
            identity_path: None,
            state_path: None,
            service_path: None,
            exit_path: None,
            ingress_path: None,
            bootstrap: Vec::new(),
            roles: RoleSet::default(),
            mix_mean_delay: DEFAULT_MIX_DELAY,
            cover_interval: DEFAULT_COVER_INTERVAL,
            start_heartbeat: true,
            beacon: None,
            epoch_period: DEFAULT_EPOCH_PERIOD,
            admission_difficulty: None,
            service: None,
            exit: None,
            ingress: None,
            proteus_secret: None,
            proteus_morph: Morph::Polymorph,
            proteus_environment: None,
        }
    }
}


/// Apply one of the three **role provisioning** keys — `service`, `exit`, `ingress_params` (#90).
///
/// Paths, never the material, for the same reason `beacon_params` is: each file carries a secret seed or
/// share, and inlining one would put a key into the file an operator copies between hosts.
///
/// Each **implies its role**, exactly as the matching flag does. Handing a node a dealt file *is* the operator
/// asking it to serve that role — there is no other reason to provision one — and a setting whose effect
/// depends on a second setting being remembered is a setting that will be absent in production.
///
/// Without these keys a supervised unit had to carry them on its `ExecStart=` line, so the config was not a
/// complete description of the node; and, worse, they were invisible to the render/parse round-trip assertion
/// that exists to catch exactly that class.
fn role_key(config: &mut NodeConfig, key: &str, value: &str) -> Result<(), NodeError> {
    let text = std::fs::read_to_string(value)
        .map_err(|e| NodeError::Config(format!("{key} '{value}': {e}")))?;
    let path = PathBuf::from(value);
    match key {
        "service" => {
            config.service = Some(ServiceParams::from_config_str(&text)?);
            config.service_path = Some(path);
            config.roles.service = true;
        }
        "exit" => {
            config.exit = Some(ExitParams::from_config_str(&text)?);
            config.exit_path = Some(path);
            config.roles.exit = true;
        }
        _ => {
            config.ingress = Some(IngressParams::from_config_str(&text)?);
            config.ingress_path = Some(path);
            config.roles.ingress = true;
        }
    }
    Ok(())
}

impl NodeConfig {
    /// The **genesis seed of the network this configuration describes** — the value every epoch-0 coordinate
    /// on it is drawn against (`docs/design-genesis.md` §4).
    ///
    /// `H("FANOS-v1/genesis-beacon" ‖ commitment)` when a beacon is provisioned, and the bare constant when
    /// none is. Both halves matter. The first is the defence: at genesis there is no reshuffle yet, so on the
    /// base cell placement has no other protection, and a *constant* seed meant one grinding effort bought a
    /// chosen placement on **every FANOS network that would ever exist**. The second is honest about the
    /// deployment that has no beacon at all — it has no epoch clock and no reshuffle either, so it has no
    /// placement defence at any epoch, and pretending otherwise would be worse than the constant.
    ///
    /// Derived from material the operator already holds: the commitment is in every provisioning file because
    /// no node can verify a beacon round without it. No new field, no new ceremony step.
    #[must_use]
    pub fn genesis_seed(&self) -> fanos_primitives::BeaconSeed {
        self.beacon.as_ref().map_or(fanos_primitives::BeaconSeed::GENESIS, BeaconParams::genesis_seed)
    }

    /// A short, comparable name for that network — the first four bytes of its genesis seed, hex.
    ///
    /// Operators need to answer "are we on the same network?" before they can debug anything else, and the
    /// coordinate cannot answer it (two networks seat the same identity at different points, and two
    /// identities on one network seat at different points — neither comparison separates the cases). This
    /// does: same fingerprint, same genesis material.
    #[must_use]
    pub fn network_fingerprint(&self) -> String {
        let seed = self.genesis_seed();
        let b = seed.as_bytes();
        format!("{:02x}{:02x}{:02x}{:02x}", b[0], b[1], b[2], b[3])
    }

    /// Parse a node config from a simple `key = value` text file — one setting per line, `#` starts a
    /// comment — the operator-facing alternative to a long CLI-flag line (§11). Recognised keys:
    /// `listen`, `identity`, `bootstrap` (comma-separated `coord@addr` peers), `role` (comma-separated
    /// roles), `heartbeat` (`true`/`false`). An unrecognised key is an ERROR, not silently ignored — a
    /// typo on a production node must fail loudly rather than leave a setting unexpectedly at its
    /// default. Beacon parameters (the DVRF group commitment) are genesis material provisioned
    /// out-of-band, not from this file, so `beacon` stays `None` here.
    ///
    /// # Errors
    /// [`NodeError::Config`] on a line without `=`, an unrecognised key, or an unparseable value.
    pub fn from_config_str(text: &str) -> Result<Self, NodeError> {
        let mut config = Self::default();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| {
                NodeError::Config(format!("config line {}: expected `key = value`", n + 1))
            })?;
            let (key, value) = (key.trim(), value.trim());
            match key {
                "listen" => {
                    config.listen = value
                        .parse()
                        .map_err(|_| NodeError::Config(format!("bad listen '{value}'")))?;
                }
                "identity" => config.identity_path = Some(PathBuf::from(value)),
                "state" => config.state_path = Some(PathBuf::from(value)),
                "bootstrap" => {
                    for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                        config.bootstrap.push(Peer::parse(part)?);
                    }
                }
                "role" => config.roles = RoleSet::parse(value)?,
                "heartbeat" => {
                    config.start_heartbeat = value.parse().map_err(|_| {
                        NodeError::Config(format!("bad heartbeat '{value}' (expected true/false)"))
                    })?;
                }
                "proteus_secret" => {
                    if value.is_empty() {
                        return Err(NodeError::Config(
                            "proteus_secret must be non-empty (a shared community secret)".to_owned(),
                        ));
                    }
                    config.proteus_secret = Some(value.as_bytes().to_vec());
                }
                "proteus_morph" => {
                    config.proteus_morph = Morph::from_name(value).ok_or_else(|| {
                        NodeError::Config(format!(
                            "unknown proteus_morph '{value}' (expected one of: plain, polymorph, \
                             tls-tunnel, masque-h3, fronted, webrtc, pluggable)"
                        ))
                    })?;
                }
                // Everything below is settable on the command line too, and *had* to be, which was the defect: a
                // daemon started by an init system has no argv an operator later edits. A setting reachable only
                // through a flag is a setting a service unit cannot express, so the file was the narrower surface
                // of the two — exactly backwards for the deployment that matters.
                "plane_order" => {
                    let q: u32 = value
                        .parse()
                        .map_err(|_| NodeError::Config(format!("bad plane_order '{value}'")))?;
                    if !matches!(q, 2 | 4 | 7 | 31) {
                        return Err(NodeError::Config(format!(
                            "plane_order '{q}' is not a supported projective order (expected 2, 4, 7 or 31)"
                        )));
                    }
                    config.plane_order = q;
                }
                // Opt-in by construction: absent means no export, and a node does not begin emitting its coherence
                // readings because it was upgraded. `0` is refused rather than silently meaning "no noise".
                "telemetry_epsilon" => {
                    let eps: f64 = value
                        .parse()
                        .map_err(|_| NodeError::Config(format!("bad telemetry_epsilon '{value}'")))?;
                    if !(eps.is_finite() && eps > 0.0) {
                        return Err(NodeError::Config(format!(
                            "telemetry_epsilon '{value}' must be a finite positive ε (omit the key to publish nothing)"
                        )));
                    }
                    config.telemetry_epsilon = Some(eps);
                }
                "epoch_period" => config.epoch_period = parse_duration_secs(value, "epoch_period")?,
                "mix_mean_delay" => config.mix_mean_delay = parse_duration_millis(value, "mix_mean_delay")?,
                "cover_interval" => config.cover_interval = parse_duration_millis(value, "cover_interval")?,
                "admission_difficulty" => {
                    let bits: u32 = value
                        .parse()
                        .map_err(|_| NodeError::Config(format!("bad admission_difficulty '{value}'")))?;
                    config.admission_difficulty = Some(bits);
                }
                // A **path**, not the material. Beacon provisioning is genesis material with a secret share in it,
                // and inlining it here would put a key into the file an operator copies between hosts. The daemon
                // needs *some* way to be told, though: `--beacon-params` alone means a relay can never run under
                // an init system, because a service unit's argv is not something an operator edits per host.
                "beacon_params" => {
                    let text = std::fs::read_to_string(value).map_err(|e| {
                        NodeError::Config(format!("beacon_params '{value}': {e}"))
                    })?;
                    config.beacon = Some(BeaconParams::from_config_str(&text)?);
                }
                // The three role provisioning files (#90) — see [`role_key`] for why they are paths and
                // why each implies its role.
                "service" | "exit" | "ingress_params" => role_key(&mut config, key, value)?,
                "proteus_environment" => {
                    config.proteus_environment = Some(Environment::from_name(value).ok_or_else(|| {
                        NodeError::Config(format!(
                            "unknown proteus_environment '{value}' (expected one of: open, \
                             dpi-corporate, sni-filter, deep-censorship)"
                        ))
                    })?);
                }
                other => {
                    return Err(NodeError::Config(format!(
                        "config line {}: unknown key '{other}'",
                        n + 1
                    )));
                }
            }
        }
        Ok(config)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    /// The **revision clock** on the two mixnet defaults: it rings when their sweep becomes buildable
    /// again (#187, UHM `316edd9`).
    ///
    /// UHM's rule: *"a constant with no incoming observations is a fixed point of any transmission chain
    /// — it has no revision mechanism, since its only source is itself. Give every blind constant a
    /// revision clock against observations, or the chain will carry it forever."*
    ///
    /// Both defaults came from one `PG(2,7)` knee sweep that stopped building the day after it ran, and
    /// nothing since has been able to feed them an observation. The failure mode this guards is not the
    /// breakage — that is known — it is the **repair going unnoticed**: someone raises the onion budget for
    /// an unrelated reason, the sweep becomes runnable, and two shipped anonymity defaults quietly stay at
    /// numbers nobody can reproduce. That is a conditional obligation with no tripwire, and this is the
    /// tripwire.
    ///
    /// It computes the condition from `depth_for` and `slot_len` rather than restating `37 804`: a guard
    /// that copies the value it guards stops guarding the moment the original moves.
    #[test]
    fn the_mixnet_defaults_revision_clock_has_not_rung() {
        // `PG(2,7)` — the plane the sweep ran on — has 8 points per line.
        const SWEEP_LINE_SIZE: usize = 8;
        let depth = fanos_aphantos::slots::depth_for(SWEEP_LINE_SIZE);

        assert!(
            depth < 2,
            "the knee sweep that set DEFAULT_MIX_DELAY ({DEFAULT_MIX_DELAY:?}) and DEFAULT_COVER_INTERVAL \
             ({DEFAULT_COVER_INTERVAL:?}) needs a \
             2-hop circuit on PG(2,7), and depth_for(8) has risen to {depth} — it BUILDS again. Re-run \
             `cargo test -p fanos-sim --test threshold_routing -- --ignored` and re-derive both defaults \
             from it, then retire this clock. Leaving them is exactly the fossil UHM 316edd9 names: a \
             constant whose only source is itself (#187)",
        );

        // And the clock must be watching the right thing: Fano, the one dispatchable plane that *does*
        // reach depth 2, is not a substitute — its own line is smaller, and #187 records why its floor of
        // 1/2 cannot discriminate a schedule. Asserting both keeps the clock from reading as "no plane
        // works", which would make it ring for the wrong reason.
        assert!(
            fanos_aphantos::slots::depth_for(3) >= 2,
            "Fano must still build a circuit — if it does not, the finding is larger than this clock"
        );
    }

    /// **A provisioning file that names one seat twice is refused, and an idempotent repeat is not.**
    ///
    /// The PROPERTY, and the discriminator is the pair: the guard must reject exactly the input that would silently
    /// shrink the bootstrap set, and accept the one that would not. Without the second half it would pass just as well
    /// if `seed_directory` rejected every list with a repeated coordinate, including the harmless one an operator
    /// writes when the same peer appears in two merged fragments of a config.
    ///
    /// The write itself cannot make this distinction (#241): both entries are unranked, an unranked incumbent yields
    /// to anyone, so BOTH lists produce `Bound` and the second address quietly wins. Only the input is wrong, so only
    /// the input can be checked.
    #[test]
    fn a_seat_listed_twice_at_two_addresses_is_refused_and_a_repeat_of_one_address_is_not() {
        let coord = [1, 2, 3];
        let a: SocketAddr = "10.0.0.1:9000".parse().expect("addr");
        let b: SocketAddr = "10.0.0.2:9000".parse().expect("addr");

        let doubled = [Peer { coord, addr: a }, Peer { coord, addr: b }];
        let err = seed_directory(&doubled, &fanos_quic::Directory::new())
            .expect_err("one seat cannot hold two addresses");
        let text = format!("{err:?}");
        assert!(text.contains("1:2:3"), "the refusal must name the repeated coordinate: {text}");
        assert!(
            text.contains("10.0.0.1:9000") && text.contains("10.0.0.2:9000"),
            "and both addresses claiming it, or the operator cannot find the two lines: {text}"
        );

        // The same coordinate at the SAME address: two config fragments naming one peer. Nothing is lost, so nothing
        // is refused — and the directory holds exactly one binding either way.
        let dir = fanos_quic::Directory::new();
        let repeated = [Peer { coord, addr: a }, Peer { coord, addr: a }];
        seed_directory(&repeated, &dir).expect("an idempotent repeat is not a misconfiguration");
        assert_eq!(dir.resolve(coord), Some(a));
        assert_eq!(dir.len(), 1);
    }

    /// **The censorship horizon is stated in epochs and justified in years — pin the conversion.**
    ///
    /// `CENSORSHIP_HORIZON_EPOCHS` is a *policy* number whose entire warrant is a span of time: "at most one
    /// censored epoch over this long". Its first version read "`2²⁰` epochs is ≈120 years at one epoch per
    /// hour" — computed against a clock this platform does not run. The real default is **ten minutes**, six
    /// times faster, so it bought ≈20 years and the justification was simply wrong.
    ///
    /// Neither crate can see the other's constant (`fanos-rendezvous` must not depend on the node's config),
    /// so the invariant lives here, where both are visible, and fails if either moves. A comment hoping to
    /// stay true is what produced the error; a test cannot hope.
    #[test]
    fn the_censorship_horizon_is_stated_against_the_real_epoch_period() {
        let epochs = fanos_rendezvous::CENSORSHIP_HORIZON_EPOCHS;
        let span = DEFAULT_EPOCH_PERIOD.saturating_mul(u32::try_from(epochs).unwrap_or(u32::MAX));
        let years = span.as_secs_f64() / (365.25 * 24.0 * 3600.0);
        assert!(
            (100.0..500.0).contains(&years),
            "the horizon must be a human lifetime and change, not a decade and not a geological age: \
             {epochs} epochs x {DEFAULT_EPOCH_PERIOD:?} = {years:.0} years"
        );
    }

    use super::*;

    #[test]
    fn parses_a_peer_seed() {
        let p = Peer::parse("1:2:3@127.0.0.1:9000").unwrap();
        assert_eq!(p.coord, [1, 2, 3]);
        assert_eq!(p.addr, "127.0.0.1:9000".parse().unwrap());
    }

    #[test]
    fn beacon_params_round_trip_through_the_provisioning_file() {
        // Audit S1-H2: a node must be provisionable with its DKG output so it runs the live epoch clock. Deal a
        // 4-of-7 sharing, serialize each role's params to the file format, and parse them back byte-identically.
        use fanos_vrf::vss::{DeterministicRng, deal};
        let (shares, commitment) = deal(&[0x7B; 32], 4, 7, &mut DeterministicRng::new(b"cfg-beacon")).unwrap();
        let s2 = shares.get(2).unwrap();

        // An ANCHOR's file carries the threshold, the public commitment, and its own share.
        let anchor =
            BeaconParams { network_id: crate::NetworkId::from_seed(b"test-network"), commitment: commitment.clone(), threshold: 4, share: Some(s2.clone()), authority: None };
        let parsed = BeaconParams::from_config_str(&anchor.to_config_string()).unwrap();
        assert_eq!(parsed.threshold, 4);
        assert_eq!(parsed.commitment.to_bytes(), commitment.to_bytes(), "the group commitment round-trips");
        assert_eq!(parsed.share.unwrap().to_bytes(), s2.to_bytes(), "the anchor's share round-trips");

        // A pure CONSUMER's file omits the share (it verifies + adopts, never contributes).
        let consumer = BeaconParams { network_id: crate::NetworkId::from_seed(b"test-network"), commitment, threshold: 4, share: None, authority: None };
        let parsed = BeaconParams::from_config_str(&consumer.to_config_string()).unwrap();
        assert!(parsed.share.is_none(), "a consumer has no share");

        // Missing required fields, and a bad hex body, are rejected — not silently defaulted.
        assert!(BeaconParams::from_config_str("threshold = 4\n").is_err(), "a missing commitment is rejected");
        assert!(BeaconParams::from_config_str("threshold = 4\ncommitment = zz\n").is_err(), "bad hex is rejected");
    }

    #[test]
    fn the_recovery_authority_survives_the_provisioning_file() {
        // The field that closes the recovery loop, and the one whose absence made a beacon freeze permanent:
        // a beacon with no configured trust root refuses every reshare trigger and every re-genesis. It must
        // therefore reach a node the same way its share does — through the file an operator is handed.
        use fanos_vrf::vss::{DeterministicRng, deal};
        let (_secret, verifier) =
            fanos_pqcrypto::sig::HybridSigSecret::generate(&mut fanos_pqcrypto::rng::SeedRng::from_seed(
                b"fanos-node/config/authority-round-trip",
            ));
        let (_shares, commitment) =
            deal(&[0x2C; 32], 4, 7, &mut DeterministicRng::new(b"cfg-authority")).unwrap();
        let params = BeaconParams {
            network_id: crate::NetworkId::from_seed(b"test-network"),
            commitment: commitment.clone(),
            threshold: 4,
            share: None,
            authority: Some(RecoveryAuthoritySet::new(vec![verifier.clone()]).unwrap()),
        };
        let back = BeaconParams::from_config_str(&params.to_config_string()).expect("round trip");
        // The network's NAME must survive byte-identically, and this is not a formality: it is what epoch 0's
        // coordinates are drawn against, so two members whose files disagree by one byte seat themselves in
        // different coordinate spaces and cannot verify each other at genesis (#98).
        assert_eq!(
            back.network_id.as_bytes(),
            params.network_id.as_bytes(),
            "the network name must come back byte-identical or the cell cannot agree on a single genesis"
        );
        // And a file WITHOUT it is refused rather than defaulted. A fallback to the commitment would keep the
        // very coupling this replaced, for exactly the configurations that forgot the field — the opt-in
        // shape that keeps producing findings. Fail closed: an unnamed network is a provisioning error.
        let full = params.to_config_string();
        let kept: Vec<&str> =
            full.lines().filter(|l| !l.trim_start().starts_with("network_id")).collect();
        let unnamed = kept.join("\n");
        assert!(
            BeaconParams::from_config_str(&unnamed).is_err(),
            "a beacon file with no network_id must be refused, never silently renamed after its commitment"
        );
        let recovered = back.authority.expect("the authority must survive the file");
        assert_eq!(
            recovered.members().first().expect("one member").encode(),
            verifier.encode(),
            "the verifier must come back byte-identical — a different key rejects the operator's own trigger"
        );

        // And a file without one still parses: an operator may deliberately provision a cell that cannot be
        // reshaped, and that must be a choice rather than a parse error.
        let without = BeaconParams::from_config_str(
            &BeaconParams { network_id: crate::NetworkId::from_seed(b"test-network"), commitment: commitment.clone(), threshold: 4, share: None, authority: None }
                .to_config_string(),
        )
        .expect("a file without an authority is still valid");
        assert!(without.authority.is_none());
    }

    #[test]
    fn a_relays_gpa_defence_is_on_by_default() {
        // Audit S1-H1: the shipping node must not run its mixnet with cover traffic and Poisson mixing off
        // (no global-passive-adversary / T2 defence). The defaults enable both — an operator can zero them to
        // trade anonymity for bandwidth/latency, but the safe default is defended.
        let cfg = NodeConfig::default();
        assert!(cfg.mix_mean_delay > Duration::ZERO, "Poisson mixing is on by default");
        assert!(cfg.cover_interval > Duration::ZERO, "cover traffic is on by default");
        assert_eq!(cfg.mix_mean_delay, DEFAULT_MIX_DELAY);
        assert_eq!(cfg.cover_interval, DEFAULT_COVER_INTERVAL);
    }

    #[test]
    fn rejects_malformed_peers() {
        assert!(Peer::parse("1:2:3").is_err()); // no '@addr'
        assert!(Peer::parse("1:2@127.0.0.1:9000").is_err()); // 2-coord
        assert!(Peer::parse("a:b:c@127.0.0.1:9000").is_err()); // non-numeric
        assert!(Peer::parse("1:2:3@not-an-addr").is_err());
    }

    #[test]
    fn parses_and_encodes_roles() {
        let r = RoleSet::parse("relay,exit").unwrap();
        assert!(r.relay && r.exit && !r.storage && !r.service);
        assert_eq!(r.encode(), 0b1001);
        assert!(r.any());
        assert!(RoleSet::parse("bogus").is_err());
        assert!(!RoleSet::default().any());
    }

    #[test]
    fn parses_service_params_from_a_config() {
        let p = ServiceParams::from_config_str(
            "# a 3-of-3 service line\n\
             seed = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
             line = 1:0:0, 0:1:0, 0:0:1\n\
             threshold = 2\n",
        )
        .unwrap();
        assert_eq!(p.seed[0], 0x00);
        assert_eq!(p.seed[1], 0x11);
        assert_eq!(p.seed[31], 0xff);
        assert_eq!(p.line, vec![[1, 0, 0], [0, 1, 0], [0, 0, 1]]);
        assert_eq!(p.threshold, 2);
        // The seed is redacted from Debug (it regenerates the member secret).
        assert!(format!("{p:?}").contains("<redacted>"));
        assert!(!format!("{p:?}").contains("0011"));
    }

    #[test]
    fn parses_exit_params_from_a_config() {
        let p = ExitParams::from_config_str(&format!(
            "# a web-only exit\nseed = {}\nports = 80, 443\n",
            "cd".repeat(32)
        ))
        .unwrap();
        assert_eq!(p.seed[0], 0xcd);
        assert_eq!(p.allowed_ports, vec![80, 443]);
        assert!(format!("{p:?}").contains("<redacted>"));
        // `ports` omitted = any port (empty list).
        let open = ExitParams::from_config_str(&format!("seed = {}", "ab".repeat(32))).unwrap();
        assert!(open.allowed_ports.is_empty());
        // Missing seed / bad port / unknown key rejected.
        assert!(ExitParams::from_config_str("ports = 80").is_err());
        assert!(
            ExitParams::from_config_str(&format!("seed = {}\nports = notaport", "ab".repeat(32)))
                .is_err()
        );
        assert!(
            ExitParams::from_config_str(&format!("seed = {}\nbogus = 1", "ab".repeat(32))).is_err()
        );
    }

    #[test]
    fn rejects_malformed_service_params() {
        // Missing keys.
        assert!(ServiceParams::from_config_str("line = 1:0:0\nthreshold = 1").is_err()); // no seed
        assert!(
            ServiceParams::from_config_str(&format!("seed = {}\nthreshold = 1", "ab".repeat(32)))
                .is_err(),
            "empty line rejected"
        );
        // Bad seed length / hex.
        assert!(ServiceParams::from_config_str("seed = abcd\nline = 1:0:0\nthreshold = 1").is_err());
        assert!(
            ServiceParams::from_config_str(&format!(
                "seed = {}\nline = 1:0:0\nthreshold = 1",
                "zz".repeat(32)
            ))
            .is_err(),
            "non-hex seed rejected"
        );
        // Unknown key and bad coordinate.
        assert!(
            ServiceParams::from_config_str(&format!(
                "seed = {}\nline = 1:0:0\nthreshold = 1\nbogus = 1",
                "ab".repeat(32)
            ))
            .is_err()
        );
        assert!(
            ServiceParams::from_config_str(&format!(
                "seed = {}\nline = 1:0\nthreshold = 1",
                "ab".repeat(32)
            ))
            .is_err(),
            "two-component coordinate rejected"
        );
    }

    #[test]
    fn parses_a_config_file() {
        let cfg = NodeConfig::from_config_str(
            "# a relay node\nlisten = 127.0.0.1:9000\nrole = relay,storage\nbootstrap = 1:2:3@10.0.0.1:9000, 4:5:6@10.0.0.2:9000\nheartbeat = false\n",
        )
        .unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:9000".parse().unwrap());
        assert!(cfg.roles.relay && cfg.roles.storage && !cfg.roles.exit);
        assert_eq!(cfg.bootstrap.len(), 2);
        assert!(!cfg.start_heartbeat);
        assert!(cfg.beacon.is_none());
    }

    #[test]
    fn config_file_rejects_unknown_keys_and_malformed_values() {
        assert!(NodeConfig::from_config_str("bogus = 1").is_err()); // unknown key fails loudly
        assert!(NodeConfig::from_config_str("listen 127.0.0.1:9000").is_err()); // no '='
        assert!(NodeConfig::from_config_str("listen = not-an-addr").is_err());
        assert!(NodeConfig::from_config_str("heartbeat = maybe").is_err());
    }

    #[test]
    fn config_file_comments_and_blanks_keep_defaults() {
        let cfg = NodeConfig::from_config_str("\n  # only a comment\n\n").unwrap();
        assert!(cfg.start_heartbeat); // the default is preserved
        assert!(cfg.bootstrap.is_empty());
        assert!(cfg.identity_path.is_none());
    }

    #[test]
    fn proteus_secret_enables_shaping_and_is_off_by_default() {
        // PROTEUS (§13.4) is opt-in: default off (plaintext QUIC), enabled by a non-empty shared secret.
        assert!(NodeConfig::default().proteus_secret.is_none(), "off by default");
        let cfg = NodeConfig::from_config_str("proteus_secret = a-shared-bridge-secret").unwrap();
        assert_eq!(cfg.proteus_secret.as_deref(), Some(&b"a-shared-bridge-secret"[..]));
        // An empty secret is a configuration error, not a silent no-op.
        assert!(NodeConfig::from_config_str("proteus_secret =").is_err());
    }

    #[test]
    fn proteus_morph_selects_the_shaping_profile() {
        // Defaults to the flagship polymorph; a valid name selects a shaping morph; a bad name errors.
        assert_eq!(NodeConfig::default().proteus_morph, Morph::Polymorph);
        let cfg = NodeConfig::from_config_str("proteus_morph = tls-tunnel").unwrap();
        assert_eq!(cfg.proteus_morph, Morph::TlsTunnel);
        assert!(NodeConfig::from_config_str("proteus_morph = nonsense").is_err());
    }

    #[test]
    fn proteus_environment_enables_auto_fallback() {
        // Off by default (fixed morph); a valid environment enables auto-fallback; a bad name errors.
        assert!(NodeConfig::default().proteus_environment.is_none());
        let cfg = NodeConfig::from_config_str("proteus_environment = deep-censorship").unwrap();
        assert_eq!(cfg.proteus_environment, Some(Environment::DeepCensorship));
        assert!(NodeConfig::from_config_str("proteus_environment = nowhere").is_err());
    }

    #[test]
    fn an_ingress_provisioning_file_round_trips_and_still_serves() {
        use fanos_calypso::hosting::Share;
        use fanos_geometry::Point;
        use fanos_field::F2;
        use crate::poros::{IngressDescriptor, Recovery, recover, shard_descriptor};

        // **The ceremony's whole point, asserted as one property**: what `fanos ingress-deal` writes must,
        // after a trip through the file format, still reconstruct the descriptor it dealt. A codec that loses
        // a byte of the share or of the binding produces a line that starts cleanly and admits nobody — and
        // the binding is what makes that failure *loud* rather than a wrong ingress set, so it has to survive
        // the round trip too.
        let peers: Vec<Peer> = (0..4)
            .map(|i| Peer {
                coord: Point::<F2>::at(i % 7).coords(),
                addr: SocketAddr::from(([203, 0, 113, i as u8], 9000 + i as u16)),
            })
            .collect();
        let descriptor = IngressDescriptor { peers };
        let (threshold, line_size) = (2usize, 3u8);
        let randomness = vec![0x4Du8; descriptor.to_bytes().len() * threshold + 32];
        let dealt = shard_descriptor(&descriptor, threshold as u8, line_size, &randomness).unwrap();
        let line: Vec<Triple> = (0..3).map(|i| Point::<F2>::at(i).coords()).collect();

        let written: Vec<IngressParams> = dealt
            .shares
            .iter()
            .map(|share| IngressParams {
                community: b"a-community-secret".to_vec(),
                share: share.clone(),
                binding: dealt.binding.clone(),
                line: line.clone(),
                threshold,
                difficulty: 12,
                kem_seed: [0x9Cu8; 32],
            })
            .collect();

        let read: Vec<IngressParams> = written
            .iter()
            .map(|p| IngressParams::from_config_str(&p.to_config_string()).expect("round trip"))
            .collect();

        for (a, b) in written.iter().zip(&read) {
            assert_eq!(a.community, b.community);
            assert_eq!(a.share.x(), b.share.x(), "the share index survives");
            assert_eq!(a.share.y(), b.share.y(), "and every byte of its value");
            assert_eq!(a.binding, b.binding, "the binding is not separable from the share");
            assert_eq!((a.line.clone(), a.threshold, a.difficulty), (b.line.clone(), b.threshold, b.difficulty));
            assert_eq!(a.kem_seed, b.kem_seed);
        }

        // The property, not the fields: a threshold of the shares as they came back OFF DISK recovers the
        // dealt descriptor, verified against the binding that travelled with them.
        let recovered: Vec<Share> = read.iter().take(threshold).map(|p| p.share.clone()).collect();
        let commitment = read.first().expect("a dealt line has members").binding.commitment();
        assert_eq!(
            recover(&recovered, threshold, &commitment),
            Recovery::Recovered(descriptor, None),
            "a threshold of provisioned members reconstructs the committed descriptor",
        );
    }
}
