//! Every file a dealing ceremony writes is classified, and the secret ones are unreadable by anyone else.
//!
//! `fanos` has one writer that sets `0600` **before** the bytes land ([`write_file`]), and a comment on it
//! saying why the order matters. Five secret-bearing dealer outputs went around it and landed at the process
//! umask — 0644 on the usual host — so a beacon share, a POROS share, a validator's config and the genesis
//! founder's spending seed were readable by every account on the dealing machine (task #82). The guard was
//! never missing; it was written, documented, and simply not called on the paths that hold the most.
//!
//! So this test does not check that some files are 0600. It checks that **the produced set is exactly the
//! classified set**: a ceremony that grows a new output fails here until someone decides which kind it is.
//! That is the property — the classification is total — and it is the only form that survives the next file.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A directory of this test's own, removed when it drops.
///
/// Named per test rather than per process: these run in parallel in one binary, and a shared directory would
/// make each ceremony's file list the union of all of them — which is exactly the assertion under test.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("fanos-ceremony-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the ceremony's output directory");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Best-effort: a leaked directory holds dealt SECRETS, so a failure here is worth the noise, but
        // panicking in a Drop during an unwind would abort and hide the assertion that actually failed.
        if let Err(e) = std::fs::remove_dir_all(&self.0) {
            eprintln!("could not remove {}: {e}", self.0.display());
        }
    }
}

/// Run `fanos <args…>` in a fresh directory and return the names of the files it wrote.
fn deal(dir: &Path, args: &[&str]) -> BTreeSet<String> {
    let out = Command::new(env!("CARGO_BIN_EXE_fanos"))
        .args(args)
        .output()
        .expect("the fanos binary is built by the test harness");
    assert!(
        out.status.success(),
        "`fanos {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read_dir(dir)
        .expect("the ceremony's output directory")
        .map(|e| e.expect("dir entry").file_name().to_string_lossy().into_owned())
        .collect()
}

/// Assert `dir` holds exactly `secret ∪ public`, that every secret file is owner-only, and — the half that
/// keeps this honest — that every public one is NOT, so a blanket `0600` cannot satisfy the test vacuously.
///
/// The **modes are checked first**, deliberately. Both halves can fail at once — an unprotected new output
/// is unclassified AND world-readable — and a set-equality assertion reports only "the lists differ", which
/// is the ratchet talking, not the exposure. First failure wins in Rust, so the order of these two blocks
/// decides which one an operator reads.
fn assert_classified(dir: &Path, produced: &BTreeSet<String>, secret: &[&str], public: &[&str]) {
    for name in secret {
        let meta = std::fs::metadata(dir.join(name))
            .unwrap_or_else(|e| panic!("the ceremony must deal {name}, and did not: {e}"));
        let mode = meta.permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "{name} carries key material and is mode {mode:o} — readable off-owner. Deal it through \
             write_file(.., secret = true), which sets the mode at creation rather than after."
        );
    }
    for name in public {
        let meta = std::fs::metadata(dir.join(name))
            .unwrap_or_else(|e| panic!("the ceremony must deal {name}, and did not: {e}"));
        let mode = meta.permissions().mode();
        assert_ne!(
            mode & 0o077,
            0,
            "{name} is public material dealt as a secret. Not itself an exposure, but it makes the secret \
             half of this test unfalsifiable — every file 0600 passes whatever the ceremony does."
        );
    }
    let classified: BTreeSet<String> =
        secret.iter().chain(public).map(|s| (*s).to_owned()).collect();
    assert_eq!(
        *produced, classified,
        "a ceremony output is unclassified: this test is the only thing that forces a new dealt file to be \
         declared secret or public, so it fails until someone decides"
    );
}

#[test]
fn the_beacon_ceremony_deals_every_share_owner_only() {
    const SCRATCH: &str = "beacon";
    let dir = Scratch::new(SCRATCH);
    let path = dir.path().to_string_lossy().into_owned();
    let produced = deal(dir.path(), &["beacon-deal", "7", "3", "--out", &path]);
    assert_classified(
        dir.path(),
        &produced,
        &[
            "anchor-1.beacon",
            "anchor-2.beacon",
            "anchor-3.beacon",
            "anchor-4.beacon",
            "anchor-5.beacon",
            "anchor-6.beacon",
            "anchor-7.beacon",
            "recovery-authority-1.key",
            "recovery-authority-2.key",
            "recovery-authority-3.key",
            "recovery-authority-4.key",
            "recovery-authority-5.key",
            "recovery-authority-6.key",
            "recovery-authority-7.key",
        ],
        // The consumer's copy carries the commitment and the threshold and no share at all — it is what a
        // client is *given*, so dealing it 0600 would be a category error, not caution.
        &["consumer.beacon"],
    );
}

/// Gated on the feature that builds the chain into the binary: without it `taxis-deal` refuses by design,
/// and CI runs the suite both ways, so this is covered rather than skipped.
#[cfg(feature = "validator")]
#[test]
fn the_taxis_ceremony_deals_every_validator_owner_only() {
    const SCRATCH: &str = "taxis";
    let dir = Scratch::new(SCRATCH);
    let path = dir.path().to_string_lossy().into_owned();
    let produced = deal(dir.path(), &["taxis-deal", "--out", &path]);
    // 0-based, unlike `anchor-<i>.beacon`: the number in a validator's filename is the member index that
    // config carries, and divorcing the two to make the tooling look uniform would be the worse trade.
    let validators: Vec<String> = (0..7).map(|i| format!("validator-{i}.taxis")).collect();
    let mut secret: Vec<&str> = validators.iter().map(String::as_str).collect();
    secret.push("founder.key");
    assert_classified(dir.path(), &produced, &secret, &["chain-info.taxis"]);
}

#[test]
fn the_ingress_ceremony_deals_every_share_owner_only() {
    const SCRATCH: &str = "ingress";
    let dir = Scratch::new(SCRATCH);
    let path = dir.path().to_string_lossy().into_owned();
    let produced =
        deal(dir.path(), &["ingress-deal", "acme", "1:0:0@127.0.0.1:9001", "--out", &path]);
    assert_classified(
        dir.path(),
        &produced,
        &["ingress-1.poros", "ingress-2.poros", "ingress-3.poros"],
        &[],
    );
}

#[test]
fn a_founder_generates_their_own_authority_key_and_it_never_leaves_owner_only() {
    const SCRATCH: &str = "authkey";
    let dir = Scratch::new(SCRATCH);
    let key = dir.path().join("mine.key");
    let produced = deal(dir.path(), &["authority-key", "--out", &key.to_string_lossy()]);
    assert_classified(dir.path(), &produced, &["mine.key"], &[]);
}

/// The trust-minimized founding (#74): each founder generates locally, the dealer assembles verifiers and
/// **never holds an authority secret**.
///
/// The property is the absence: with `--authority-verifiers` the ceremony must write no authority key at
/// all — the same file list minus the secrets it did not create. If the dealer kept generating them "as a
/// backup" the ceremony would still work and the whole point would be gone, so the assertion is on the set.
#[test]
fn founders_can_supply_their_own_verifiers_and_the_dealer_deals_no_authority_secret() {
    const SCRATCH: &str = "byfounders";
    let dir = Scratch::new(SCRATCH);
    let path = dir.path().to_string_lossy().into_owned();

    // Three founders, each on their own machine, each keeping their seed.
    let mut verifiers = Vec::new();
    for i in 0..3 {
        let home = Scratch::new(&format!("{SCRATCH}-founder-{i}"));
        let key = home.path().join("mine.key");
        let out = Command::new(env!("CARGO_BIN_EXE_fanos"))
            .args(["authority-key", "--out", &key.to_string_lossy()])
            .output()
            .expect("the fanos binary");
        assert!(out.status.success(), "founder {i} could not generate a key");
        let text = String::from_utf8(out.stdout).expect("utf-8");
        // The verifier is the one long hex line the founder is told to send back.
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| l.len() > 64 && l.chars().all(|c| c.is_ascii_hexdigit()))
            .expect("`fanos authority-key` prints the verifier to hand to the dealer");
        verifiers.push(line.to_owned());
        assert!(key.exists(), "the seed stays on the founder's own machine");
    }
    let list = dir.path().join("verifiers.txt");
    std::fs::write(&list, format!("# collected in agreed order\n{}\n", verifiers.join("\n")))
        .expect("write the collected verifiers");

    let produced = deal(
        dir.path(),
        &["beacon-deal", "3", "2", "--out", &path, "--authority-verifiers", &list.to_string_lossy()],
    );
    assert_classified(
        dir.path(),
        &produced,
        &["anchor-1.beacon", "anchor-2.beacon", "anchor-3.beacon"],
        &["consumer.beacon", "verifiers.txt"],
    );
}

/// A verifier list whose length disagrees with the cell is refused, because the order and the count are
/// genesis material: a signature names its member by INDEX, so a list one short does not shrink the
/// committee — it renames every member after the gap.
#[test]
fn a_verifier_list_that_does_not_match_the_cell_is_refused() {
    const SCRATCH: &str = "mismatch";
    let dir = Scratch::new(SCRATCH);
    let path = dir.path().to_string_lossy().into_owned();
    let list = dir.path().join("verifiers.txt");

    let key = dir.path().join("mine.key");
    let out = Command::new(env!("CARGO_BIN_EXE_fanos"))
        .args(["authority-key", "--out", &key.to_string_lossy()])
        .output()
        .expect("the fanos binary");
    let text = String::from_utf8(out.stdout).expect("utf-8");
    let one = text
        .lines()
        .map(str::trim)
        .find(|l| l.len() > 64 && l.chars().all(|c| c.is_ascii_hexdigit()))
        .expect("the verifier line");
    std::fs::write(&list, format!("{one}\n")).expect("write");

    // One verifier, seven anchors.
    let out = Command::new(env!("CARGO_BIN_EXE_fanos"))
        .args([
            "beacon-deal",
            "7",
            "3",
            "--out",
            &path,
            "--authority-verifiers",
            &list.to_string_lossy(),
        ])
        .output()
        .expect("the fanos binary");
    assert!(!out.status.success(), "a 1-member committee for a 7-anchor cell was dealt");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("verifiers"),
        "the refusal must name the mismatch it is about; got: {err}"
    );
}

/// **Every member's file must carry the SAME roster**, which is the only thing this ceremony exists to
/// guarantee — the seeds are independent and each operator could have drawn their own.
///
/// Assembling a service line was once entirely manual: each operator ran `openssl rand -hex 32` and
/// hand-copied the roster. The failure that makes a tool worth having is not a weak seed, it is a roster
/// that differs by one coordinate between two members — a line that cannot reconstruct and says nothing
/// when it fails to.
///
/// **This ceremony now also mints and splits the service's signing identity (§12.3 half (a))**, so the
/// sentence this doc used to carry — "the members hold independent keys rather than shares of one split
/// secret, and this dealer holds no secret after it exits, because there is no split secret for it to
/// hold" — is no longer true and would have been the most reassuring wrong claim in the file. There IS a
/// split secret now; what stays true is that the dealer keeps no copy of it, and that is asserted below
/// rather than described.
#[test]
fn the_service_ceremony_deals_one_roster_and_keeps_every_seed_apart() {
    const SCRATCH: &str = "service";
    let dir = Scratch::new(SCRATCH);
    let path = dir.path().to_string_lossy().into_owned();
    let produced =
        deal(dir.path(), &["service-deal", "1:0:0", "0:1:0", "0:0:1", "--out", &path]);
    assert_classified(
        dir.path(),
        &produced,
        &["service-1.conf", "service-2.conf", "service-3.conf"],
        // The verifier is the one half of the identity that survives the ceremony, and it is public by
        // construction — a client checks a registration against it. Classified as public *because* the
        // rest of the identity is now secret: a file an operator cannot tell apart from the shares is a
        // file they will guard wrongly in one of the two directions.
        &["service-identity.pub"],
    );

    let files: Vec<String> = (1..=3)
        .map(|i| {
            std::fs::read_to_string(dir.path().join(format!("service-{i}.conf"))).expect("member file")
        })
        .collect();

    let roster_of = |text: &str| -> Vec<String> {
        text.lines()
            .filter(|l| l.starts_with("line =") || l.starts_with("threshold ="))
            .map(str::to_owned)
            .collect()
    };
    let first = roster_of(&files[0]);
    assert!(!first.is_empty(), "a member file must name the line and the threshold");
    for (i, text) in files.iter().enumerate() {
        assert_eq!(
            roster_of(text),
            first,
            "member {} disagrees about the line or the threshold — the one thing dealing all the files from \
             a single list is supposed to make impossible",
            i + 1
        );
    }

    // And the seeds are independent — one per member, never a copy.
    let seeds: BTreeSet<&str> = files
        .iter()
        .filter_map(|t| t.lines().find(|l| l.starts_with("seed =")))
        .collect();
    assert_eq!(seeds.len(), 3, "every member must get its own seed, not a copy of one");

    // Every member gets a DISTINCT identity slot, and every member gets one. A ceremony that wrote the same
    // slot three times would still parse, still start three nodes, and still be unable to reconstruct
    // anything — Shamir needs distinct points.
    let slots: BTreeSet<&str> = files
        .iter()
        .filter_map(|t| t.lines().find(|l| l.starts_with("identity_share =")))
        .collect();
    assert_eq!(slots.len(), 3, "every member must get its own identity slot, and one each");
}

/// **The property the whole of §12.3 half (a) exists for, proven against the files the real binary wrote:
/// `threshold` members reconstruct the service's signing identity, and `threshold − 1` reconstruct nothing.**
///
/// This is the falsification that matters, and it is stated as a comparison against the PUBLISHED verifier
/// rather than against a value this test knows: the recovered seed must regenerate the very keypair whose
/// public half `service-identity.pub` carries. Anything weaker — "the reconstruction succeeded", "the bytes
/// are 32 long" — would pass for a ceremony that dealt a secret unrelated to the identity it published,
/// which is precisely the failure a threshold custody must not have.
///
/// The below-threshold arm is the security claim itself. Shamir gives it information-theoretically, so what
/// is being checked here is not the mathematics but the WIRING: that the dealer split the identity at the
/// threshold it printed, over the members it addressed, and not at some other one.
#[test]
fn a_threshold_of_members_reconstructs_the_published_identity_and_fewer_reconstruct_nothing() {
    use fanos_calypso::hosting::{open_service_share, recover_service_key};
    use fanos_node::ServiceParams;
    use fanos_pqcrypto::{HybridKemSecret, SeedRng};
    use fanos_pqcrypto::sig::HybridSigSecret;

    const SCRATCH: &str = "service-identity";
    let dir = Scratch::new(SCRATCH);
    let path = dir.path().to_string_lossy().into_owned();
    let _produced = deal(dir.path(), &["service-deal", "1:0:0", "0:1:0", "0:0:1", "--out", &path]);

    // Read the three member files exactly as a node would, and open each member's own slot with the key its
    // own seed regenerates — the same two lines `composition.rs` and the startup check run.
    let members: Vec<ServiceParams> = (1..=3)
        .map(|i| {
            let text = std::fs::read_to_string(dir.path().join(format!("service-{i}.conf")))
                .expect("member file");
            ServiceParams::from_config_str(&text).expect("a node must be able to read what the dealer wrote")
        })
        .collect();
    assert_eq!(members[0].threshold, 2, "the Fano default for a 3-member line is 2-of-3");

    let opened: Vec<_> = members
        .iter()
        .map(|m| {
            let (secret, _public) = HybridKemSecret::generate(&mut SeedRng::from_seed(&m.seed));
            open_service_share(m.identity_share.as_ref().expect("every member is dealt a slot"), &secret)
                .expect("a member's own slot opens under its own key")
        })
        .collect();

    // The published verifier — the only half of the identity that survived the ceremony.
    let pub_text = std::fs::read_to_string(dir.path().join("service-identity.pub")).expect("the public half");
    let published_hex = pub_text
        .lines()
        .find_map(|l| l.strip_prefix("verifier = "))
        .expect("the public file names the verifier")
        .trim()
        .to_owned();

    // THRESHOLD: any 2 of the 3 recover the seed, and it regenerates exactly the published keypair.
    for pair in [[0usize, 1], [0, 2], [1, 2]] {
        let shares = [opened[pair[0]].clone(), opened[pair[1]].clone()];
        let seed = recover_service_key(&shares).expect("two members reconstruct");
        let (_signer, verifier) = HybridSigSecret::generate(&mut SeedRng::from_seed(&seed));
        assert_eq!(
            fanos_node::config::hex_encode(&verifier.encode()),
            published_hex,
            "members {pair:?} recovered a secret that is NOT the identity the ceremony published — a \
             custody that reconstructs something else is worse than none, because it looks like it works",
        );
    }

    // BELOW THRESHOLD: one member alone recovers nothing that is this identity. Checked as "not the
    // published verifier" rather than "the call fails", because Lagrange over one point returns a value
    // quite happily — the security claim is that the value is unrelated, not that the arithmetic refuses.
    for (i, share) in opened.iter().enumerate() {
        let alone = recover_service_key(std::slice::from_ref(share));
        if let Ok(seed) = alone {
            let (_s, verifier) = HybridSigSecret::generate(&mut SeedRng::from_seed(&seed));
            assert_ne!(
                fanos_node::config::hex_encode(&verifier.encode()),
                published_hex,
                "member {i} alone reconstructed the service identity — the whole of §12.3 half (a) is that \
                 seizing fewer than the threshold yields nothing",
            );
        }
    }

    // And the dealer kept nothing: no file it wrote contains the identity in a form one member could use.
    // The public file is the verifier, which is a PUBLIC key — it must not be mistakable for the seed.
    assert!(
        !pub_text.contains("seed") && !pub_text.contains("identity_share"),
        "the public file must carry the verifier and nothing that reconstructs the secret: {pub_text}",
    );
}

/// A one-member line, or a threshold of one, is refused: it inverts the claim a threshold line makes.
#[test]
fn a_service_line_that_one_member_could_serve_alone_is_refused() {
    const SCRATCH: &str = "service-degenerate";
    let dir = Scratch::new(SCRATCH);
    let path = dir.path().to_string_lossy().into_owned();
    for (what, args) in [
        ("a threshold of one", vec!["service-deal", "1:0:0", "0:1:0", "--threshold", "1", "--out", &path]),
        ("a threshold above the line", vec!["service-deal", "1:0:0", "--threshold", "2", "--out", &path]),
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_fanos")).args(&args).output().expect("the fanos binary");
        assert!(!out.status.success(), "{what} was dealt");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("threshold"),
            "{what}: the refusal must name what it is about"
        );
    }
}
