//! `ra` — command-line front end for the BO3 cipher engine.

mod corpus;
mod gate;
mod repair;
mod spec;
mod sweep;
mod variants;
mod web;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ra_core::{registry, Display, Repr};

#[derive(Parser)]
#[command(
    name = "ra",
    about = "BO3 Zombies cipher engine: pluggable pipelines, exact coverage, gated attestation.",
    version
)]
struct Cli {
    /// Directory holding the corpus JSON. Defaults to $RA_DATA_DIR, else the nearest
    /// `data/` directory found by walking up from the working directory.
    #[arg(long, global = true)]
    data: Option<std::path::PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List every registered node plugin with its content-addressed identity.
    Nodes {
        /// Show the parameter schema for each node.
        #[arg(long)]
        schema: bool,
    },
    /// Run one pipeline against an input and print the result.
    Run {
        /// Chain spec, e.g. "hexdecode | xtea:key=Zombies | reverse | rot:n=20".
        chain: String,
        /// Literal input.
        #[arg(long, conflicts_with_all = ["target", "file"])]
        input: Option<String>,
        /// Corpus cipher id to use as input, e.g. tg4, rev7, rev12.
        #[arg(long)]
        target: Option<String>,
        /// Read the input from a file.
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        /// How to interpret the input's display when it is not from the corpus.
        #[arg(long, default_value = "bytes")]
        display: String,
        /// Print the per-step layer analysis.
        #[arg(long)]
        trace: bool,
        /// Score the output with a named oracle.
        #[arg(long)]
        oracle: Option<String>,
    },
    /// Sweep a parameter space, commit to it, and report hits.
    Sweep(sweep::SweepArgs),
    /// Inventory exact first-layer outputs before transform/codec/layer 2.
    PrefixInventory(sweep::PrefixInventoryArgs),
    /// Sweep transcription *repairs* jointly with cipher parameters.
    ///
    /// A sweep takes the recorded ciphertext as given; the corpus shows that
    /// assumption fails (rev2, rev8). `--grid` reports the transcription grid and
    /// the repair arithmetic without searching anything.
    Repair(repair::RepairArgs),
    /// Compute UNIVERSE \ CLAIMS exactly, and show what remains.
    Residual {
        /// Model the full mcrypt menu rather than only the observed one.
        #[arg(long)]
        full: bool,
        /// Fold real claims emitted by `ra sweep --emit-claim` into the aggregate,
        /// so the residual reflects work actually done rather than only the worked
        /// example.
        #[arg(long, value_delimiter = ',')]
        claims: Vec<std::path::PathBuf>,
    },
    /// Check that a claim can regenerate its own commitment.
    ///
    /// The coverage digest is order-independent by design; the Merkle root is
    /// order-*dependent* by necessity, because `leaf_hash` binds the candidate index.
    /// A claim therefore has to record the enumeration order, and this is what checks
    /// that it does and that it rebuilds.
    VerifyClaim {
        /// Path to a claim emitted by `ra sweep --emit-claim`.
        path: std::path::PathBuf,
        /// Re-run the enumeration and compare the Merkle root byte for byte. Costs
        /// what the original run cost.
        #[arg(long)]
        recompute: bool,
    },
    /// Inspect an attestation: claimed versus conformance-gated coverage.
    Attest {
        /// Path to an attestation JSON document.
        path: std::path::PathBuf,
    },
    /// Reproduce the solved corpus to prove the primitives are correct.
    Conformance {
        /// Only check this primitive.
        #[arg(long)]
        prim: Option<String>,
    },
    /// Show what is known about a target cipher.
    Target {
        /// Cipher id, e.g. tg4 or rev7.
        id: String,
    },
    /// Serve a local web interface to the engine: build a chain, watch the
    /// candidate count update live, run it, and watch progress.
    ///
    /// Binds 127.0.0.1 only — this exposes an execution engine and must never be
    /// reachable off-machine.
    Serve {
        /// TCP port to listen on.
        #[arg(long, default_value_t = 8787)]
        port: u16,
        /// Open the UI in the default browser once the server is listening.
        #[arg(long)]
        open: bool,
    },
}

fn main() -> Result<()> {
    // Force the plugin crates to be linked so their registry entries exist. A
    // library dependency the binary never names by path can be dropped by the
    // linker, silently emptying the registry.
    ra_prim::link();

    let cli = Cli::parse();
    let data = corpus::resolve_data_dir(cli.data.as_deref())?;

    match cli.cmd {
        Cmd::Nodes { schema } => cmd_nodes(schema),
        Cmd::Run {
            chain,
            input,
            target,
            file,
            display,
            trace,
            oracle,
        } => cmd_run(&data, &chain, input, target, file, &display, trace, oracle),
        Cmd::Sweep(args) => sweep::run(&data, args),
        Cmd::PrefixInventory(args) => sweep::run_prefix_inventory(&data, args),
        Cmd::Repair(args) => repair::run(&data, args),
        Cmd::Residual { full, claims } => cmd_residual(&data, full, &claims),
        Cmd::VerifyClaim { path, recompute } => sweep::verify(&data, &path, recompute),
        Cmd::Attest { path } => cmd_attest(&data, &path),
        Cmd::Conformance { prim } => corpus::run_conformance(&data, prim.as_deref()),
        Cmd::Target { id } => corpus::show_target(&data, &id),
        Cmd::Serve { port, open } => web::run(&data, port, open),
    }
}

fn cmd_nodes(schema: bool) -> Result<()> {
    let reg = registry();
    println!("{} registered node plugins\n", reg.len());
    // the registry is name-ordered; group by family for display
    let mut nodes: Vec<_> = reg.iter().collect();
    nodes.sort_by_key(|n| (n.family(), n.name()));
    let mut family = "";
    for node in nodes {
        let fam = node.family().as_str();
        if fam != family {
            println!("[{fam}]");
            family = fam;
        }
        let flags = if node.terminal() {
            "  TERMINAL, heuristic coverage"
        } else if node.layer_forming() {
            "  layer-forming"
        } else {
            ""
        };
        println!("  {}{}", node.node_id(), flags);
        if schema {
            for p in node.params_schema() {
                let req = if p.required { "required" } else { "optional" };
                println!(
                    "      {:<10} {:<6} {:<9} {}",
                    p.name,
                    format!("{:?}", p.ty),
                    req,
                    p.doc
                );
            }
        }
    }
    Ok(())
}

fn parse_display(s: &str) -> Result<Display> {
    Ok(match s {
        "bytes" => Display::Bytes,
        "hex" => Display::Hex,
        "base64" | "b64" => Display::Base64,
        "decimal" => Display::Decimal,
        "octal" => Display::Octal,
        other => anyhow::bail!("unknown display {other:?}"),
    })
}

#[allow(clippy::too_many_arguments)]
fn cmd_run(
    data: &std::path::Path,
    chain_spec: &str,
    input: Option<String>,
    target: Option<String>,
    file: Option<std::path::PathBuf>,
    display: &str,
    trace: bool,
    oracle: Option<String>,
) -> Result<()> {
    let chain = spec::parse_chain(chain_spec)?;

    let (bytes, disp) = match (input, target, file) {
        (Some(s), _, _) => (s.into_bytes(), parse_display(display)?),
        (_, Some(id), _) => {
            let c = corpus::load_target(data, &id)?;
            println!("input: {} ({}, {} chars)", id, c.display_hint, c.raw.len());
            // A target carrying `ciphertext_canonical` may admit a reading that
            // differs from the legacy `raw` string (TG4's canonical differs at
            // offset 39). Feeding `raw` unconditionally here fed a `--target tg4`
            // run the wrong ciphertext even after `sweep` and `residual` agreed on
            // the canonical one — so this goes through the same
            // `Target::variant_space`/`select("recorded")` machinery they use,
            // rather than reading `raw` directly.
            let display = c.display;
            let bytes = if c.ciphertext_canonical.is_some() {
                let compact: Vec<u8> =
                    c.raw.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
                anyhow::ensure!(
                    compact.len() == c.raw.len(),
                    "{id} carries a ciphertext_canonical but its recorded ciphertext \
                     contains whitespace; the canonical narrowing's offsets are defined \
                     over the compacted text and cannot be safely reapplied to the raw one"
                );
                let vspace = c.variant_space(&format!("{}-exact", c.display_hint))?;
                let mask = vspace.select("recorded")?[0];
                let mut out = Vec::new();
                vspace.apply(mask, &compact, &mut out);
                out
            } else {
                c.raw.into_bytes()
            };
            (bytes, display)
        }
        (_, _, Some(p)) => (
            std::fs::read(&p).with_context(|| format!("reading {}", p.display()))?,
            parse_display(display)?,
        ),
        _ => anyhow::bail!("one of --input, --target or --file is required"),
    };

    let start = Repr::new(bytes, disp);
    println!("chain: {}", spec::render_chain(&chain));
    println!("chain id: {}", chain.chain_id());

    let (out, tr) = chain.run_traced(&start)?;

    if trace {
        println!("\nlayer analysis:");
        let mut layers = 0;
        for t in &tr {
            let mark = if t.delta.is_layer_boundary {
                layers += 1;
                "LAYER"
            } else if t.delta.notable {
                "notable"
            } else {
                "-"
            };
            println!(
                "  {:<44} {:>8}  entropy {:>6.3} -> {:>6.3} ({:+.3})  {} -> {}",
                t.node_id,
                mark,
                t.delta.entropy_before,
                t.delta.entropy_after,
                t.delta.entropy_delta,
                t.delta.class_before.as_str(),
                t.delta.class_after.as_str()
            );
        }
        println!("  => {layers} layer boundaries crossed");
    }

    if let Some(id) = oracle {
        let spec = ra_oracle::oracle(&id).with_context(|| format!("unknown oracle {id:?}"))?;
        let s = spec.score(&out.data, chain.terminal_block_size());
        println!(
            "\noracle {}: score={:.4} class={} skipped={} scored={} => {}",
            id,
            s.score,
            s.class.as_str(),
            s.skipped,
            s.scored_len,
            if s.passed { "PASS" } else { "fail" }
        );
    }

    println!("\noutput ({} bytes):", out.data.len());
    println!("{}", String::from_utf8_lossy(&out.data));
    Ok(())
}

fn cmd_residual(data: &std::path::Path, full: bool, claim_paths: &[std::path::PathBuf]) -> Result<()> {
    use ra_covalg::{product, Cover, CoverageSet};

    // The transcription dimension is *derived from the corpus ciphertext*, not written
    // down: the ciphertext admits 2^7 = 128 raw I/l readings once the `0`/`O` pair is
    // fixed against the source font. The project owner has since supplied a canonical
    // transcription (`ciphertext_canonical`) that resolves all but one of those seven
    // positions, so the admissible space narrows further, to 2. Deriving both from the
    // corpus record means a re-transcription, or a change to what the canonical text
    // resolves, moves the universe rather than leaving it stale.
    let tg4 = corpus::load_target(data, "tg4")?;
    let compact: Vec<u8> = tg4
        .raw
        .bytes()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let vspace = tg4.variant_space(&format!("{}-exact", tg4.display_hint))?;
    let variants: Vec<String> = vspace.masks().iter().map(|&m| vspace.label(m)).collect();
    let open = vspace.open_positions();
    println!(
        "TG4 transcription: {} open ambiguous glyph position{} {:?} -> {} admissible \
         reading{} ({}); {} more positions are resolved (against the source font, or by \
         the project owner's canonical transcription) and fixed.",
        open.len(),
        if open.len() == 1 { "" } else { "s" },
        open,
        vspace.count(),
        if vspace.count() == 1 { "" } else { "s" },
        variants.join(", "),
        vspace.positions().len() - open.len()
            + variants::VariantSpace::resolved_positions(&compact, tg4.display).len(),
    );
    let keys = [
        "TheGiant",
        "Zombies",
        "ZOMBIES",
        "thegiant",
        "TheGiant_b64",
        "zombies",
    ];
    let confirmed: Vec<String> = ra_prim::PRIMS
        .iter()
        .map(|p| p.display_name.to_string())
        .collect();
    let prims: Vec<String> = if full {
        let mut v = confirmed.clone();
        v.extend(
            [
                "CAST-128",
                "CAST-256",
                "TripleDES",
                "Enigma",
                "Gost",
                "Rijndael-128",
                "Rijndael-192",
                "Wake",
            ]
            .iter()
            .map(|s| s.to_string()),
        );
        v
    } else {
        confirmed.clone()
    };
    let modes: Vec<String> = if full {
        ra_prim::Mode::ALL.iter().map(|m| m.to_string()).collect()
    } else {
        vec!["cfb".into(), "ecb".into()]
    };
    let ivs: Vec<String> = if full {
        vec!["ascii0".into(), "null".into(), "other".into()]
    } else {
        vec!["ascii0".into()]
    };
    let kd: Vec<String> = ra_prim::KeyDerivation::ALL
        .iter()
        .map(|k| k.to_string())
        .collect();
    let xf = ["identity", "reverse", "rot", "route4"];

    let sk_t1 = sweep::Tier::T1.skeleton();
    let sk_t2 = sweep::Tier::T2.skeleton();
    // T3's skeleton carries the inter-layer `codec` slot. The reference model's
    // ("b64d","dec","xf","dec") omits it, and therefore does not contain the
    // pipelines that actually solved the corpus — every recorded chain hides a
    // decode at each decrypt hop.
    let sk_t3 = sweep::Tier::T3.skeleton();
    let codecs = sweep::codec_domain();

    let mut universe = CoverageSet::new();
    universe.add(Cover::new(
        sk_t1.clone(),
        vec![product! {
            "0.variant" => variants, "1.key" => keys, "1.kd" => kd,
            "1.prim" => prims, "1.mode" => modes, "1.iv" => ivs,
        }],
    ));
    universe.add(Cover::new(
        sk_t2.clone(),
        vec![product! {
            "0.variant" => variants, "1.xf" => xf, "2.key" => keys, "2.kd" => kd,
            "2.prim" => prims, "2.mode" => modes, "2.iv" => ivs,
        }],
    ));
    universe.add(Cover::new(
        sk_t3,
        vec![product! {
            "0.variant" => variants,
            "1.key" => keys, "1.kd" => kd, "1.prim" => prims,
            "1.mode" => modes, "1.iv" => ivs,
            "2.xf" => xf, "3.codec" => codecs,
            "4.key" => keys, "4.kd" => kd, "4.prim" => prims,
            "4.mode" => modes, "4.iv" => ivs,
        }],
    ));

    println!(
        "UNIVERSE (TG4, tiers T1-T3, {} menu)",
        if full { "full mcrypt" } else { "observed" }
    );
    for (sk, cov) in &universe.covers {
        println!("  <{}>  size = {}", sk.join(" o "), fmt(cov.size_exact()));
    }
    println!("  TOTAL  = {}", fmt(universe.size_exact()));
    println!("  digest = {}", &universe.digest()[..26]);

    // Conformance is executed here, not read off a document. Every claim below is
    // intersected with what actually reproduces *now*, so a primitive that regressed
    // between a sweep and this residual voids its coverage rather than smuggling a
    // fabricated negative into the result.
    let conformance = corpus::conformance_state(data, None)?;
    println!(
        "\nCONFORMANCE GATE: {} of {} mcrypt primitives reproduce right now (suite {})",
        conformance.proven.len(),
        ra_prim::PRIMS.len(),
        &conformance.suite_digest[..24.min(conformance.suite_digest.len())]
    );
    if conformance.proven.len() < ra_prim::PRIMS.len() {
        for info in ra_prim::PRIMS {
            if !conformance.proven.contains(info.display_name) {
                println!(
                    "  UNPROVEN {}: {}",
                    info.display_name,
                    conformance.void_reason(info.display_name)
                );
            }
        }
    } else {
        println!("  gating is currently the identity, and is applied anyway.");
    }
    if !conformance.no_vector.is_empty() {
        println!(
            "  no conformance vector exists for: {}",
            conformance
                .no_vector
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let stock = ["DES", "RC2", "RC4", "Blowfish"];
    // The recorded reading, and the readings within one glyph correction of it. Both
    // are derived from the same space the universe is, so the worked example cannot
    // drift out of the model it is differenced against.
    let recorded = vspace.label(0);
    let first_three: Vec<String> = vspace
        .masks()
        .iter()
        .take(3)
        .map(|&m| vspace.label(m))
        .collect();
    let mut claims: Vec<(String, CoverageSet, gate::Provenance)> = Vec::new();

    let mut a = CoverageSet::new();
    a.add(Cover::new(
        sk_t1.clone(),
        vec![product! {
            "0.variant" => [recorded.as_str()], "1.key" => ["TheGiant"], "1.kd" => ["null-pad-max"],
            "1.prim" => stock, "1.mode" => ["cfb","ecb"], "1.iv" => ["ascii0"],
        }],
    ));
    claims.push((
        "A  single layer, key TheGiant, stock primitives".to_string(),
        a,
        gate::Provenance::InProcess,
    ));

    let mut b = CoverageSet::new();
    b.add(Cover::new(
        sk_t1,
        vec![product! {
            "0.variant" => variants,
            "1.key" => ["Zombies"], "1.kd" => ["null-pad-max","repeat-pad-max"],
            "1.prim" => confirmed, "1.mode" => ["cfb","ecb"], "1.iv" => ["ascii0"],
        }],
    ));
    claims.push((
        "B  single layer, key Zombies, all confirmed primitives".to_string(),
        b,
        gate::Provenance::InProcess,
    ));

    let mut c = CoverageSet::new();
    c.add(Cover::new(
        sk_t2,
        vec![product! {
            "0.variant" => [recorded.as_str()], "1.xf" => ["reverse"], "2.key" => keys,
            "2.kd" => ["null-pad-max"], "2.prim" => stock,
            "2.mode" => ["cfb","ecb"], "2.iv" => ["ascii0"],
        }],
    ));
    claims.push((
        "C  reverse + modern, stock primitives".to_string(),
        c,
        gate::Provenance::InProcess,
    ));

    // Deliberately overlaps claim B, so the aggregate exercises the difference
    // machinery rather than a trivially disjoint union. This overlap is exactly what
    // a count-based report cannot see: two teams reporting their totals would
    // double-count every candidate in the intersection.
    let mut d = CoverageSet::new();
    d.add(Cover::new(
        vec!["b64d".to_string(), "dec".to_string()],
        vec![product! {
            "0.variant" => first_three, "1.key" => ["Zombies"],
            "1.kd" => ["null-pad-max"], "1.prim" => ["DES","Twofish","Serpent"],
            "1.mode" => ["cfb"], "1.iv" => ["ascii0"],
        }],
    ));
    claims.push((
        "D  a second team's run, overlapping B".to_string(),
        d,
        gate::Provenance::InProcess,
    ));

    // Real claims, loaded from `ra sweep --emit-claim`. A sweep's output is meant to
    // be an input here, not a report to read: this is the whole reason the sweep
    // emits a set with a digest rather than a count.
    for p in claim_paths {
        let set = sweep::load_claim(p)?;
        let name = format!(
            "*  {} (loaded from a real sweep)",
            p.file_name().and_then(|s| s.to_str()).unwrap_or("claim")
        );
        let provenance = match sweep::load_claim_conformance(p)? {
            Some(c) => gate::Provenance::Recorded {
                suite_digest: c.suite_digest,
                proven: c.proven,
            },
            None => gate::Provenance::Absent,
        };
        claims.push((name, set, provenance));
    }

    // Nothing reaches the aggregate except through the gate. `gate_claims` returns
    // only gated claims, so there is no route from here to a raw `CoverageSet`.
    let proven = conformance.proven_primitives();
    let claims = gate::gate_claims(claims, &conformance)?;

    println!("\nREGISTERED CLAIMS");
    let mut combined = CoverageSet::new();
    let mut naive: u128 = 0;
    let mut voided_total: u128 = 0;
    for c in &claims {
        println!("\n{}", c.name);
        println!("   digest = {}", &c.claimed.digest()[..26]);
        gate::report(c, &proven);
        for line in c.effective().notation().lines() {
            println!("   {line}");
        }
        // Everything downstream is computed from EFFECTIVE coverage. Claimed coverage
        // is an assertion; only what survives the gate is evidence.
        naive += c.effective_size();
        voided_total += c.claimed_size() - c.effective_size();
        combined = combined.union(c.effective());
    }
    if voided_total > 0 {
        println!(
            "\n  {} of claimed coverage was VOIDED by conformance gating and is not in \
             the aggregate below.",
            fmt(voided_total)
        );
    }

    let exact = combined.size_exact();
    println!("\nAGGREGATE (union, overlap removed exactly)");
    println!("  naive sum of claims = {}", fmt(naive));
    println!("  exact union         = {}", fmt(exact));
    println!(
        "  double counted      = {}   <- invisible if you only report counts",
        fmt(naive - exact)
    );

    let residual = universe.difference(&combined);
    println!("\nRESIDUAL = UNIVERSE \\ AGGREGATE");
    for (sk, cov) in &residual.covers {
        println!(
            "  <{}>  remaining = {}  ({} disjoint blocks)",
            sk.join(" o "),
            fmt(cov.size_exact()),
            cov.products.len()
        );
    }
    println!("  TOTAL REMAINING   = {}", fmt(residual.size_exact()));
    // Coverage achieved is |U| - |U \ A|, not |A|. Those coincide only while every
    // claim lies inside the modelled universe; a real sweep need not. Dividing |A|
    // by |U| reported 153% once actual claims (7 modes, both IVs) were folded into
    // the observed-menu universe, which models 2 modes and one IV — an over-claim of
    // exactly the kind this command exists to detect.
    let universe_size = universe.size_exact();
    let covered = universe_size - residual.size_exact();
    println!(
        "  coverage achieved = {:.6}% of the modelled universe  ({} of {})",
        100.0 * covered as f64 / universe_size as f64,
        fmt(covered),
        fmt(universe_size)
    );
    let outside = exact - covered;
    if outside > 0 {
        println!(
            "  claimed OUTSIDE the modelled universe = {}   <- the model is narrower \
             than the work;\n                                          widen it (--full) \
             or those candidates buy no residual",
            fmt(outside)
        );
    }
    println!("  residual digest   = {}", &residual.digest()[..26]);
    Ok(())
}

fn cmd_attest(data: &std::path::Path, path: &std::path::Path) -> Result<()> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading attestation {}", path.display()))?;
    let doc: serde_json::Value = serde_json::from_str(&raw)?;
    let suite = corpus::conformance_vectors(data)?;

    println!("attestation: {}", path.display());
    println!(
        "  claim_id : {}",
        doc["claim_id"].as_str().unwrap_or("(missing)")
    );
    println!(
        "  target   : {}",
        doc["target"].as_str().unwrap_or("(missing)")
    );
    println!(
        "  oracle   : {}",
        doc["oracle"]["id"].as_str().unwrap_or("(missing)")
    );

    let empty = vec![];
    if let Some(v) = doc["validation"].as_object() {
        for key in ["errors", "warnings"] {
            let items = v.get(key).and_then(|x| x.as_array()).unwrap_or(&empty);
            println!("\n  {key} ({}):", items.len());
            for item in items {
                println!("    - {}", item.as_str().unwrap_or_default());
            }
            if items.is_empty() {
                println!("    (none)");
            }
        }
        for key in ["proven", "unproven"] {
            let items: Vec<&str> = v
                .get(key)
                .and_then(|x| x.as_array())
                .unwrap_or(&empty)
                .iter()
                .filter_map(|x| x.as_str())
                .collect();
            println!("  {key:<9}: {items:?}");
        }
    }

    // Sizes may be a JSON string (this engine emits u128 as a string, since JSON
    // numbers cannot hold one) or a number (the Python reference emits an int).
    let size_of = |k: &str| -> String {
        match &doc[k] {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => "?".to_string(),
        }
    };
    let claimed = size_of("coverage_claimed_size");
    let effective = size_of("coverage_effective_size");
    println!("\n  claimed coverage   = {claimed}");
    println!("  effective coverage = {effective}  (after conformance gating)");
    if claimed != effective {
        println!("  => part of this claim carries no coverage and must not enter the residual");
    }

    println!(
        "\n  conformance suite defines vectors for {} primitives",
        suite.len()
    );
    Ok(())
}

pub fn fmt(n: u128) -> String {
    if n < 10_000 {
        return n.to_string();
    }
    let f = n as f64;
    for (unit, div) in [
        ("e18", 1e18),
        ("e15", 1e15),
        ("e12", 1e12),
        ("e9", 1e9),
        ("e6", 1e6),
        ("e3", 1e3),
    ] {
        if f >= div {
            return format!("{:.2}{}", f / div, unit);
        }
    }
    n.to_string()
}
