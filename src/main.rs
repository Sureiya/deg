use deg::artifact::ArtifactSet;
use deg::kernel::{self, ClaimStatus, ObligationStatus};
use deg::parser::parse_model;
use deg::report;
use deg::semantic::ModelIndex;
use deg::stdlib::STDLIB;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = r#"deg — a proof language for game client/server reverse engineering

Usage:
  deg check <model.dg> [--artifacts DIR] [--json] [--strict]
  deg seal  <model.dg> [--artifacts DIR] [--out FILE] [--strict]
  deg report <model.dg> [--artifacts DIR] [--json]
  deg explain <model.dg> <claim> [--artifacts DIR]
  deg artifacts <model.dg> [--artifacts DIR] [--json]
  deg port <model.dg> --to <build> [--artifacts DIR] [--json]
  deg stdlib
  deg version

Exit codes: 0 ok, 1 check/seal failures, 2 usage or parse error.
"#;

struct Opts {
    model: Option<String>,
    artifacts: Option<PathBuf>,
    json: bool,
    strict: bool,
    out: Option<PathBuf>,
    to: Option<String>,
    extra: Option<String>,
}

fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        model: None,
        artifacts: None,
        json: false,
        strict: false,
        out: None,
        to: None,
        extra: None,
    };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--artifacts" => {
                i += 1;
                o.artifacts = Some(PathBuf::from(
                    args.get(i).ok_or("--artifacts needs a directory")?,
                ));
            }
            "--json" => o.json = true,
            "--strict" => o.strict = true,
            "--out" => {
                i += 1;
                o.out = Some(PathBuf::from(args.get(i).ok_or("--out needs a file")?));
            }
            "--to" => {
                i += 1;
                o.to = Some(args.get(i).ok_or("--to needs a build name")?.clone());
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown option `{other}`"));
            }
            _ => {
                if o.model.is_none() {
                    o.model = Some(a.clone());
                } else if o.extra.is_none() {
                    o.extra = Some(a.clone());
                } else {
                    return Err(format!("unexpected argument `{a}`"));
                }
            }
        }
        i += 1;
    }
    Ok(o)
}

fn load(model: &str, artifacts_root: Option<&Path>) -> Result<(ModelIndex, ArtifactSet), String> {
    let src = fs::read_to_string(model).map_err(|e| format!("cannot read {model}: {e}"))?;
    let parsed = parse_model(model, &src)?;
    let index = ModelIndex::new(&parsed).map_err(|errs| errs.join("\n"))?;
    let artifacts = ArtifactSet::load(&parsed, artifacts_root);
    Ok((index, artifacts))
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let cmd = argv[0].clone();
    let rest = &argv[1..];

    if cmd == "version" || cmd == "--version" {
        println!("deg {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if cmd == "stdlib" {
        println!("{STDLIB}");
        return ExitCode::SUCCESS;
    }
    if cmd == "help" || cmd == "--help" || cmd == "-h" {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let opts = match parse_opts(rest) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("deg: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let Some(model_path) = opts.model.clone() else {
        eprintln!("deg: missing model path\n\n{USAGE}");
        return ExitCode::from(2);
    };

    let (index, artifacts) = match load(&model_path, opts.artifacts.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("deg: {e}");
            return ExitCode::from(2);
        }
    };
    let report = kernel::check(&index, &artifacts);

    match cmd.as_str() {
        "check" => {
            if opts.json {
                println!("{}", report::report_json(&report, &index));
            } else {
                report::print_check(&report, &model_path, opts.strict);
            }
            if !report.ok {
                return ExitCode::from(1);
            }
            if opts.strict && report.seal_ready().is_err() {
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        "seal" => {
            let mut hard = report.errors.clone();
            for o in report.open_blocking_obligations() {
                hard.push(format!(
                    "obligation {} is open and blocks seal: {}",
                    o.name, o.goal
                ));
            }
            for c in report.unresolved_conflicts() {
                hard.push(format!(
                    "unresolved conflict {} between {} and {}",
                    c.name, c.left, c.right
                ));
            }
            let mut hypotheses = Vec::new();
            for c in &report.claims {
                match c.status {
                    ClaimStatus::Sealed | ClaimStatus::Provisional => {}
                    ClaimStatus::Hypothesis => hypotheses.push(c.name.clone()),
                    _ => hard.push(format!(
                        "claim {} is {} and cannot be sealed",
                        c.name,
                        c.status.as_str()
                    )),
                }
            }
            if opts.strict && !hypotheses.is_empty() {
                hard.push(format!(
                    "{} claim(s) are only hypotheses: {} (--strict refuses to record them)",
                    hypotheses.len(),
                    hypotheses.join(", ")
                ));
            }
            if !hard.is_empty() {
                eprintln!("deg: seal refused");
                for e in hard {
                    eprintln!("  - {e}");
                }
                return ExitCode::from(1);
            }
            let out = opts
                .out
                .clone()
                .unwrap_or_else(|| Path::new(&model_path).with_extension("lock.json"));
            let json = kernel::lock_json(&index, &artifacts, &report);
            if let Err(e) = fs::write(&out, format!("{json}\n")) {
                eprintln!("deg: cannot write {}: {e}", out.display());
                return ExitCode::from(1);
            }
            println!(
                "sealed {} claim(s) ({} provisional) into {}",
                report
                    .claims
                    .iter()
                    .filter(|c| c.status == ClaimStatus::Sealed)
                    .count(),
                report
                    .claims
                    .iter()
                    .filter(|c| c.status == ClaimStatus::Provisional)
                    .count(),
                out.display()
            );
            if !hypotheses.is_empty() {
                println!(
                    "recorded {} hypothesis/hypotheses: {}",
                    hypotheses.len(),
                    hypotheses.join(", ")
                );
            }
            let open: Vec<&str> = report
                .obligations
                .iter()
                .filter(|o| o.status == ObligationStatus::Open)
                .map(|o| o.name.as_str())
                .collect();
            if !open.is_empty() {
                println!("open obligations recorded: {}", open.join(", "));
            }
            ExitCode::SUCCESS
        }
        "report" => {
            if opts.json {
                println!("{}", report::report_json(&report, &index));
            } else {
                print!("{}", report::markdown(&report, &index));
            }
            if report.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        "explain" => {
            let Some(claim) = opts.extra.clone() else {
                eprintln!("deg: explain needs a claim name\n\n{USAGE}");
                return ExitCode::from(2);
            };
            report::explain(&report, &claim);
            ExitCode::SUCCESS
        }
        "artifacts" => {
            if opts.json {
                println!("{}", report::artifacts_json(&report));
            } else {
                println!(
                    "{:<20} {:<10} {:<12} sha256",
                    "artifact", "kind", "verified"
                );
                for a in &report.artifacts {
                    println!(
                        "{:<20} {:<10} {:<12} {}",
                        a.name,
                        a.kind,
                        if a.verified { "yes" } else { "NO" },
                        a.actual_sha256
                    );
                }
            }
            if report.artifacts.iter().all(|a| a.verified) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        "port" => {
            let Some(to) = opts.to.clone() else {
                eprintln!("deg: port needs --to <build>\n\n{USAGE}");
                return ExitCode::from(2);
            };
            let port_report = deg::port::port(&index, &artifacts, &to);
            if opts.json {
                println!("{}", deg::port::port_json(&port_report));
            } else {
                deg::port::print_port(&port_report);
            }
            if port_report.errors.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        other => {
            eprintln!("deg: unknown command `{other}`\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}
