//! `validation-crd-export` — emits the three CRD YAML manifests on stdout
//! for consumption by `lareira-akeyless-validation`'s Helm chart.
//!
//! Run with `--out DIR` to write one file per CRD into DIR.

use std::path::PathBuf;

use kube::CustomResourceExt;
use validation_crds::{AkeylessEphemeralTenant, AkeylessImageValidation, ScanJob};

fn main() -> anyhow::Result<()> {
    let mut out_dir: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" => out_dir = args.next().map(PathBuf::from),
            "-h" | "--help" => {
                eprintln!("validation-crd-export [--out DIR]");
                eprintln!();
                eprintln!("Emits the three AKEYLESS-VALIDATION-PLATFORM CRD manifests.");
                eprintln!("Without --out, prints all three concatenated to stdout.");
                eprintln!("With --out DIR, writes:");
                eprintln!("  DIR/akeylessimagevalidations.crd.yaml");
                eprintln!("  DIR/akeylessephemeraltenants.crd.yaml");
                eprintln!("  DIR/scanjobs.crd.yaml");
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown flag: {other}"),
        }
    }

    let crds: Vec<(&'static str, String)> = vec![
        ("akeylessimagevalidations", serde_yaml::to_string(&AkeylessImageValidation::crd())?),
        ("akeylessephemeraltenants", serde_yaml::to_string(&AkeylessEphemeralTenant::crd())?),
        ("scanjobs",                 serde_yaml::to_string(&ScanJob::crd())?),
    ];

    if let Some(dir) = out_dir {
        std::fs::create_dir_all(&dir)?;
        for (name, yaml) in &crds {
            let path = dir.join(format!("{name}.crd.yaml"));
            std::fs::write(&path, yaml)?;
            eprintln!("wrote {}", path.display());
        }
    } else {
        for (_, yaml) in &crds {
            println!("---");
            print!("{yaml}");
        }
    }

    Ok(())
}
