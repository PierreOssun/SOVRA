//! The `certs` verbs: thin wrappers over `sovra-certs`, printed for humans.
//! No HTTP, no state beyond the pem files — these exist so a deployed host
//! provisions with the shipped binary instead of the Rust toolchain, and so
//! the CSR flow's operator review ("what does this CSR ask for?") has a
//! place to happen.

use std::process::ExitCode;

use crate::types::CertsCommand;

pub fn run(cmd: &CertsCommand) -> ExitCode {
    match execute(cmd) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::FAILURE
        }
    }
}

fn execute(cmd: &CertsCommand) -> Result<(), String> {
    match cmd {
        CertsCommand::Ca { dir } => {
            sovra_certs::ensure_ca(dir).map_err(|e| e.to_string())?;
            println!(
                "CA ready under {} — {} stays on THIS machine",
                dir.display(),
                sovra_certs::CA_KEY_FILE
            );
            Ok(())
        }
        CertsCommand::Csr { dir, stem, cn, san } => {
            let cn = cn.clone().unwrap_or_else(|| format!("sovra-{stem}"));
            let mut sans = sovra_certs::default_sans();
            sans.extend(san.iter().cloned());
            let paths =
                sovra_certs::generate_csr(dir, stem, &cn, &sans).map_err(|e| e.to_string())?;
            println!(
                "key born at {} (never leaves this host)\nsend {} to the CA machine",
                paths.key.display(),
                paths.csr.display()
            );
            Ok(())
        }
        CertsCommand::Sign { csr, dir, out } => {
            let csr_pem =
                std::fs::read_to_string(csr).map_err(|e| format!("{}: {e}", csr.display()))?;
            let summary = sovra_certs::describe_csr(&csr_pem).map_err(|e| e.to_string())?;
            println!("signing request: {summary}");
            let ca = sovra_certs::ensure_ca(dir).map_err(|e| e.to_string())?;
            let cert_pem = sovra_certs::sign_csr(&ca, &csr_pem).map_err(|e| e.to_string())?;
            // cosigner1.csr.pem -> cosigner1.cert.pem, next to the CSR.
            let out = out.clone().unwrap_or_else(|| {
                let stem = csr
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("leaf")
                    .trim_end_matches(".csr.pem");
                csr.with_file_name(format!("{stem}.cert.pem"))
            });
            std::fs::write(&out, cert_pem).map_err(|e| format!("{}: {e}", out.display()))?;
            println!(
                "signed → {} (public — send it back to the node)",
                out.display()
            );
            Ok(())
        }
    }
}
