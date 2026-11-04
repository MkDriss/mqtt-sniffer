//! Écrit les captures de test (scénarios) dans un dossier, pour les rejouer
//! avec le sniffer :
//!
//! ```text
//! cargo run --example scenarios -- scenarios/
//! cargo run -- --read scenarios/desordre.pcap
//! ```
//!
//! Les scénarios sont définis dans `tests/common/mod.rs`, partagés avec les
//! tests d'intégration.

#[path = "../tests/common/mod.rs"]
mod common;

use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "scenarios".into()),
    );
    std::fs::create_dir_all(&dir)?;
    for scenario in common::scenarios() {
        let path = dir.join(format!("{}.pcap", scenario.name));
        common::write_pcap(&path, &scenario.frames)?;
        println!("{:<45} {}", path.display(), scenario.description);
    }
    Ok(())
}
