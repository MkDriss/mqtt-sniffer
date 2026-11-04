//! Bibliothèque `mqtt_sniffer` : la logique réutilisable du projet.
//!
//! Le package contient deux crates :
//! - ce crate bibliothèque (`src/lib.rs`);
//! - le crate binaire (`src/main.rs`), une simple interface en ligne de commande.

pub mod capture;
pub mod mqtt;
pub mod parser;
