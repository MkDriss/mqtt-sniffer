//! Bibliothèque `mqtt_sniffer` : la logique réutilisable du projet.
//!
//! Le package contient deux crates :
//! - ce crate bibliothèque (`src/lib.rs`), réutilisable par d'autres outils ;
//! - le crate binaire (`src/main.rs`), une simple interface en ligne de commande.
//!
//! Modules, de la capture à l'interprétation :
//! - [`capture`] : ouverture d'une capture libpcap ;
//! - [`parser`] : découpage d'une trame Ethernet → IP → TCP ;
//! - [`checksum`] : vérification des checksums IPv4 et TCP ;
//! - [`tcp`] : réassemblage des flux TCP ;
//! - [`mqtt`] : décodage des messages MQTT 3.1.1 ;
//! - [`analyzer`] : relie réassemblage et décodage, et signale tout ce qui est
//!   observé sous forme d'événements.

pub mod analyzer;
pub mod capture;
pub mod checksum;
pub mod mqtt;
pub mod parser;
pub mod tcp;
