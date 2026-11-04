//! Module `mqtt` : décodeur MQTT 3.1.1 écrit à partir de la spécification OASIS.
//!
//! Référence : *MQTT Version 3.1.1*, OASIS, 2014.
//! <https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html>
//! Les identifiants entre crochets (ex. `[MQTT-2.2.2-1]`) renvoient aux
//! exigences numérotées de la spécification.
//!
//! # Principes de conception
//!
//! - **zéro-copie** : topics, payloads et identifiants sont des `&str` / `&[u8]`
//!   qui pointent dans le buffer d'entrée ;
//! - **fonction pure** : [`decode()`] ne connaît ni le réseau ni TCP, elle prend
//!   des octets et dit ce qu'elle y trouve ;
//! - **framing explicite** : [`decode()`] indique combien d'octets elle a
//!   consommés, ou combien il en manque (utile au réassemblage TCP) ;
//! - **erreurs détaillées** : chaque violation de la spec a sa propre variante
//!   de [`MqttError`], car une anomalie est une information à rapporter.
//!
//! # Organisation des fichiers
//!
//! | Fichier          | Contenu                                                      |
//! |------------------|--------------------------------------------------------------|
//! | `types.rs`       | [`PacketType`] et [`QoS`]                                    |
//! | `error.rs`       | [`MqttError`] : toutes les violations détectables            |
//! | `packet.rs`      | [`Packet`] et [`Decoded`] : ce que renvoie le décodeur       |
//! | `decode.rs`      | [`decode()`] : en-tête fixe, Remaining Length, framing         |
//! | `reader.rs`      | `Reader` : lecture des champs avec vérification des limites  |
//! | `connect.rs`     | CONNECT et CONNACK (spec §3.1-3.2)                           |
//! | `publish.rs`     | PUBLISH et ses acquittements PUBACK/PUBREC/PUBREL/PUBCOMP    |
//! | `subscribe.rs`   | SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK (spec §3.8-3.11)    |
//! | `display.rs`     | affichage sécurisé (`describe`, neutralisation CWE-150)      |
//!
//! Les sous-modules sont privés : le reste du programme n'utilise que les
//! éléments ré-exportés ci-dessous (`pub use`).

mod connect;
mod decode;
mod display;
mod error;
mod packet;
mod publish;
mod reader;
mod subscribe;
mod types;

#[cfg(test)]
mod test_util;

pub use connect::{ConnAck, Connect, Will};
pub use decode::decode;
pub use error::MqttError;
pub use packet::{Decoded, Packet};
pub use publish::{PubAck, PubComp, PubRec, PubRel, Publish};
pub use subscribe::{SubAck, Subscribe, UnsubAck, Unsubscribe};
pub use types::{PacketType, QoS};

/// Port TCP standard de MQTT sans TLS.
pub const MQTT_PORT: u16 = 1883;
