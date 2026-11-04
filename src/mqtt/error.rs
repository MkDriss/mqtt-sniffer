//! [`MqttError`] : toutes les violations de la spécification que le décodeur
//! sait détecter, avec leur affichage lisible (référence de l'exigence incluse).

use std::fmt;

use super::PacketType;

/// Toutes les violations de la spécification que le décodeur sait détecter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MqttError {
    /// Type 0 ou 15, réservés.
    InvalidPacketType(u8),
    /// Bits 3-0 de l'en-tête fixe différents de la valeur imposée.
    InvalidFlags { packet_type: PacketType, flags: u8 },
    /// Remaining Length codée sur plus de 4 octets.
    MalformedRemainingLength,
    /// Un champ annonce plus d'octets que le paquet n'en contient.
    BoundaryCrossed { field: &'static str },
    /// Le CONNECT ne commence pas par la chaîne "MQTT".
    InvalidProtocolName,
    /// Niveau de protocole autre que 4 (MQTT 3.1.1).
    UnsupportedProtocolLevel(u8),
    /// Combinaison de Connect Flags interdite.
    InvalidConnectFlags(&'static str),
    /// Bit réservé positionné à 1.
    ReservedBits { field: &'static str },
    /// QoS égale à 3.
    InvalidQos(u8),
    /// DUP à 1 sur un PUBLISH de QoS 0.
    DupWithQos0,
    /// Joker `+` ou `#` dans le topic d'un PUBLISH.
    WildcardInTopicName,
    /// Chaîne qui n'est pas de l'UTF-8 valide.
    InvalidUtf8 { field: &'static str },
    /// Caractère nul U+0000 dans une chaîne.
    NullCharacter { field: &'static str },
    /// Packet Identifier égal à 0.
    ZeroPacketId,
    /// SUBSCRIBE sans aucun filtre.
    EmptySubscribe,
    /// UNSUBSCRIBE sans aucun filtre.
    EmptyUnsubscribe,
    /// Code de retour de SUBACK hors de {0x00, 0x01, 0x02, 0x80}.
    InvalidSubAckCode(u8),
    /// Longueur différente de celle imposée pour ce type de paquet.
    UnexpectedLength {
        packet_type: PacketType,
        expected: usize,
        actual: usize,
    },
    /// Octets en trop après le dernier champ attendu.
    TrailingBytes {
        packet_type: PacketType,
        count: usize,
    },
}

impl fmt::Display for MqttError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use MqttError::*;
        match self {
            InvalidPacketType(t) => write!(f, "type de paquet réservé ({t}) (spec §2.2.1)"),
            InvalidFlags { packet_type, flags } => write!(
                f,
                "flags {flags:#06b} invalides pour {} [MQTT-2.2.2-1]",
                packet_type.name()
            ),
            MalformedRemainingLength => {
                write!(f, "Remaining Length sur plus de 4 octets (spec §2.2.3)")
            }
            BoundaryCrossed { field } => {
                write!(f, "le champ « {field} » dépasse la fin du paquet")
            }
            InvalidProtocolName => {
                write!(f, "nom de protocole différent de \"MQTT\" [MQTT-3.1.2-1]")
            }
            UnsupportedProtocolLevel(l) => {
                write!(
                    f,
                    "niveau de protocole {l} non supporté (4 attendu) [MQTT-3.1.2-2]"
                )
            }
            InvalidConnectFlags(why) => write!(f, "Connect Flags invalides : {why}"),
            ReservedBits { field } => write!(f, "bit(s) réservé(s) à 1 dans « {field} »"),
            InvalidQos(q) => write!(f, "QoS {q} interdite [MQTT-3.3.1-4]"),
            DupWithQos0 => write!(f, "DUP à 1 sur un PUBLISH de QoS 0 [MQTT-3.3.1-2]"),
            WildcardInTopicName => {
                write!(f, "joker dans le topic d'un PUBLISH [MQTT-3.3.2-2]")
            }
            InvalidUtf8 { field } => {
                write!(f, "« {field} » n'est pas de l'UTF-8 valide [MQTT-1.5.3-1]")
            }
            NullCharacter { field } => write!(f, "caractère nul dans « {field} » [MQTT-1.5.3-2]"),
            ZeroPacketId => write!(f, "Packet Identifier nul [MQTT-2.3.1-1]"),
            EmptySubscribe => write!(f, "SUBSCRIBE sans filtre [MQTT-3.8.3-3]"),
            EmptyUnsubscribe => write!(f, "UNSUBSCRIBE sans filtre [MQTT-3.10.3-2]"),
            InvalidSubAckCode(c) => {
                write!(f, "code de retour SUBACK {c:#04x} réservé [MQTT-3.9.3-2]")
            }
            UnexpectedLength {
                packet_type,
                expected,
                actual,
            } => write!(
                f,
                "{} de longueur {actual} (attendu : {expected})",
                packet_type.name()
            ),
            TrailingBytes { packet_type, count } => {
                write!(
                    f,
                    "{count} octet(s) en trop à la fin d'un {}",
                    packet_type.name()
                )
            }
        }
    }
}

impl std::error::Error for MqttError {}
