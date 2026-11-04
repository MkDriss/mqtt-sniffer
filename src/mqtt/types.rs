//! Types de base : la sorte d'un paquet ([`PacketType`]) et le niveau de
//! qualité de service ([`QoS`]).

/// Les 14 types de paquets de contrôle (spec §2.2.1, table 2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Connect,
    ConnAck,
    Publish,
    PubAck,
    PubRec,
    PubRel,
    PubComp,
    Subscribe,
    SubAck,
    Unsubscribe,
    UnsubAck,
    PingReq,
    PingResp,
    Disconnect,
}

impl PacketType {
    /// Convertit les 4 bits de poids fort du premier octet en type de paquet.
    /// Les valeurs 0 et 15 sont réservées (interdites) : on renvoie `None`.
    pub(super) fn from_nibble(value: u8) -> Option<PacketType> {
        use PacketType::*;
        match value {
            1 => Some(Connect),
            2 => Some(ConnAck),
            3 => Some(Publish),
            4 => Some(PubAck),
            5 => Some(PubRec),
            6 => Some(PubRel),
            7 => Some(PubComp),
            8 => Some(Subscribe),
            9 => Some(SubAck),
            10 => Some(Unsubscribe),
            11 => Some(UnsubAck),
            12 => Some(PingReq),
            13 => Some(PingResp),
            14 => Some(Disconnect),
            _ => None,
        }
    }

    /// Valeur obligatoire des flags (bits 3-0) pour ce type (spec §2.2.2,
    /// table 2.2). PUBLISH est le seul type dont les flags varient : `None`.
    pub(super) fn required_flags(self) -> Option<u8> {
        use PacketType::*;
        match self {
            Publish => None,
            PubRel | Subscribe | Unsubscribe => Some(0b0010),
            _ => Some(0b0000),
        }
    }

    /// Nom officiel du type, en majuscules comme dans la spec.
    pub fn name(self) -> &'static str {
        use PacketType::*;
        match self {
            Connect => "CONNECT",
            ConnAck => "CONNACK",
            Publish => "PUBLISH",
            PubAck => "PUBACK",
            PubRec => "PUBREC",
            PubRel => "PUBREL",
            PubComp => "PUBCOMP",
            Subscribe => "SUBSCRIBE",
            SubAck => "SUBACK",
            Unsubscribe => "UNSUBSCRIBE",
            UnsubAck => "UNSUBACK",
            PingReq => "PINGREQ",
            PingResp => "PINGRESP",
            Disconnect => "DISCONNECT",
        }
    }
}

/// Niveau de qualité de service (spec §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QoS {
    AtMostOnce = 0,
    AtLeastOnce = 1,
    ExactlyOnce = 2,
}

impl QoS {
    /// 0, 1 ou 2 ; la valeur 3 est interdite [MQTT-3.3.1-4].
    pub(super) fn from_u8(value: u8) -> Option<QoS> {
        match value {
            0 => Some(QoS::AtMostOnce),
            1 => Some(QoS::AtLeastOnce),
            2 => Some(QoS::ExactlyOnce),
            _ => None,
        }
    }
}
