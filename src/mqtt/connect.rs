//! CONNECT (spec §3.1) et CONNACK (spec §3.2) : ouverture d'une session MQTT.

use super::decode::expect_len;
use super::reader::Reader;
use super::{MqttError, PacketType, QoS};

/// Message « testament » publié par le broker si le client disparaît
/// sans DISCONNECT (spec §3.1.2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Will<'a> {
    pub topic: &'a str,
    pub message: &'a [u8],
    pub qos: QoS,
    pub retain: bool,
}

/// Contenu décodé d'un CONNECT (spec §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect<'a> {
    pub protocol_level: u8,
    pub clean_session: bool,
    pub keep_alive: u16,
    pub client_id: &'a str,
    pub will: Option<Will<'a>>,
    pub username: Option<&'a str>,
    /// Données binaires (pas forcément du texte) [spec §3.1.3.5].
    pub password: Option<&'a [u8]>,
}

/// Contenu décodé d'un CONNACK (spec §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnAck {
    pub session_present: bool,
    pub return_code: u8,
}

// ===========================================================================
// Décodage
// ===========================================================================

/// CONNECT (spec §3.1).
pub(super) fn decode_connect(body: &[u8]) -> Result<Connect<'_>, MqttError> {
    let mut r = Reader::new(body);

    // En-tête variable : nom du protocole, niveau, flags, keep alive.
    if r.binary("nom du protocole")? != b"MQTT" {
        return Err(MqttError::InvalidProtocolName);
    }
    let protocol_level = r.u8("niveau de protocole")?;
    if protocol_level != 4 {
        return Err(MqttError::UnsupportedProtocolLevel(protocol_level));
    }

    let flags = r.u8("connect flags")?;
    if flags & 0b0000_0001 != 0 {
        return Err(MqttError::ReservedBits {
            field: "connect flags [MQTT-3.1.2-3]",
        });
    }
    let clean_session = flags & 0b0000_0010 != 0;
    let will_flag = flags & 0b0000_0100 != 0;
    let will_qos = (flags >> 3) & 0b11;
    let will_retain = flags & 0b0010_0000 != 0;
    let password_flag = flags & 0b0100_0000 != 0;
    let username_flag = flags & 0b1000_0000 != 0;

    if !will_flag && (will_qos != 0 || will_retain) {
        return Err(MqttError::InvalidConnectFlags(
            "Will QoS ou Will Retain non nuls sans Will Flag [MQTT-3.1.2-13] [MQTT-3.1.2-15]",
        ));
    }
    if password_flag && !username_flag {
        return Err(MqttError::InvalidConnectFlags(
            "Password Flag sans User Name Flag [MQTT-3.1.2-22]",
        ));
    }

    let keep_alive = r.u16("keep alive")?;

    // Payload : les champs apparaissent dans cet ordre précis [MQTT-3.1.3-1].
    let client_id = r.string("client identifier")?;
    if client_id.is_empty() && !clean_session {
        return Err(MqttError::InvalidConnectFlags(
            "ClientId vide avec Clean Session à 0 [MQTT-3.1.3-7]",
        ));
    }

    let will = if will_flag {
        let qos = QoS::from_u8(will_qos).ok_or(MqttError::InvalidQos(will_qos))?;
        Some(Will {
            topic: r.string("will topic")?,
            message: r.binary("will message")?,
            qos,
            retain: will_retain,
        })
    } else {
        None
    };
    let username = if username_flag {
        Some(r.string("user name")?)
    } else {
        None
    };
    let password = if password_flag {
        Some(r.binary("password")?)
    } else {
        None
    };

    r.expect_end(PacketType::Connect)?;

    Ok(Connect {
        protocol_level,
        clean_session,
        keep_alive,
        client_id,
        will,
        username,
        password,
    })
}

/// CONNACK (spec §3.2) : toujours exactement 2 octets.
pub(super) fn decode_connack(body: &[u8]) -> Result<ConnAck, MqttError> {
    expect_len(PacketType::ConnAck, body, 2)?;
    if body[0] & 0b1111_1110 != 0 {
        return Err(MqttError::ReservedBits {
            field: "connect acknowledge flags",
        });
    }
    Ok(ConnAck {
        session_present: body[0] & 0b0000_0001 != 0,
        return_code: body[1],
    })
}

// ===========================================================================
// Tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::mqtt::test_util::{complete, CONNECT_AVEC_IDENTIFIANTS};
    use crate::mqtt::{decode, Packet};

    #[test]
    fn connect_de_mosquitto_sub() {
        let buf = [
            0x10, 0x0c, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00,
        ];
        let (packet, consumed) = complete(&buf);
        assert_eq!(consumed, 14);
        let Packet::Connect(c) = packet else {
            panic!("CONNECT attendu")
        };
        assert_eq!(c.protocol_level, 4);
        assert!(c.clean_session);
        assert_eq!(c.keep_alive, 60);
        assert_eq!(c.client_id, "");
        assert_eq!(c.username, None);
        assert_eq!(c.password, None);
    }

    #[test]
    fn connack_accepte() {
        let (packet, _) = complete(&[0x20, 0x02, 0x00, 0x00]);
        assert_eq!(
            packet,
            Packet::ConnAck(ConnAck {
                session_present: false,
                return_code: 0
            })
        );
    }

    #[test]
    fn connect_avec_identifiants_en_clair() {
        let (packet, _) = complete(&CONNECT_AVEC_IDENTIFIANTS);
        let Packet::Connect(c) = packet else {
            panic!("CONNECT attendu")
        };
        assert_eq!(c.client_id, "actionneur");
        assert_eq!(c.username, Some("admin"));
        assert_eq!(c.password, Some(&b"1234"[..]));
    }

    #[test]
    fn password_sans_username_est_interdit() {
        let mut buf = CONNECT_AVEC_IDENTIFIANTS;
        buf[9] = 0x42; // password flag sans user name flag
        assert!(matches!(
            decode(&buf),
            Err(MqttError::InvalidConnectFlags(_))
        ));
    }
}
