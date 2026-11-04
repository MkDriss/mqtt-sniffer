//! Gestion des abonnements : SUBSCRIBE (spec §3.8), SUBACK (§3.9),
//! UNSUBSCRIBE (§3.10) et UNSUBACK (§3.11).

use super::decode::decode_packet_id_only;
use super::reader::Reader;
use super::{MqttError, PacketType, QoS};

/// Contenu décodé d'un SUBSCRIBE (spec §3.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscribe<'a> {
    pub packet_id: u16,
    /// Couples (filtre de topic, QoS demandée). Le `Vec` alloue de la place
    /// pour les couples, mais les chaînes elles-mêmes ne sont pas copiées.
    pub filters: Vec<(&'a str, QoS)>,
}

/// Contenu décodé d'un SUBACK (spec §3.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubAck<'a> {
    pub packet_id: u16,
    /// Un code par filtre : 0x00, 0x01, 0x02 (QoS accordée) ou 0x80 (échec).
    pub return_codes: &'a [u8],
}

/// Contenu décodé d'un UNSUBSCRIBE (spec §3.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsubscribe<'a> {
    pub packet_id: u16,
    /// Filtres de topic à désabonner (pas de QoS, contrairement au SUBSCRIBE).
    pub filters: Vec<&'a str>,
}

/// Contenu décodé d'un UNSUBACK (spec §3.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsubAck {
    pub packet_id: u16,
}

// ===========================================================================
// Décodage
// ===========================================================================

/// SUBSCRIBE (spec §3.8) : Packet Identifier puis une liste (filtre, QoS).
pub(super) fn decode_subscribe(body: &[u8]) -> Result<Subscribe<'_>, MqttError> {
    let mut r = Reader::new(body);
    let packet_id = r.u16("packet identifier")?;
    if packet_id == 0 {
        return Err(MqttError::ZeroPacketId);
    }

    let mut filters = Vec::new();
    while r.remaining() > 0 {
        let filter = r.string("topic filter")?;
        let requested = r.u8("requested qos")?;
        if requested & 0b1111_1100 != 0 {
            return Err(MqttError::ReservedBits {
                field: "requested qos [MQTT-3-8.3-4]",
            });
        }
        let qos = QoS::from_u8(requested).ok_or(MqttError::InvalidQos(requested))?;
        filters.push((filter, qos));
    }

    if filters.is_empty() {
        return Err(MqttError::EmptySubscribe);
    }
    Ok(Subscribe { packet_id, filters })
}

/// SUBACK (spec §3.9) : Packet Identifier puis un code par filtre.
pub(super) fn decode_suback(body: &[u8]) -> Result<SubAck<'_>, MqttError> {
    let mut r = Reader::new(body);
    let packet_id = r.u16("packet identifier")?;
    let return_codes = r.rest();
    if let Some(&bad) = return_codes
        .iter()
        .find(|&&code| !matches!(code, 0x00 | 0x01 | 0x02 | 0x80))
    {
        return Err(MqttError::InvalidSubAckCode(bad));
    }
    Ok(SubAck {
        packet_id,
        return_codes,
    })
}

/// UNSUBSCRIBE (spec §3.10) : Packet Identifier puis une liste de filtres.
/// Même structure que SUBSCRIBE, mais sans octet de QoS après chaque filtre.
pub(super) fn decode_unsubscribe(body: &[u8]) -> Result<Unsubscribe<'_>, MqttError> {
    let mut r = Reader::new(body);
    let packet_id = r.u16("packet identifier")?;
    if packet_id == 0 {
        return Err(MqttError::ZeroPacketId);
    }

    let mut filters = Vec::new();
    while r.remaining() > 0 {
        filters.push(r.string("topic filter")?);
    }

    if filters.is_empty() {
        return Err(MqttError::EmptyUnsubscribe);
    }
    Ok(Unsubscribe { packet_id, filters })
}

/// UNSUBACK (spec §3.11).
pub(super) fn decode_unsuback(body: &[u8]) -> Result<UnsubAck, MqttError> {
    let packet_id = decode_packet_id_only(PacketType::UnsubAck, body)?;
    Ok(UnsubAck { packet_id })
}

// ===========================================================================
// Tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::mqtt::test_util::complete;
    use crate::mqtt::{decode, Packet};

    #[test]
    fn subscribe_labo_diese() {
        let buf = [
            0x82, 0x0b, 0x00, 0x01, 0x00, 0x06, b'l', b'a', b'b', b'o', b'/', b'#', 0x00,
        ];
        let (packet, _) = complete(&buf);
        let Packet::Subscribe(s) = packet else {
            panic!("SUBSCRIBE attendu")
        };
        assert_eq!(s.packet_id, 1);
        assert_eq!(s.filters, vec![("labo/#", QoS::AtMostOnce)]);
    }

    #[test]
    fn suback_qos0() {
        let (packet, _) = complete(&[0x90, 0x03, 0x00, 0x01, 0x00]);
        let Packet::SubAck(s) = packet else {
            panic!("SUBACK attendu")
        };
        assert_eq!(s.packet_id, 1);
        assert_eq!(s.return_codes, &[0x00]);
    }

    #[test]
    fn subscribe_avec_mauvais_flags() {
        // 0x80 au lieu de 0x82 : les bits réservés doivent valoir 0010.
        let buf = [0x80, 0x05, 0x00, 0x01, 0x00, 0x01, b'a'];
        assert_eq!(
            decode(&buf),
            Err(MqttError::InvalidFlags {
                packet_type: PacketType::Subscribe,
                flags: 0
            })
        );
    }

    #[test]
    fn unsubscribe_deux_filtres() {
        let buf = [
            0xa2, 0x0d, 0x00, 0x02, // UNSUBSCRIBE, RL = 13, id = 2
            0x00, 0x03, b'a', b'/', b'b', // "a/b"
            0x00, 0x04, b'c', b'/', b'#', b'+', // "c/#+" (filtre quelconque)
        ];
        let (packet, _) = complete(&buf);
        let Packet::Unsubscribe(u) = packet else {
            panic!("UNSUBSCRIBE attendu")
        };
        assert_eq!(u.packet_id, 2);
        assert_eq!(u.filters, vec!["a/b", "c/#+"]);
        assert_eq!(
            complete(&[0xb0, 0x02, 0x00, 0x02]).0,
            Packet::UnsubAck(UnsubAck { packet_id: 2 })
        );
    }

    #[test]
    fn unsubscribe_sans_filtre_est_rejete() {
        assert_eq!(
            decode(&[0xa2, 0x02, 0x00, 0x02]),
            Err(MqttError::EmptyUnsubscribe)
        );
    }
}
