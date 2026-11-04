//! PUBLISH (spec §3.3) et ses acquittements : PUBACK pour la QoS 1 (§3.4),
//! PUBREC, PUBREL et PUBCOMP pour l'échange en quatre temps de la QoS 2
//! (§3.5 à §3.7).

use super::decode::decode_packet_id_only;
use super::reader::Reader;
use super::{MqttError, PacketType, QoS};

/// Contenu décodé d'un PUBLISH (spec §3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish<'a> {
    pub dup: bool,
    pub qos: QoS,
    pub retain: bool,
    pub topic: &'a str,
    /// Présent seulement si QoS > 0 [MQTT-2.3.1-5].
    pub packet_id: Option<u16>,
    pub payload: &'a [u8],
}

/// Contenu décodé d'un PUBACK (spec §3.4) : acquittement d'un PUBLISH de QoS 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PubAck {
    pub packet_id: u16,
}

/// Contenu décodé d'un PUBREC (spec §3.5) : 1re réponse à un PUBLISH de QoS 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PubRec {
    pub packet_id: u16,
}

/// Contenu décodé d'un PUBREL (spec §3.6) : réponse à un PUBREC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PubRel {
    pub packet_id: u16,
}

/// Contenu décodé d'un PUBCOMP (spec §3.7) : réponse finale à un PUBREL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PubComp {
    pub packet_id: u16,
}

// ===========================================================================
// Décodage
// ===========================================================================

/// PUBLISH (spec §3.3). Les flags de l'en-tête fixe portent DUP, QoS, RETAIN.
pub(super) fn decode_publish(flags: u8, body: &[u8]) -> Result<Publish<'_>, MqttError> {
    let dup = flags & 0b1000 != 0;
    let qos_bits = (flags >> 1) & 0b11;
    let retain = flags & 0b0001 != 0;

    let qos = QoS::from_u8(qos_bits).ok_or(MqttError::InvalidQos(qos_bits))?;
    if qos == QoS::AtMostOnce && dup {
        return Err(MqttError::DupWithQos0);
    }

    let mut r = Reader::new(body);
    let topic = r.string("topic name")?;
    if topic.contains(['+', '#']) {
        return Err(MqttError::WildcardInTopicName);
    }

    let packet_id = if qos == QoS::AtMostOnce {
        None
    } else {
        let id = r.u16("packet identifier")?;
        if id == 0 {
            return Err(MqttError::ZeroPacketId);
        }
        Some(id)
    };

    Ok(Publish {
        dup,
        qos,
        retain,
        topic,
        packet_id,
        payload: r.rest(),
    })
}

/// PUBACK (spec §3.4).
pub(super) fn decode_puback(body: &[u8]) -> Result<PubAck, MqttError> {
    let packet_id = decode_packet_id_only(PacketType::PubAck, body)?;
    Ok(PubAck { packet_id })
}

/// PUBREC (spec §3.5).
pub(super) fn decode_pubrec(body: &[u8]) -> Result<PubRec, MqttError> {
    let packet_id = decode_packet_id_only(PacketType::PubRec, body)?;
    Ok(PubRec { packet_id })
}

/// PUBREL (spec §3.6). Ses flags imposés (0010) sont déjà vérifiés par `decode`.
pub(super) fn decode_pubrel(body: &[u8]) -> Result<PubRel, MqttError> {
    let packet_id = decode_packet_id_only(PacketType::PubRel, body)?;
    Ok(PubRel { packet_id })
}

/// PUBCOMP (spec §3.7).
pub(super) fn decode_pubcomp(body: &[u8]) -> Result<PubComp, MqttError> {
    let packet_id = decode_packet_id_only(PacketType::PubComp, body)?;
    Ok(PubComp { packet_id })
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
    fn publish_temperature() {
        let buf = [
            0x30, 0x0f, 0x00, 0x09, b'l', b'a', b'b', b'o', b'/', b't', b'e', b'm', b'p', b'2',
            b'1', b'.', b'5',
        ];
        let (packet, consumed) = complete(&buf);
        assert_eq!(consumed, 17);
        let Packet::Publish(p) = packet else {
            panic!("PUBLISH attendu")
        };
        assert_eq!(p.topic, "labo/temp");
        assert_eq!(p.qos, QoS::AtMostOnce);
        assert_eq!(p.packet_id, None);
        assert_eq!(p.payload, b"21.5");
    }

    #[test]
    fn longueur_de_topic_mensongere() {
        // Le topic annonce 200 octets alors que le paquet n'en contient que 2.
        let buf = [0x30, 0x04, 0x00, 0xc8, b'a', b'b'];
        assert_eq!(
            decode(&buf),
            Err(MqttError::BoundaryCrossed {
                field: "topic name"
            })
        );
    }

    #[test]
    fn publish_qos3_est_interdit() {
        let buf = [0x36, 0x03, 0x00, 0x01, b'a'];
        assert_eq!(decode(&buf), Err(MqttError::InvalidQos(3)));
    }

    #[test]
    fn puback_accepte() {
        let (packet, _) = complete(&[0x40, 0x02, 0x00, 0x01]);
        assert_eq!(packet, Packet::PubAck(PubAck { packet_id: 1 }));
    }

    #[test]
    fn puback_de_mauvaise_longueur_est_rejete() {
        // La Remaining Length (3) annonce un corps trop long pour un PUBACK.
        let packet = [0x40, 0x03, 0x00, 0x01, 0x01];
        assert_eq!(
            decode(&packet),
            Err(MqttError::UnexpectedLength {
                packet_type: PacketType::PubAck,
                expected: 2,
                actual: 3
            })
        );
    }

    #[test]
    fn puback_suivi_d_un_octet_ne_deborde_pas() {
        // Le 'a' qui suit appartient au paquet suivant : on n'en consomme que 4.
        let (packet, consumed) = complete(&[0x40, 0x02, 0x00, 0x01, b'a']);
        assert_eq!(packet, Packet::PubAck(PubAck { packet_id: 1 }));
        assert_eq!(consumed, 4);
    }

    #[test]
    fn echange_qos2_complet() {
        assert_eq!(
            complete(&[0x50, 0x02, 0x00, 0x07]).0,
            Packet::PubRec(PubRec { packet_id: 7 })
        );
        assert_eq!(
            complete(&[0x62, 0x02, 0x00, 0x07]).0,
            Packet::PubRel(PubRel { packet_id: 7 })
        );
        assert_eq!(
            complete(&[0x70, 0x02, 0x00, 0x07]).0,
            Packet::PubComp(PubComp { packet_id: 7 })
        );
    }

    #[test]
    fn pubrel_avec_flags_0000_est_rejete() {
        // PUBREL impose les flags 0010 : 0x60 au lieu de 0x62 est invalide.
        assert_eq!(
            decode(&[0x60, 0x02, 0x00, 0x07]),
            Err(MqttError::InvalidFlags {
                packet_type: PacketType::PubRel,
                flags: 0
            })
        );
    }

    #[test]
    fn publish_dup_en_qos0_est_interdit() {
        // PUBLISH avec DUP = 1 et QoS 0 : combinaison interdite [MQTT-3.3.1-2].
        let buf = [0x38, 0x03, 0x00, 0x01, b'a'];
        assert_eq!(decode(&buf), Err(MqttError::DupWithQos0));
    }

    #[test]
    fn publish_dup_en_qos1_est_accepte() {
        // Contre-test : DUP = 1 est légitime en QoS 1 (retransmission).
        // 0x3A = PUBLISH, DUP = 1, QoS 1 ; topic "a", identifiant 7.
        let (packet, _) = complete(&[0x3a, 0x05, 0x00, 0x01, b'a', 0x00, 0x07]);
        let Packet::Publish(p) = packet else {
            panic!("PUBLISH attendu")
        };
        assert!(p.dup);
        assert_eq!(p.qos, QoS::AtLeastOnce);
        assert_eq!(p.packet_id, Some(7));
    }

    #[test]
    fn jokers_interdits_dans_le_topic_d_un_publish() {
        // Les jokers ne sont permis que dans les filtres d'abonnement.
        assert_eq!(
            decode(&[0x30, 0x05, 0x00, 0x03, b'a', b'/', b'#']),
            Err(MqttError::WildcardInTopicName)
        );
        assert_eq!(
            decode(&[0x30, 0x05, 0x00, 0x03, b'a', b'/', b'+']),
            Err(MqttError::WildcardInTopicName)
        );
    }

    #[test]
    fn identifiant_nul_en_qos1_est_rejete() {
        // 0x32 = PUBLISH QoS 1 ; topic "a", identifiant 0.
        assert_eq!(
            decode(&[0x32, 0x05, 0x00, 0x01, b'a', 0x00, 0x00]),
            Err(MqttError::ZeroPacketId)
        );
    }

    #[test]
    fn topic_utf8_invalide_est_rejete() {
        assert_eq!(
            decode(&[0x30, 0x03, 0x00, 0x01, 0xff]),
            Err(MqttError::InvalidUtf8 {
                field: "topic name"
            })
        );
    }
}