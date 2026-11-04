//! Point d'entrée du décodeur : [`decode()`] lit l'en-tête fixe (type, flags,
//! Remaining Length), découpe exactement un paquet (framing), puis confie son
//! corps au décodeur spécialisé de chaque type.
//!
//! Contient aussi les deux aides communes à plusieurs décodeurs :
//! [`expect_len`] et [`decode_packet_id_only`].

use super::{connect, publish, subscribe};
use super::{Decoded, MqttError, Packet, PacketType};

// ===========================================================================
// Point d'entrée
// ===========================================================================

/// Décode le paquet MQTT qui commence au début de `buf`.
///
/// - `Ok(Decoded::Complete { packet, consumed })` : un paquet complet ;
/// - `Ok(Decoded::Incomplete { needed })` : début de paquet, données manquantes ;
/// - `Err(..)` : les octets violent la spécification.
pub fn decode(buf: &[u8]) -> Result<Decoded<'_>, MqttError> {
    // `let ... else` : si le motif ne correspond pas, on exécute le bloc `else`,
    // qui doit obligatoirement quitter la fonction (ici avec `return`).
    let Some(&byte1) = buf.first() else {
        // Un paquet fait au minimum 2 octets (type + Remaining Length).
        return Ok(Decoded::Incomplete { needed: 2 });
    };

    // --- En-tête fixe, octet 1 : type (bits 7-4) et flags (bits 3-0) ---
    let type_nibble = byte1 >> 4;
    let packet_type =
        PacketType::from_nibble(type_nibble).ok_or(MqttError::InvalidPacketType(type_nibble))?;
    let flags = byte1 & 0x0F;
    if let Some(required) = packet_type.required_flags() {
        if flags != required {
            return Err(MqttError::InvalidFlags { packet_type, flags });
        }
    }

    // --- En-tête fixe, octets 2 à 5 : Remaining Length ---
    let Some((remaining_len, len_len)) = decode_remaining_length(&buf[1..])? else {
        return Ok(Decoded::Incomplete { needed: 1 });
    };

    // --- Framing : a-t-on reçu tout le paquet ? ---
    let header_len = 1 + len_len;
    let total_len = header_len + remaining_len;
    if buf.len() < total_len {
        return Ok(Decoded::Incomplete {
            needed: total_len - buf.len(),
        });
    }
    let body = &buf[header_len..total_len];

    // --- Décodage spécifique à chaque type ---
    let packet = match packet_type {
        PacketType::Connect => Packet::Connect(connect::decode_connect(body)?),
        PacketType::ConnAck => Packet::ConnAck(connect::decode_connack(body)?),
        PacketType::Publish => Packet::Publish(publish::decode_publish(flags, body)?),
        PacketType::PubAck => Packet::PubAck(publish::decode_puback(body)?),
        PacketType::PubRec => Packet::PubRec(publish::decode_pubrec(body)?),
        PacketType::PubRel => Packet::PubRel(publish::decode_pubrel(body)?),
        PacketType::PubComp => Packet::PubComp(publish::decode_pubcomp(body)?),
        PacketType::Subscribe => Packet::Subscribe(subscribe::decode_subscribe(body)?),
        PacketType::SubAck => Packet::SubAck(subscribe::decode_suback(body)?),
        PacketType::Unsubscribe => Packet::Unsubscribe(subscribe::decode_unsubscribe(body)?),
        PacketType::UnsubAck => Packet::UnsubAck(subscribe::decode_unsuback(body)?),
        PacketType::PingReq => {
            expect_len(packet_type, body, 0)?;
            Packet::PingReq
        }
        PacketType::PingResp => {
            expect_len(packet_type, body, 0)?;
            Packet::PingResp
        }
        PacketType::Disconnect => {
            expect_len(packet_type, body, 0)?;
            Packet::Disconnect
        }
    };

    Ok(Decoded::Complete {
        packet,
        consumed: total_len,
    })
}

/// Décode la Remaining Length (spec §2.2.3) à partir de l'octet 2 du paquet.
///
/// Renvoie `Ok(Some((valeur, nombre_d_octets_utilisés)))`, ou `Ok(None)` si les
/// octets de la longueur ne sont pas encore tous arrivés.
///
/// Chaque octet porte 7 bits de valeur ; le bit de poids fort (0x80) signifie
/// « un autre octet suit ». Au plus 4 octets sont autorisés.
fn decode_remaining_length(bytes: &[u8]) -> Result<Option<(usize, usize)>, MqttError> {
    let mut value: usize = 0;
    let mut multiplier: usize = 1;
    for (index, &encoded) in bytes.iter().enumerate().take(4) {
        value += usize::from(encoded & 0x7F) * multiplier;
        if encoded & 0x80 == 0 {
            return Ok(Some((value, index + 1)));
        }
        multiplier *= 128;
    }
    if bytes.len() >= 4 {
        // 4 octets lus et le 4e annonçait encore une suite : interdit.
        Err(MqttError::MalformedRemainingLength)
    } else {
        Ok(None)
    }
}

// ===========================================================================
// Aides communes aux décodeurs
// ===========================================================================

/// Vérifie qu'un corps de paquet a exactement la longueur imposée.
pub(super) fn expect_len(
    packet_type: PacketType,
    body: &[u8],
    expected: usize,
) -> Result<(), MqttError> {
    if body.len() == expected {
        Ok(())
    } else {
        Err(MqttError::UnexpectedLength {
            packet_type,
            expected,
            actual: body.len(),
        })
    }
}

/// Corps commun à PUBACK, PUBREC, PUBREL, PUBCOMP et UNSUBACK : exactement
/// 2 octets contenant un Packet Identifier (spec §3.4 à §3.7 et §3.11).
///
/// Un acquittement reprend l'identifiant du paquet qu'il acquitte, et cet
/// identifiant ne peut jamais valoir 0 [MQTT-2.3.1-1]. Un acquittement
/// portant l'identifiant 0 ne peut donc rien acquitter : c'est une anomalie.
pub(super) fn decode_packet_id_only(
    packet_type: PacketType,
    body: &[u8],
) -> Result<u16, MqttError> {
    expect_len(packet_type, body, 2)?;
    let packet_id = u16::from_be_bytes([body[0], body[1]]);
    if packet_id == 0 {
        return Err(MqttError::ZeroPacketId);
    }
    Ok(packet_id)
}

// ===========================================================================
// Tests : en-tête fixe, Remaining Length et framing
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::mqtt::test_util::complete;

    #[test]
    fn ping_et_disconnect() {
        assert_eq!(complete(&[0xc0, 0x00]).0, Packet::PingReq);
        assert_eq!(complete(&[0xd0, 0x00]).0, Packet::PingResp);
        assert_eq!(complete(&[0xe0, 0x00]).0, Packet::Disconnect);
    }

    #[test]
    fn deux_paquets_dans_un_meme_buffer() {
        // PINGREQ puis DISCONNECT collés : le premier décodage consomme 2 octets.
        let buf = [0xc0, 0x00, 0xe0, 0x00];
        let (first, consumed) = complete(&buf);
        assert_eq!((first, consumed), (Packet::PingReq, 2));
        assert_eq!(complete(&buf[consumed..]).0, Packet::Disconnect);
    }

    #[test]
    fn paquet_coupe_est_incomplet() {
        // PUBLISH de 17 octets dont seuls les 10 premiers sont arrivés.
        let buf = [0x30, 0x0f, 0x00, 0x09, b'l', b'a', b'b', b'o', b'/', b't'];
        assert_eq!(decode(&buf), Ok(Decoded::Incomplete { needed: 7 }));
        assert_eq!(decode(&[]), Ok(Decoded::Incomplete { needed: 2 }));
        assert_eq!(decode(&[0x30]), Ok(Decoded::Incomplete { needed: 1 }));
    }

    #[test]
    fn remaining_length_sur_deux_octets() {
        // Exemple de la spec §2.2.3 : 321 = 65 + 2*128, codé 0xC1 0x02.
        assert_eq!(decode_remaining_length(&[0xc1, 0x02]), Ok(Some((321, 2))));
        assert_eq!(decode_remaining_length(&[0x40]), Ok(Some((64, 1))));
        assert_eq!(
            decode_remaining_length(&[0xff, 0xff, 0xff, 0x7f]),
            Ok(Some((268_435_455, 4)))
        );
    }

    #[test]
    fn remaining_length_sur_cinq_octets_est_malformee() {
        let buf = [0x30, 0xff, 0xff, 0xff, 0xff, 0x7f];
        assert_eq!(decode(&buf), Err(MqttError::MalformedRemainingLength));
    }

    #[test]
    fn type_reserve_est_rejete() {
        assert_eq!(decode(&[0xf0, 0x00]), Err(MqttError::InvalidPacketType(15)));
    }

    #[test]
    fn acquittement_d_identifiant_nul_est_une_anomalie() {
        assert_eq!(
            decode(&[0x40, 0x02, 0x00, 0x00]),
            Err(MqttError::ZeroPacketId)
        );
        assert_eq!(
            decode(&[0xb0, 0x02, 0x00, 0x00]),
            Err(MqttError::ZeroPacketId)
        );
    }

    #[test]
    fn ping_et_disconnect_avec_un_corps_sont_rejetes() {
        // Ces trois paquets n'ont jamais de corps : Remaining Length = 0.
        for (octet, packet_type) in [
            (0xc0, PacketType::PingReq),
            (0xd0, PacketType::PingResp),
            (0xe0, PacketType::Disconnect),
        ] {
            assert_eq!(
                decode(&[octet, 0x01, 0x00]),
                Err(MqttError::UnexpectedLength {
                    packet_type,
                    expected: 0,
                    actual: 1
                })
            );
        }
    }
}