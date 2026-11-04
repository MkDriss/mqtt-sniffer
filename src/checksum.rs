//! Vérification des checksums IPv4 et TCP.
//!
//! Algorithme : somme en complément à un des mots de 16 bits (RFC 1071).
//! Pour VÉRIFIER, on additionne tous les mots, checksum compris : le résultat
//! doit valoir 0xFFFF. Le checksum TCP couvre en plus un *pseudo-en-tête*
//! (adresses, protocole, longueur), non transmis : RFC 9293 pour IPv4,
//! RFC 8200 §8.1 pour IPv6.
//!
//! Le module ne fait que constater : la décision d'ignorer un segment invalide
//! appartient à l'appelant (voir `analyzer::ChecksumPolicy`).

use std::net::{Ipv4Addr, Ipv6Addr};

/// Numéro de protocole de TCP, placé dans le pseudo-en-tête.
const TCP_PROTOCOL: u8 = 6;

/// Ajoute à `acc` les mots de 16 bits big-endian de `data`. Un octet final
/// isolé est complété par un octet nul (RFC 1071).
fn add_words(acc: &mut u64, data: &[u8]) {
    // `as_chunks::<2>` découpe en paires d'octets, plus un reste éventuel.
    let (words, rest) = data.as_chunks::<2>();
    for word in words {
        *acc += u64::from(u16::from_be_bytes(*word));
    }
    if let [last] = rest {
        *acc += u64::from(u16::from_be_bytes([*last, 0]));
    }
}

/// Replie les retenues sur 16 bits (*end-around carry*).
fn fold(mut acc: u64) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

/// Un en-tête IPv4 (checksum compris) est intact si la somme de ses mots
/// vaut 0xFFFF.
pub fn ipv4_header_is_valid(header: &[u8]) -> bool {
    let mut acc = 0;
    add_words(&mut acc, header);
    fold(acc) == 0xffff
}

/// Vérifie le checksum d'un segment TCP (en-tête + données) transporté par IPv4.
pub fn tcp_ipv4_is_valid(src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> bool {
    // La longueur TCP du pseudo-en-tête IPv4 tient sur 16 bits.
    let Ok(length) = u16::try_from(segment.len()) else {
        return false;
    };
    let mut acc = 0;
    // Pseudo-en-tête IPv4 : source, destination, zéro, protocole, longueur.
    add_words(&mut acc, &src.octets());
    add_words(&mut acc, &dst.octets());
    add_words(&mut acc, &[0, TCP_PROTOCOL]);
    add_words(&mut acc, &length.to_be_bytes());
    add_words(&mut acc, segment);
    fold(acc) == 0xffff
}

/// Vérifie le checksum d'un segment TCP (en-tête + données) transporté par IPv6.
pub fn tcp_ipv6_is_valid(src: Ipv6Addr, dst: Ipv6Addr, segment: &[u8]) -> bool {
    // La longueur du pseudo-en-tête IPv6 tient sur 32 bits.
    let Ok(length) = u32::try_from(segment.len()) else {
        return false;
    };
    let mut acc = 0;
    // Pseudo-en-tête IPv6 : source, destination, longueur sur 32 bits,
    // trois octets nuls, puis le protocole (Next Header).
    add_words(&mut acc, &src.octets());
    add_words(&mut acc, &dst.octets());
    add_words(&mut acc, &length.to_be_bytes());
    add_words(&mut acc, &[0, 0, 0, TCP_PROTOCOL]);
    add_words(&mut acc, segment);
    fold(acc) == 0xffff
}

// ===========================================================================
// Tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};

    /// En-tête IPv4 du paquet #1 de la capture loopback : son checksum vaut
    /// 0xd18a, la valeur calculée à la main dans le glossaire (RFC 1071).
    const IPV4_HEADER: [u8; 20] = [
        0x45, 0x00, 0x00, 0x3c, 0x6b, 0x2f, 0x40, 0x00, 0x40, 0x06, 0xd1, 0x8a, 0x7f, 0x00, 0x00,
        0x01, 0x7f, 0x00, 0x00, 0x01,
    ];

    #[test]
    fn l_en_tete_ip_capture_est_valide() {
        assert!(ipv4_header_is_valid(&IPV4_HEADER));
    }

    #[test]
    fn un_bit_modifie_rend_l_en_tete_invalide() {
        let mut header = IPV4_HEADER;
        header[8] ^= 0x01; // TTL 64 → 65
        assert!(!ipv4_header_is_valid(&header));
    }

    /// Construit une trame TCP sur IPv4 valide (checksums calculés par etherparse).
    fn trame_ipv4(payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4([192, 168, 1, 20], [192, 168, 1, 10], 64)
            .tcp(40000, 1883, 123_456, 65_535)
            .psh()
            .ack(42);
        let mut frame = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut frame, payload).unwrap();
        frame
    }

    /// Notre verdict sur le checksum TCP d'une trame IPv4, et celui d'etherparse.
    fn deux_verdicts(frame: &[u8]) -> (bool, bool) {
        let sliced = SlicedPacket::from_ethernet(frame).unwrap();
        let (Some(NetSlice::Ipv4(ip)), Some(TransportSlice::Tcp(tcp))) =
            (&sliced.net, &sliced.transport)
        else {
            panic!("trame TCP/IPv4 attendue")
        };
        let (src, dst) = (ip.header().source_addr(), ip.header().destination_addr());
        let nous = tcp_ipv4_is_valid(src, dst, tcp.slice());
        let attendu = tcp.calc_checksum_ipv4(src.octets(), dst.octets()).unwrap();
        (nous, attendu == tcp.checksum())
    }

    #[test]
    fn test_differentiel_avec_etherparse() {
        // Longueurs paires et impaires, segments intacts et altérés : notre
        // verdict doit toujours être celui d'etherparse, référence indépendante.
        for len in 0..=40 {
            let payload: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let frame = trame_ipv4(&payload);
            assert_eq!(deux_verdicts(&frame), (true, true), "intact, {len} octets");

            let mut alteree = frame.clone();
            let dernier = alteree.len() - 1;
            alteree[dernier] ^= 0x40; // un bit du dernier octet (en-tête si pas de données)
            assert_eq!(
                deux_verdicts(&alteree),
                (false, false),
                "altéré, {len} octets"
            );
        }
    }

    #[test]
    fn segment_tcp_sur_ipv6() {
        let builder = PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv6(
                [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                64,
            )
            .tcp(40000, 1883, 1, 65_535)
            .ack(1);
        let mut frame = Vec::new();
        builder.write(&mut frame, b"abc").unwrap();
        let sliced = SlicedPacket::from_ethernet(&frame).unwrap();
        let (Some(NetSlice::Ipv6(ip)), Some(TransportSlice::Tcp(tcp))) =
            (&sliced.net, &sliced.transport)
        else {
            panic!("trame TCP/IPv6 attendue")
        };
        let (src, dst) = (ip.header().source_addr(), ip.header().destination_addr());
        assert!(tcp_ipv6_is_valid(src, dst, tcp.slice()));
        // Une autre adresse destination invalide le checksum : le pseudo-en-tête
        // lie le segment aux adresses IP.
        assert!(!tcp_ipv6_is_valid(src, Ipv6Addr::LOCALHOST, tcp.slice()));
    }
}
