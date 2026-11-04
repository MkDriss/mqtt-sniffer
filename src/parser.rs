//! Module `parser` : découpe une trame Ethernet en couches (Ethernet -> IP -> TCP).
//!
//! Ce module ne dépend PAS de libpcap : il reçoit des octets (`&[u8]`) et
//! renvoie des informations structurées. On peut donc le tester sans réseau
//! ni privilèges (voir les tests en bas de fichier)

use std::fmt;
use std::net::IpAddr;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};

/// Les flags TCP qui nous intéressent, décodés en booléens.
///
/// `#[derive(...)]` demande au compilateur d'écrire automatiquement
/// certaines fonctionnalités : affichage de debug, copie, comparaison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
}

/// Affichage lisible des flags, par exemple `SYN,ACK`.
/// Implémenter le trait `Display` permet d'écrire `println!("{}", flags)`.
impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Tableau de couples (le flag est-il levé ?, son nom).
        let all = [
            (self.syn, "SYN"),
            (self.fin, "FIN"),
            (self.rst, "RST"),
            (self.psh, "PSH"),
            (self.ack, "ACK"),
        ];
        // On garde les noms des flags levés, puis on les joint par des virgules.
        let names: Vec<&str> = all
            .iter()
            .filter(|(is_set, _)| *is_set)
            .map(|(_, name)| *name)
            .collect();
        write!(f, "{}", names.join(","))
    }
}

/// Un segment TCP décodé.
///
/// Le paramètre de durée de vie `'a` signifie : « `payload` emprunte des
/// octets qui vivent au moins aussi longtemps que `'a` ». Concrètement,
/// `payload` pointe DANS la trame capturée : aucune copie (zéro-copie).
/// Le compilateur interdit d'utiliser ce `TcpSegment` après la disparition
/// de la trame d'origine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub payload: &'a [u8],
}

/// Résultat du parsing d'une trame valide.
///
/// Une `enum` Rust est un type « l'un OU l'autre » : une valeur `Parsed`
/// est soit `Tcp` (et contient alors un `TcpSegment`), soit `Other`.
#[derive(Debug)]
pub enum Parsed<'a> {
    /// Segment TCP sur IPv4 ou IPv6.
    Tcp(TcpSegment<'a>),
    /// Trame correcte mais qui ne nous intéresse pas (ARP, UDP, ICMP...).
    Other,
}

/// Erreurs possibles pendant le parsing.
#[derive(Debug)]
pub enum ParseError {
    /// Trame tronquée ou incohérente (longueurs impossibles, etc.).
    /// On conserve l'erreur détaillée d'etherparse à l'intérieur.
    Malformed(etherparse::err::packet::SliceError),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Malformed(e) => write!(f, "trame malformée : {e:?}"),
        }
    }
}

/// Permet d'utiliser `ParseError` partout où Rust attend « une erreur ».
impl std::error::Error for ParseError {}

/// Découpe une trame qui commence par un en-tête Ethernet II.
///
/// - `Ok(Parsed::Tcp(..))` : c'est du TCP, voici les champs utiles ;
/// - `Ok(Parsed::Other)`   : trame valide, mais pas du TCP sur IP ;
/// - `Err(..)`             : trame malformée.
pub fn parse_ethernet(frame: &[u8]) -> Result<Parsed<'_>, ParseError> {
    // 1. etherparse découpe la trame couche par couche, sans rien copier.
    //    `map_err` convertit son erreur en NOTRE type d'erreur, puis `?`
    //    la renvoie immédiatement à l'appelant si c'est un `Err`.
    let sliced = SlicedPacket::from_ethernet(frame).map_err(ParseError::Malformed)?;

    // 2. Couche réseau : on extrait les adresses IP source et destination.
    //    `match` doit couvrir TOUS les cas possibles ; `_` signifie
    //    « n'importe quel autre cas » (ARP, absence de couche réseau...).
    let (src_ip, dst_ip) = match &sliced.net {
        Some(NetSlice::Ipv4(ipv4)) => (
            IpAddr::V4(ipv4.header().source_addr()),
            IpAddr::V4(ipv4.header().destination_addr()),
        ),
        Some(NetSlice::Ipv6(ipv6)) => (
            IpAddr::V6(ipv6.header().source_addr()),
            IpAddr::V6(ipv6.header().destination_addr()),
        ),
        _ => return Ok(Parsed::Other),
    };

    // 3. Couche transport : on ne garde que TCP.
    let tcp = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => tcp,
        _ => return Ok(Parsed::Other),
    };

    // 4. On assemble notre structure. `tcp.payload()` renvoie une sous-slice
    //    de `frame` : c'est elle qui donne sa durée de vie au résultat.
    Ok(Parsed::Tcp(TcpSegment {
        src_ip,
        dst_ip,
        src_port: tcp.source_port(),
        dst_port: tcp.destination_port(),
        seq: tcp.sequence_number(),
        ack: tcp.acknowledgment_number(),
        flags: TcpFlags {
            syn: tcp.syn(),
            ack: tcp.ack(),
            fin: tcp.fin(),
            rst: tcp.rst(),
            psh: tcp.psh(),
        },
        payload: tcp.payload(),
    }))
}

// ---------------------------------------------------------------------------
// Tests unitaires : lancés avec `cargo test`, sans réseau ni privilèges.
// Les trames ci-dessous sont des copies EXACTES de la capture réalisées auparavant
// (paquets #1 et #18). `#[cfg(test)]` : ce code n'est compilé que pour les tests.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Paquet #1 : SYN de mosquitto_sub (port 57734) vers le broker (1883).
    // Mise en forme manuelle : 16 octets par ligne, comme un hexdump.
    #[rustfmt::skip]
    const FRAME_SYN: [u8; 74] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x3c, 0x6b, 0x2f, 0x40, 0x00, 0x40, 0x06, 0xd1, 0x8a, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00,
        0x00, 0x01, 0xe1, 0x86, 0x07, 0x5b, 0xde, 0x23, 0x0c, 0xca, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
        0xff, 0xd7, 0xfe, 0x30, 0x00, 0x00, 0x02, 0x04, 0xff, 0xd7, 0x04, 0x02, 0x08, 0x0a, 0x9c, 0xe9,
        0xbf, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x0a,
    ];

    /// Paquet #18 : PUBLISH `labo/temp` = `21.5` de mosquitto_pub (port 37600).
    // Mise en forme manuelle : 16 octets par ligne, comme un hexdump.
    #[rustfmt::skip]
    const FRAME_PUBLISH: [u8; 83] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x45, 0x5d, 0x53, 0x40, 0x00, 0x40, 0x06, 0xdf, 0x5d, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00,
        0x00, 0x01, 0x92, 0xe0, 0x07, 0x5b, 0x3f, 0x6b, 0xdd, 0x11, 0x24, 0x88, 0x78, 0x47, 0x80, 0x18,
        0x00, 0x40, 0xfe, 0x39, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0xce, 0xcd, 0x52, 0x33, 0xd1, 0x55,
        0x32, 0xa7, 0x30, 0x0f, 0x00, 0x09, 0x6c, 0x61, 0x62, 0x6f, 0x2f, 0x74, 0x65, 0x6d, 0x70, 0x32,
        0x31, 0x2e, 0x35,
    ];

    /// Petite aide : extrait le TcpSegment ou fait échouer le test.
    fn expect_tcp(frame: &[u8]) -> TcpSegment<'_> {
        match parse_ethernet(frame) {
            Ok(Parsed::Tcp(seg)) => seg,
            other => panic!("attendu un segment TCP, obtenu : {other:?}"),
        }
    }

    #[test]
    fn syn_du_handshake() {
        let seg = expect_tcp(&FRAME_SYN);
        assert_eq!(seg.src_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(seg.src_port, 57734);
        assert_eq!(seg.dst_port, 1883);
        assert_eq!(seg.seq, 0xde23_0cca);
        assert_eq!(
            seg.flags,
            TcpFlags {
                syn: true,
                ..Default::default()
            }
        );
        assert_eq!(seg.flags.to_string(), "SYN");
        assert!(
            seg.payload.is_empty(),
            "un SYN ne transporte pas de données"
        );
    }

    #[test]
    fn publish_mqtt() {
        let seg = expect_tcp(&FRAME_PUBLISH);
        assert_eq!(seg.src_port, 37600);
        assert_eq!(seg.dst_port, 1883);
        assert_eq!(seg.flags.to_string(), "PSH,ACK");
        // 83 octets - 14 (Ethernet) - 20 (IPv4) - 32 (TCP avec options) = 17
        assert_eq!(seg.payload.len(), 17);
        assert_eq!(seg.payload[0], 0x30, "type MQTT 3 = PUBLISH, QoS 0");
        assert_eq!(&seg.payload[4..13], b"labo/temp");
        assert_eq!(&seg.payload[13..], b"21.5");
    }

    #[test]
    fn trame_tronquee_est_une_erreur() {
        // On coupe au milieu de l'en-tête IPv4 (14 + 10 octets seulement).
        assert!(parse_ethernet(&FRAME_SYN[..24]).is_err());
    }

    #[test]
    fn ethertype_inconnu_est_ignore() {
        // En-tête Ethernet avec l'EtherType expérimental 0x88B5, puis 4 octets.
        let frame = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xb5, 1, 2, 3, 4];
        assert!(matches!(parse_ethernet(&frame), Ok(Parsed::Other)));
    }
}
