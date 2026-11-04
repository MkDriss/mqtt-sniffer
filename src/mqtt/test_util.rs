//! Aides partagées par les tests des différents fichiers du module `mqtt`.
//! Compilé uniquement pour `cargo test` (voir `#[cfg(test)]` dans `mqtt.rs`).

use super::{decode, Decoded, Packet};

/// Petite aide : décode un paquet complet ou fait échouer le test.
pub(super) fn complete(buf: &[u8]) -> (Packet<'_>, usize) {
    match decode(buf) {
        Ok(Decoded::Complete { packet, consumed }) => (packet, consumed),
        other => panic!("paquet complet attendu, obtenu : {other:?}"),
    }
}

/// CONNECT d'un objet avec identifiant, nom d'utilisateur et mot de passe.
pub(super) const CONNECT_AVEC_IDENTIFIANTS: [u8; 37] = [
    0x10, 0x23, // CONNECT, Remaining Length = 35
    0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, // "MQTT", niveau 4
    0xc2, // flags : user + password + clean session
    0x00, 0x3c, // keep alive 60 s
    0x00, 0x0a, b'a', b'c', b't', b'i', b'o', b'n', b'n', b'e', b'u', b'r', // client id
    0x00, 0x05, b'a', b'd', b'm', b'i', b'n', // user name
    0x00, 0x04, b'1', b'2', b'3', b'4', // password
];
