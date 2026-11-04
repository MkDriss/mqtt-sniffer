//! Le curseur [`Reader`] : lit les champs d'un corps de paquet les uns après
//! les autres, en vérifiant à chaque lecture qu'on ne dépasse pas la fin.
//!
//! Toutes les lectures passent par [`Reader::bytes`] : il n'existe qu'un seul
//! point de vérification des limites, impossible à oublier.

use super::{MqttError, PacketType};

/// Lit des champs les uns après les autres dans une slice, en vérifiant à
/// chaque fois qu'on ne dépasse pas la fin. `'a` est la durée de vie des
/// octets lus : les slices renvoyées pointent dans le buffer d'origine.
pub(super) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(super) fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Nombre d'octets pas encore lus.
    pub(super) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Lit exactement `n` octets.
    pub(super) fn bytes(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], MqttError> {
        if n > self.remaining() {
            return Err(MqttError::BoundaryCrossed { field });
        }
        let buf = self.buf; // copie de la référence (pas des octets)
        let slice = &buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    pub(super) fn u8(&mut self, field: &'static str) -> Result<u8, MqttError> {
        Ok(self.bytes(1, field)?[0])
    }

    /// Entier 16 bits big-endian (octet de poids fort en premier) [spec §1.5.2].
    pub(super) fn u16(&mut self, field: &'static str) -> Result<u16, MqttError> {
        let b = self.bytes(2, field)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Données binaires préfixées par leur longueur sur 2 octets [spec §1.5.3].
    pub(super) fn binary(&mut self, field: &'static str) -> Result<&'a [u8], MqttError> {
        let len = usize::from(self.u16(field)?);
        self.bytes(len, field)
    }

    /// Chaîne UTF-8 préfixée par sa longueur sur 2 octets [spec §1.5.3].
    pub(super) fn string(&mut self, field: &'static str) -> Result<&'a str, MqttError> {
        let raw = self.binary(field)?;
        // `from_utf8` vérifie l'encodage SANS copier : la `&str` renvoyée
        // pointe sur les mêmes octets que `raw`.
        let text = std::str::from_utf8(raw).map_err(|_| MqttError::InvalidUtf8 { field })?;
        if text.contains('\0') {
            return Err(MqttError::NullCharacter { field });
        }
        Ok(text)
    }

    /// Tout ce qui reste (utilisé pour le payload d'un PUBLISH).
    pub(super) fn rest(&mut self) -> &'a [u8] {
        let buf = self.buf;
        let slice = &buf[self.pos..];
        self.pos = buf.len();
        slice
    }

    /// Vérifie qu'il ne reste aucun octet non lu.
    pub(super) fn expect_end(&self, packet_type: PacketType) -> Result<(), MqttError> {
        match self.remaining() {
            0 => Ok(()),
            count => Err(MqttError::TrailingBytes { packet_type, count }),
        }
    }
}
