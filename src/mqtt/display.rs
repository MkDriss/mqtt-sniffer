//! Affichage lisible et SÉCURISÉ des paquets décodés.
//!
//! Toutes les chaînes venues du réseau passent par [`show_text`], qui
//! neutralise les caractères qu'un terminal interpréterait (CWE-150).
//! Les mots de passe sont masqués par défaut (sécurité par défaut).

use super::Packet;

/// Affiche une chaîne venant du réseau, entre guillemets, en NEUTRALISANT
/// les caractères dangereux pour un terminal.
///
/// Sécurité (CWE-150) : une chaîne envoyée par un attaquant peut contenir des
/// séquences d'échappement (`ESC [ 2 J` efface l'écran, d'autres déplacent le
/// curseur ou réécrivent des lignes) ou des caractères d'inversion
/// bidirectionnelle (U+202E) qui falsifient l'affichage. `escape_debug`
/// remplace tous ces caractères par une écriture inerte, par ex. `\u{1b}`.
///
/// TOUTE chaîne issue du réseau doit passer par cette fonction avant d'être
/// affichée.
fn show_text(text: &str) -> String {
    format!("\"{}\"", text.escape_debug())
}

/// Affiche des octets : comme texte neutralisé s'ils sont de l'UTF-8 valide,
/// sinon en hexadécimal.
fn show_bytes(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => show_text(text),
        Err(_) => {
            let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
            format!("0x{}", hex.join(""))
        }
    }
}

impl Packet<'_> {
    /// Résumé d'une ligne. Les mots de passe sont masqués sauf si
    /// `show_secrets` vaut `true` : un outil de sécurité ne doit pas exposer
    /// de secrets par défaut, même dans un terminal.
    pub fn describe(&self, show_secrets: bool) -> String {
        match self {
            Packet::Connect(c) => {
                let client_id = if c.client_id.is_empty() {
                    "\"\" (vide : identifiant attribué par le broker)".to_string()
                } else {
                    show_text(c.client_id)
                };
                let user = c.username.map_or("-".to_string(), show_text);
                let pass = match (c.password, show_secrets) {
                    (None, _) => "-".to_string(),
                    (Some(p), true) => show_bytes(p),
                    (Some(p), false) => format!("<masqué, {} octets>", p.len()),
                };
                let will = c
                    .will
                    .as_ref()
                    .map_or("-".to_string(), |w| show_text(w.topic));
                format!(
                    "CONNECT client_id={client_id} clean_session={} keep_alive={}s \
                     user={user} pass={pass} will={will}",
                    u8::from(c.clean_session),
                    c.keep_alive
                )
            }
            Packet::ConnAck(a) => {
                let meaning = match a.return_code {
                    0 => "accepté",
                    1 => "refusé : version de protocole",
                    2 => "refusé : identifiant rejeté",
                    3 => "refusé : serveur indisponible",
                    4 => "refusé : identifiants invalides",
                    5 => "refusé : non autorisé",
                    _ => "code réservé",
                };
                format!(
                    "CONNACK code={} ({meaning}) session_present={}",
                    a.return_code,
                    u8::from(a.session_present)
                )
            }
            Packet::Publish(p) => {
                let id = p.packet_id.map_or("-".to_string(), |id| id.to_string());
                format!(
                    "PUBLISH topic={} qos={} retain={} dup={} id={id} payload={}",
                    show_text(p.topic),
                    p.qos as u8,
                    u8::from(p.retain),
                    u8::from(p.dup),
                    show_bytes(p.payload)
                )
            }
            Packet::Subscribe(s) => {
                let list: Vec<String> = s
                    .filters
                    .iter()
                    .map(|(filter, qos)| format!("{}(qos {})", show_text(filter), *qos as u8))
                    .collect();
                format!("SUBSCRIBE id={} filtres=[{}]", s.packet_id, list.join(", "))
            }
            Packet::SubAck(s) => {
                let codes: Vec<String> =
                    s.return_codes.iter().map(|c| format!("{c:#04x}")).collect();
                format!("SUBACK id={} codes=[{}]", s.packet_id, codes.join(", "))
            }
            Packet::PubAck(ack) => format!("PUBACK id={}", ack.packet_id),
            Packet::PubRec(rec) => format!("PUBREC id={}", rec.packet_id),
            Packet::PubRel(rel) => format!("PUBREL id={}", rel.packet_id),
            Packet::PubComp(comp) => format!("PUBCOMP id={}", comp.packet_id),
            Packet::Unsubscribe(u) => {
                let list: Vec<String> = u.filters.iter().map(|f| show_text(f)).collect();
                format!(
                    "UNSUBSCRIBE id={} filtres=[{}]",
                    u.packet_id,
                    list.join(", ")
                )
            }
            Packet::UnsubAck(ack) => format!("UNSUBACK id={}", ack.packet_id),
            Packet::PingReq => "PINGREQ".to_string(),
            Packet::PingResp => "PINGRESP".to_string(),
            Packet::Disconnect => "DISCONNECT".to_string(),
        }
    }
}

// ===========================================================================
// Tests : masquage des secrets et neutralisation (CWE-150)
// ===========================================================================
#[cfg(test)]
mod tests {
    use crate::mqtt::test_util::{complete, CONNECT_AVEC_IDENTIFIANTS};

    #[test]
    fn mot_de_passe_masque_par_defaut() {
        let (packet, _) = complete(&CONNECT_AVEC_IDENTIFIANTS);
        // Masqué par défaut, visible seulement sur demande explicite.
        assert!(packet.describe(false).contains("pass=<masqué, 4 octets>"));
        assert!(packet.describe(true).contains("pass=\"1234\""));
    }

    /// Vrai si la chaîne contient un caractère qu'un terminal interpréterait
    /// (contrôle comme ESC, ou inversion bidirectionnelle U+202E).
    fn contient_caractere_dangereux(text: &str) -> bool {
        text.chars().any(|c| c.is_control() || c == '\u{202e}')
    }

    #[test]
    fn topic_piege_est_neutralise_a_l_affichage() {
        // PUBLISH dont le topic contient ESC [ 2 J (effacement de l'écran).
        let buf = [
            0x30, 0x09, 0x00, 0x05, b'a', 0x1b, b'[', b'2', b'J', b'O', b'K',
        ];
        let (packet, _) = complete(&buf);
        let line = packet.describe(false);
        assert!(
            !contient_caractere_dangereux(&line),
            "ligne dangereuse : {line:?}"
        );
        assert!(
            line.contains("\\u{1b}"),
            "ESC doit apparaître sous forme inerte"
        );
    }

    #[test]
    fn client_id_et_username_pieges_sont_neutralises() {
        let buf = [
            0x10, 0x15, // CONNECT, RL = 21
            0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x82, 0x00, 0x3c, // user + clean
            0x00, 0x03, b'x', 0x1b, b'c', // client id "x ESC c"
            0x00, 0x04, b'u', 0xe2, 0x80, 0xae, // user "u" + U+202E (inversion bidi)
        ];
        let (packet, _) = complete(&buf);
        let line = packet.describe(false);
        assert!(
            !contient_caractere_dangereux(&line),
            "ligne dangereuse : {line:?}"
        );
    }

    #[test]
    fn payload_piege_est_neutralise() {
        // Payload valide en UTF-8 mais contenant ESC et U+202E.
        let buf = [
            0x30, 0x0a, 0x00, 0x01, b't', 0x1b, b'[', b'H', 0xe2, 0x80, 0xae, b'!',
        ];
        let line = complete(&buf).0.describe(false);
        assert!(
            !contient_caractere_dangereux(&line),
            "ligne dangereuse : {line:?}"
        );
    }

    #[test]
    fn payload_binaire_reste_en_hexadecimal() {
        // 0xff n'est jamais valide en UTF-8 : affichage hexadécimal.
        let buf = [0x30, 0x05, 0x00, 0x01, b't', 0xff, 0x00];
        assert!(complete(&buf).0.describe(false).contains("payload=0xff00"));
    }
}
