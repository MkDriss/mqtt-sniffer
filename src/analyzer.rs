//! Analyse des segments TCP capturés : relie le réassemblage TCP ([`crate::tcp`])
//! et le décodage MQTT par flux ([`crate::mqtt::StreamDecoder`]).
//!
//! L'[`Analyzer`] ne fait qu'observer et signaler : chaque constat est livré
//! sous forme d'[`Event`] à une fonction fournie par l'appelant, qui décide
//! quoi en faire (l'afficher, l'enregistrer, l'analyser...).
//!
//! ```text
//! TcpSegment ──► tcp::Reassembler ──► octets dans l'ordre ──► mqtt::StreamDecoder
//!                       │                                              │
//!                       └──────────────► Event ◄───────────────────────┘
//! ```

use std::collections::HashMap;
use std::time::Duration;

use crate::mqtt::{MemoryBudget, MqttError, Packet, StreamConfig, StreamDecoder, StreamEvent};
use crate::parser::TcpSegment;
use crate::tcp::{self, CloseReason, FlowKey, Reassembler, TcpEvent};

// ===========================================================================
// Configuration
// ===========================================================================

/// Réglages de l'analyse. `Config::default()` convient à un broker MQTT local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Port TCP sur lequel le trafic est décodé comme du MQTT.
    pub mqtt_port: u16,
    /// Réglages du réassemblage TCP (nombre de flux, expiration).
    pub tcp: tcp::Config,
    /// Réglages du décodage MQTT (taille maximale d'un message).
    pub stream: StreamConfig,
    /// Mémoire totale, en octets, pour les messages MQTT incomplets.
    pub memory_budget: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mqtt_port: crate::mqtt::MQTT_PORT,
            tcp: tcp::Config::default(),
            stream: StreamConfig::default(),
            memory_budget: MemoryBudget::default().limit(),
        }
    }
}

// ===========================================================================
// Événements
// ===========================================================================

/// Un constat de l'analyse, toujours rattaché à un sens de connexion (`flow`).
///
/// `'a` : un paquet MQTT emprunte ses octets ; l'événement n'est valable que
/// pendant l'appel de la fonction qui le reçoit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event<'a> {
    // --- Couche TCP ---
    /// Premier segment vu pour ce sens ; `from_syn` : début exact (SYN vu).
    FlowOpened { flow: FlowKey, from_syn: bool },
    /// Ce sens est terminé ; `incomplete_bytes` octets d'un message MQTT resté
    /// incomplet ont été perdus (0 le plus souvent).
    FlowClosed {
        flow: FlowKey,
        reason: CloseReason,
        incomplete_bytes: usize,
    },
    /// Octets situés avant le point de lecture, ignorés : retransmission, ou
    /// segment arrivé en retard après un trou.
    Retransmission { flow: FlowKey, bytes: usize },
    /// Octets jamais observés : le décodage MQTT se resynchronise.
    Gap { flow: FlowKey, missing: u32 },
    /// RST ignoré : numéro de séquence différent de celui attendu.
    IgnoredReset { flow: FlowKey },
    /// SYN ignoré : arrivé sur un flux ouvert.
    IgnoredSyn { flow: FlowKey },
    /// Nombre maximal de flux atteint : ce flux n'est pas suivi.
    FlowLimitReached { flow: FlowKey },

    // --- Couche MQTT ---
    /// Un message MQTT complet.
    Mqtt { flow: FlowKey, packet: Packet<'a> },
    /// Violation de la spécification MQTT : le reste du flux est ignoré.
    MqttAnomaly { flow: FlowKey, error: MqttError },
    /// Le décodage MQTT a retrouvé le début d'un message après `skipped` octets.
    Resynchronized { flow: FlowKey, skipped: usize },
    /// Message plus grand que la taille maximale : le reste du flux est ignoré.
    MessageTooLarge { flow: FlowKey, size: usize },
    /// Budget mémoire épuisé : le reste du flux est ignoré.
    BudgetExceeded { flow: FlowKey, needed: usize },
}

impl Event<'_> {
    /// Le sens de connexion concerné.
    pub fn flow(&self) -> FlowKey {
        use Event::*;
        match self {
            FlowOpened { flow, .. }
            | FlowClosed { flow, .. }
            | Retransmission { flow, .. }
            | Gap { flow, .. }
            | IgnoredReset { flow }
            | IgnoredSyn { flow }
            | FlowLimitReached { flow }
            | Mqtt { flow, .. }
            | MqttAnomaly { flow, .. }
            | Resynchronized { flow, .. }
            | MessageTooLarge { flow, .. }
            | BudgetExceeded { flow, .. } => *flow,
        }
    }

    /// Description d'une ligne, sans le sens de connexion. Les mots de passe
    /// MQTT ne sont affichés que si `show_secrets` vaut `true`.
    pub fn describe(&self, show_secrets: bool) -> String {
        use Event::*;
        match self {
            FlowOpened { from_syn: true, .. } => "ouverture du flux (SYN)".to_string(),
            FlowOpened {
                from_syn: false, ..
            } => "flux pris en cours de route (resynchronisation MQTT)".to_string(),
            FlowClosed {
                reason,
                incomplete_bytes,
                ..
            } => {
                let raison = match reason {
                    CloseReason::Fin => "FIN",
                    CloseReason::Reset => "RST",
                    CloseReason::Idle => "inactivité",
                };
                if *incomplete_bytes == 0 {
                    format!("fermeture du flux ({raison})")
                } else {
                    format!(
                        "fermeture du flux ({raison}), message MQTT incomplet perdu \
                         ({incomplete_bytes} octets)"
                    )
                }
            }
            Retransmission { bytes, .. } => {
                format!("[!] {bytes} octet(s) ignorés : déjà reçus, ou arrivés après un trou")
            }
            Gap { missing, .. } => format!("[!] trou : {missing} octet(s) jamais observés"),
            IgnoredReset { .. } => {
                "[!] RST ignoré (numéro de séquence inattendu, RFC 5961)".to_string()
            }
            IgnoredSyn { .. } => "[!] SYN ignoré (flux déjà ouvert)".to_string(),
            FlowLimitReached { .. } => "[!] flux non suivi : nombre maximal atteint".to_string(),
            Mqtt { packet, .. } => format!("MQTT {}", packet.describe(show_secrets)),
            MqttAnomaly { error, .. } => {
                format!("[ANOMALIE] {error} (suite du flux ignorée)")
            }
            Resynchronized { skipped, .. } => {
                format!("décodage MQTT resynchronisé ({skipped} octet(s) ignorés)")
            }
            MessageTooLarge { size, .. } => {
                format!("[ANOMALIE] message MQTT de {size} octets, trop grand (suite ignorée)")
            }
            BudgetExceeded { needed, .. } => format!(
                "[!] mémoire insuffisante pour garder {needed} octets (suite du flux ignorée)"
            ),
        }
    }
}

// ===========================================================================
// Analyseur
// ===========================================================================

/// Relie le réassemblage TCP et un décodeur MQTT par sens de connexion.
#[derive(Debug)]
pub struct Analyzer {
    config: Config,
    reassembler: Reassembler,
    /// Un décodeur par sens de connexion MQTT (port `config.mqtt_port`).
    decoders: HashMap<FlowKey, StreamDecoder>,
    budget: MemoryBudget,
}

impl Analyzer {
    pub fn new(config: Config) -> Self {
        Analyzer {
            config,
            reassembler: Reassembler::new(config.tcp),
            decoders: HashMap::new(),
            budget: MemoryBudget::new(config.memory_budget),
        }
    }

    /// Nombre de sens de connexion suivis.
    pub fn flow_count(&self) -> usize {
        self.reassembler.flow_count()
    }

    /// Octets actuellement gardés pour des messages MQTT incomplets.
    pub fn memory_used(&self) -> usize {
        self.budget.used()
    }

    /// Analyse un segment capturé à l'instant `now` (horodatage de capture).
    /// Chaque événement observé est passé à `on_event` au moment où il est
    /// produit ; les flux inactifs sont aussi expirés à cette occasion.
    pub fn process<F>(&mut self, segment: &TcpSegment<'_>, now: Duration, mut on_event: F)
    where
        F: FnMut(Event<'_>),
    {
        for event in self.reassembler.process(segment, now) {
            self.dispatch(event, &mut on_event);
        }
        for event in self.reassembler.expire_idle(now) {
            self.dispatch(event, &mut on_event);
        }
    }

    /// Transmet un événement TCP aux décodeurs MQTT, puis à l'appelant.
    fn dispatch<F>(&mut self, event: TcpEvent<'_>, on_event: &mut F)
    where
        F: FnMut(Event<'_>),
    {
        match event {
            TcpEvent::Opened { flow, from_syn } => {
                if self.is_mqtt(flow) {
                    let decoder = StreamDecoder::new(self.config.stream, from_syn);
                    // Un éventuel ancien décodeur doit rendre sa mémoire au budget.
                    if let Some(old) = self.decoders.insert(flow, decoder) {
                        old.close(&mut self.budget);
                    }
                }
                on_event(Event::FlowOpened { flow, from_syn });
            }
            TcpEvent::Data { flow, bytes } => {
                // `decoders` et `budget` sont deux champs distincts : Rust
                // accepte de les emprunter en même temps.
                if let Some(decoder) = self.decoders.get_mut(&flow) {
                    decoder.feed(bytes, &mut self.budget, |stream_event| {
                        on_event(from_stream(flow, stream_event));
                    });
                }
            }
            TcpEvent::Gap { flow, missing } => {
                if let Some(decoder) = self.decoders.get_mut(&flow) {
                    decoder.gap(&mut self.budget);
                }
                on_event(Event::Gap { flow, missing });
            }
            TcpEvent::Closed { flow, reason } => {
                let incomplete_bytes = self
                    .decoders
                    .remove(&flow)
                    .map_or(0, |decoder| decoder.close(&mut self.budget));
                on_event(Event::FlowClosed {
                    flow,
                    reason,
                    incomplete_bytes,
                });
            }
            TcpEvent::Retransmission { flow, bytes } => {
                on_event(Event::Retransmission { flow, bytes });
            }
            TcpEvent::IgnoredReset { flow } => on_event(Event::IgnoredReset { flow }),
            TcpEvent::IgnoredSyn { flow } => on_event(Event::IgnoredSyn { flow }),
            TcpEvent::FlowLimitReached { flow } => on_event(Event::FlowLimitReached { flow }),
        }
    }

    /// Ce sens de connexion transporte-t-il du MQTT ?
    fn is_mqtt(&self, flow: FlowKey) -> bool {
        flow.src.port() == self.config.mqtt_port || flow.dst.port() == self.config.mqtt_port
    }
}

/// Convertit un événement du décodeur MQTT en événement d'analyse.
fn from_stream(flow: FlowKey, event: StreamEvent<'_>) -> Event<'_> {
    match event {
        StreamEvent::Packet(packet) => Event::Mqtt { flow, packet },
        StreamEvent::Anomaly(error) => Event::MqttAnomaly { flow, error },
        StreamEvent::Resynchronized { skipped } => Event::Resynchronized { flow, skipped },
        StreamEvent::MessageTooLarge { size } => Event::MessageTooLarge { flow, size },
        StreamEvent::BudgetExceeded { needed } => Event::BudgetExceeded { flow, needed },
    }
}

// ===========================================================================
// Tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::TcpFlags;
    use std::net::{IpAddr, Ipv4Addr};

    const CLIENT: u16 = 40000;
    const BROKER: u16 = 1883;
    const T0: Duration = Duration::from_secs(1000);

    /// PUBLISH `labo/temp` = `21.5` capturé sur le labo (17 octets).
    const PUBLISH: [u8; 17] = [
        0x30, 0x0f, 0x00, 0x09, b'l', b'a', b'b', b'o', b'/', b't', b'e', b'm', b'p', b'2', b'1',
        b'.', b'5',
    ];
    const PINGREQ: [u8; 2] = [0xc0, 0x00];
    const LIGNE_PUBLISH: &str =
        "MQTT PUBLISH topic=\"labo/temp\" qos=0 retain=0 dup=0 id=- payload=\"21.5\"";

    /// Segment de 127.0.0.1:`src` vers 127.0.0.1:`dst` ; `flags` : S, F, R.
    fn seg<'a>(src: u16, dst: u16, seq: u32, flags: &str, payload: &'a [u8]) -> TcpSegment<'a> {
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
        TcpSegment {
            src_ip: local,
            dst_ip: local,
            src_port: src,
            dst_port: dst,
            seq,
            ack: 0,
            flags: TcpFlags {
                syn: flags.contains('S'),
                fin: flags.contains('F'),
                rst: flags.contains('R'),
                ack: true,
                psh: !payload.is_empty(),
            },
            payload,
        }
    }

    /// Analyse un segment et renvoie la description de chaque événement.
    fn analyser(a: &mut Analyzer, segment: &TcpSegment<'_>, now: Duration) -> Vec<String> {
        let mut lignes = Vec::new();
        a.process(segment, now, |event| lignes.push(event.describe(false)));
        lignes
    }

    /// Analyseur dont le sens client → broker a vu son SYN (ISN 1000).
    fn ouvert() -> Analyzer {
        let mut a = Analyzer::new(Config::default());
        analyser(&mut a, &seg(CLIENT, BROKER, 1000, "S", b""), T0);
        a
    }

    #[test]
    fn un_message_coupe_entre_deux_segments_est_decode_une_fois() {
        let mut a = ouvert();
        assert!(analyser(&mut a, &seg(CLIENT, BROKER, 1001, "", &PUBLISH[..10]), T0).is_empty());
        assert_eq!(a.memory_used(), 10);
        assert_eq!(
            analyser(&mut a, &seg(CLIENT, BROKER, 1011, "", &PUBLISH[10..]), T0),
            vec![LIGNE_PUBLISH]
        );
        assert_eq!(a.memory_used(), 0);
    }

    #[test]
    fn une_retransmission_n_est_pas_decodee_deux_fois() {
        let mut a = ouvert();
        let segment = seg(CLIENT, BROKER, 1001, "", &PUBLISH);
        assert_eq!(analyser(&mut a, &segment, T0), vec![LIGNE_PUBLISH]);
        assert_eq!(
            analyser(&mut a, &segment, T0),
            vec!["[!] 17 octet(s) ignorés : déjà reçus, ou arrivés après un trou"]
        );
    }

    #[test]
    fn un_trou_est_signale_puis_le_decodage_se_resynchronise() {
        let mut a = ouvert();
        analyser(&mut a, &seg(CLIENT, BROKER, 1001, "", &PUBLISH[..10]), T0);
        // 20 octets manquent avant ce PINGREQ (attendu : 1011, reçu : 1031).
        assert_eq!(
            analyser(&mut a, &seg(CLIENT, BROKER, 1031, "", &PINGREQ), T0),
            vec![
                "[!] trou : 20 octet(s) jamais observés",
                "décodage MQTT resynchronisé (0 octet(s) ignorés)",
                "MQTT PINGREQ",
            ]
        );
        assert_eq!(a.memory_used(), 0, "le message incomplet a été abandonné");
    }

    #[test]
    fn un_flux_pris_en_cours_ne_produit_pas_de_fausse_anomalie() {
        let mut a = Analyzer::new(Config::default());
        // Fin d'un message dont le début n'a pas été capturé.
        assert_eq!(
            analyser(&mut a, &seg(CLIENT, BROKER, 5000, "", &PUBLISH[5..]), T0),
            vec!["flux pris en cours de route (resynchronisation MQTT)"]
        );
        assert_eq!(
            analyser(&mut a, &seg(CLIENT, BROKER, 5012, "", &PINGREQ), T0),
            vec![
                "décodage MQTT resynchronisé (12 octet(s) ignorés)",
                "MQTT PINGREQ"
            ]
        );
    }

    #[test]
    fn la_fermeture_signale_un_message_incomplet_et_rend_la_memoire() {
        let mut a = ouvert();
        analyser(&mut a, &seg(CLIENT, BROKER, 1001, "", &PUBLISH[..10]), T0);
        assert_eq!(
            analyser(&mut a, &seg(CLIENT, BROKER, 1011, "F", b""), T0),
            vec!["fermeture du flux (FIN), message MQTT incomplet perdu (10 octets)"]
        );
        assert_eq!(a.memory_used(), 0);
    }

    #[test]
    fn un_rst_valide_ferme_et_rend_la_memoire() {
        let mut a = ouvert();
        analyser(&mut a, &seg(CLIENT, BROKER, 1001, "", &PUBLISH[..10]), T0);
        assert_eq!(
            analyser(&mut a, &seg(CLIENT, BROKER, 1011, "R", b""), T0),
            vec!["fermeture du flux (RST), message MQTT incomplet perdu (10 octets)"]
        );
        assert_eq!(a.memory_used(), 0);
        assert_eq!(a.flow_count(), 0);
    }

    #[test]
    fn un_flux_inactif_expire_et_rend_la_memoire() {
        let mut a = ouvert();
        analyser(&mut a, &seg(CLIENT, BROKER, 1001, "", &PUBLISH[..10]), T0);
        // Plus tard, un segment d'un AUTRE flux déclenche l'expiration du premier.
        let plus_tard = T0 + Config::default().tcp.idle_timeout + Duration::from_secs(1);
        let lignes = analyser(&mut a, &seg(CLIENT + 1, BROKER, 1, "S", b""), plus_tard);
        assert_eq!(
            lignes,
            vec![
                "ouverture du flux (SYN)",
                "fermeture du flux (inactivité), message MQTT incomplet perdu (10 octets)",
            ]
        );
        assert_eq!(a.memory_used(), 0);
    }

    #[test]
    fn le_trafic_hors_du_port_mqtt_n_est_pas_decode() {
        let mut a = Analyzer::new(Config::default());
        analyser(&mut a, &seg(CLIENT, 8080, 1000, "S", b""), T0);
        // Des octets qui seraient une anomalie MQTT : ici, simplement ignorés.
        assert!(analyser(&mut a, &seg(CLIENT, 8080, 1001, "", &[0xf0, 0x00]), T0).is_empty());
    }

    #[test]
    fn une_anomalie_mqtt_porte_sur_son_flux() {
        let mut a = ouvert();
        let mut flux = None;
        a.process(&seg(CLIENT, BROKER, 1001, "", &[0xf0, 0x00]), T0, |event| {
            flux = Some(event.flow())
        });
        let attendu = FlowKey::of(&seg(CLIENT, BROKER, 0, "", b""));
        assert_eq!(flux, Some(attendu));
    }
}
