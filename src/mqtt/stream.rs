//! Décodage MQTT d'un flux d'octets : retrouve les messages dans les octets
//! livrés dans l'ordre par le réassemblage TCP, y compris quand un message est
//! à cheval sur plusieurs segments.
//!
//! Un [`StreamDecoder`] traite **un seul sens** d'une connexion. Il ne connaît
//! ni TCP ni le réseau : il reçoit des octets et signale ce qu'il y trouve par
//! des événements ([`StreamEvent`]).
//!
//! # Fonctionnement
//!
//! - **Cas courant, sans copie** : les messages complets sont décodés
//!   directement dans les octets reçus.
//! - **Message incomplet** : seul le début du message est copié dans un tampon,
//!   en attendant la suite.
//! - **Resynchronisation** : après un trou, ou sur un flux pris en cours de
//!   route, on ne sait pas où commence le prochain message. On essaie alors de
//!   décoder chaque nouveau bloc d'octets depuis son début ; les échecs sont
//!   silencieux, et le premier message complet décodé rétablit le flux. C'est
//!   une heuristique : une suite d'octets quelconque peut, rarement, ressembler
//!   à un message valide.
//! - **Abandon** : sur un flux synchronisé, une violation de la spécification
//!   fait perdre le découpage en messages. Elle est signalée une fois, puis le
//!   reste du flux est ignoré (pas de cascade de fausses anomalies).
//! - **Mémoire bornée** : un message annoncé plus grand que
//!   [`StreamConfig::max_message_size`] est refusé dès son en-tête, et tous les
//!   décodeurs partagent un [`MemoryBudget`] global pour leurs tampons.

use super::{decode, Decoded, MqttError, Packet};

// ===========================================================================
// Types publics
// ===========================================================================

/// Réglages d'un décodeur de flux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamConfig {
    /// Taille maximale d'un message MQTT, en-tête fixe compris.
    pub max_message_size: usize,
}

impl Default for StreamConfig {
    fn default() -> Self {
        StreamConfig {
            max_message_size: 1024 * 1024, // 1 Mio
        }
    }
}

/// Budget mémoire partagé par tous les décodeurs de flux : le total des octets
/// mis en attente (messages incomplets) ne peut pas dépasser `limit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryBudget {
    limit: usize,
    used: usize,
}

impl MemoryBudget {
    pub fn new(limit: usize) -> Self {
        MemoryBudget { limit, used: 0 }
    }

    /// Limite totale du budget, en octets.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Octets actuellement réservés par l'ensemble des décodeurs.
    pub fn used(&self) -> usize {
        self.used
    }

    /// Réserve `n` octets si le budget le permet.
    fn try_reserve(&mut self, n: usize) -> bool {
        if n <= self.limit - self.used {
            self.used += n;
            true
        } else {
            false
        }
    }

    /// Rend `n` octets au budget.
    fn release(&mut self, n: usize) {
        debug_assert!(n <= self.used, "libération supérieure à la réservation");
        self.used -= n;
    }
}

impl Default for MemoryBudget {
    fn default() -> Self {
        MemoryBudget::new(64 * 1024 * 1024) // 64 Mio
    }
}

/// Ce que le décodeur a trouvé dans les octets reçus.
///
/// `'a` : un paquet décodé emprunte ses octets, soit aux octets reçus, soit au
/// tampon interne du décodeur. Il n'est donc valable que pendant l'appel de la
/// fonction qui le reçoit ; pour le garder, il faut en copier le contenu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent<'a> {
    /// Un message complet a été décodé.
    Packet(Packet<'a>),
    /// Violation de la spécification sur un flux synchronisé : le reste du flux
    /// est ignoré.
    Anomaly(MqttError),
    /// Le flux est de nouveau synchronisé, après `skipped` octets ignorés.
    Resynchronized { skipped: usize },
    /// Un message de `size` octets dépasse la taille maximale : le reste du
    /// flux est ignoré.
    MessageTooLarge { size: usize },
    /// Le budget mémoire global ne permet pas de garder `needed` octets en
    /// attente : le reste du flux est ignoré.
    BudgetExceeded { needed: usize },
}

// ===========================================================================
// Décodeur de flux
// ===========================================================================

/// Où en est le décodeur dans le découpage du flux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncState {
    /// On sait où commence le prochain message.
    Synced,
    /// On cherche le début d'un message ; `skipped` octets ignorés jusqu'ici.
    Resyncing { skipped: usize },
    /// Le flux est ignoré jusqu'à sa fermeture.
    Abandoned,
}

/// Découpe en messages MQTT les octets d'un sens d'une connexion.
#[derive(Debug)]
pub struct StreamDecoder {
    config: StreamConfig,
    state: SyncState,
    /// Début d'un message incomplet, en attente de la suite.
    pending: Vec<u8>,
}

impl StreamDecoder {
    /// `synced` vaut `true` si le flux est observé depuis son début (SYN vu),
    /// `false` s'il est pris en cours de route.
    pub fn new(config: StreamConfig, synced: bool) -> Self {
        let state = if synced {
            SyncState::Synced
        } else {
            SyncState::Resyncing { skipped: 0 }
        };
        StreamDecoder {
            config,
            state,
            pending: Vec::new(),
        }
    }

    /// Octets actuellement en attente (début d'un message incomplet).
    pub fn buffered(&self) -> usize {
        self.pending.len()
    }

    /// Traite les octets suivants du flux. Chaque événement observé est passé à
    /// `on_event`, au moment où il est produit.
    pub fn feed<F>(&mut self, data: &[u8], budget: &mut MemoryBudget, mut on_event: F)
    where
        F: FnMut(StreamEvent<'_>),
    {
        match self.state {
            SyncState::Abandoned => {}
            SyncState::Resyncing { skipped } => {
                // On n'accepte comme point de départ qu'un message COMPLET.
                if let Ok(Decoded::Complete { .. }) = decode(data) {
                    self.state = SyncState::Synced;
                    on_event(StreamEvent::Resynchronized { skipped });
                    self.feed_synced(data, budget, &mut on_event);
                } else {
                    // Échec silencieux : on cherche encore le début d'un message.
                    self.state = SyncState::Resyncing {
                        skipped: skipped + data.len(),
                    };
                }
            }
            SyncState::Synced => self.feed_synced(data, budget, &mut on_event),
        }
    }

    /// Signale que des octets du flux ont été perdus (trou TCP) : le message en
    /// attente est abandonné, et il faut retrouver le début d'un message.
    pub fn gap(&mut self, budget: &mut MemoryBudget) {
        self.discard_pending(budget);
        if self.state != SyncState::Abandoned {
            self.state = SyncState::Resyncing { skipped: 0 };
        }
    }

    /// Fin du flux : rend la mémoire au budget et renvoie le nombre d'octets
    /// d'un message resté incomplet (0 si aucun).
    pub fn close(mut self, budget: &mut MemoryBudget) -> usize {
        let lost = self.pending.len();
        self.discard_pending(budget);
        lost
    }

    // --- Fonctionnement interne ---

    fn feed_synced<F>(&mut self, data: &[u8], budget: &mut MemoryBudget, on_event: &mut F)
    where
        F: FnMut(StreamEvent<'_>),
    {
        if self.pending.is_empty() {
            // Cas courant : on décode directement dans `data`, sans copie.
            let outcome = decode_all(data, on_event);
            let rest = &data[outcome.consumed..];
            match outcome.end {
                End::Clean => {}
                End::Error(error) => self.abandon(StreamEvent::Anomaly(error), budget, on_event),
                End::Incomplete { needed } => {
                    // Taille totale du message (exacte dès que l'en-tête est complet).
                    let size = rest.len() + needed;
                    if size > self.config.max_message_size {
                        self.abandon(StreamEvent::MessageTooLarge { size }, budget, on_event);
                    } else if budget.try_reserve(rest.len()) {
                        // Seul le début du message incomplet est copié.
                        self.pending.extend_from_slice(rest);
                    } else {
                        let needed = rest.len();
                        self.abandon(StreamEvent::BudgetExceeded { needed }, budget, on_event);
                    }
                }
            }
        } else {
            // Un message attend sa suite : on complète le tampon.
            if !budget.try_reserve(data.len()) {
                let needed = self.pending.len() + data.len();
                self.abandon(StreamEvent::BudgetExceeded { needed }, budget, on_event);
                return;
            }
            self.pending.extend_from_slice(data);

            // `decode_all` emprunte le tampon le temps du décodage...
            let outcome = decode_all(&self.pending, on_event);
            // ...puis on retire du tampon les messages déjà décodés.
            self.pending.drain(..outcome.consumed);
            budget.release(outcome.consumed);

            match outcome.end {
                End::Clean => {} // le tampon est vide
                End::Error(error) => self.abandon(StreamEvent::Anomaly(error), budget, on_event),
                End::Incomplete { needed } => {
                    // Le début du message suivant reste dans le tampon (déjà réservé).
                    let size = self.pending.len() + needed;
                    if size > self.config.max_message_size {
                        self.abandon(StreamEvent::MessageTooLarge { size }, budget, on_event);
                    }
                }
            }
        }
    }

    /// Signale `event`, libère la mémoire et ignore la suite du flux.
    fn abandon<F>(&mut self, event: StreamEvent<'_>, budget: &mut MemoryBudget, on_event: &mut F)
    where
        F: FnMut(StreamEvent<'_>),
    {
        self.discard_pending(budget);
        self.state = SyncState::Abandoned;
        on_event(event);
    }

    fn discard_pending(&mut self, budget: &mut MemoryBudget) {
        budget.release(self.pending.len());
        self.pending = Vec::new(); // rend aussi la capacité allouée
    }
}

// ===========================================================================
// Décodage d'une suite de messages
// ===========================================================================

/// Comment se termine une suite de messages dans un bloc d'octets.
enum End {
    /// Le bloc se termine exactement à la fin d'un message.
    Clean,
    /// Le bloc se termine au milieu d'un message ; il manque au moins `needed` octets.
    Incomplete { needed: usize },
    /// Les octets violent la spécification.
    Error(MqttError),
}

/// Résultat de [`decode_all`] : `consumed` octets ont formé des messages
/// complets, puis la suite se termine comme l'indique `end`.
struct Outcome {
    consumed: usize,
    end: End,
}

/// Décode tous les messages complets de `buf`, en passant chacun à `on_event`.
///
/// C'est une fonction libre, et non une méthode : elle n'emprunte que `buf`,
/// ce qui permet de l'appeler sur le tampon interne d'un décodeur.
fn decode_all<F>(buf: &[u8], on_event: &mut F) -> Outcome
where
    F: FnMut(StreamEvent<'_>),
{
    let mut consumed = 0;
    loop {
        if consumed == buf.len() {
            return Outcome {
                consumed,
                end: End::Clean,
            };
        }
        match decode(&buf[consumed..]) {
            Ok(Decoded::Complete {
                packet,
                consumed: n,
            }) => {
                on_event(StreamEvent::Packet(packet));
                consumed += n;
            }
            Ok(Decoded::Incomplete { needed }) => {
                return Outcome {
                    consumed,
                    end: End::Incomplete { needed },
                }
            }
            Err(error) => {
                return Outcome {
                    consumed,
                    end: End::Error(error),
                }
            }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::mqtt::PacketType;

    /// PUBLISH `labo/temp` = `21.5` capturé sur le labo (17 octets).
    const PUBLISH: [u8; 17] = [
        0x30, 0x0f, 0x00, 0x09, b'l', b'a', b'b', b'o', b'/', b't', b'e', b'm', b'p', b'2', b'1',
        b'.', b'5',
    ];
    const PINGREQ: [u8; 2] = [0xc0, 0x00];

    /// Copie « possédée » d'un événement, pour pouvoir le garder après l'appel.
    /// Les événements reçus par la closure ne vivent que pendant l'appel : on
    /// les transforme donc en valeurs indépendantes (le paquet devient texte).
    #[derive(Debug, PartialEq, Eq)]
    enum Vu {
        Paquet(String),
        Anomalie(MqttError),
        Resync(usize),
        TropGrand(usize),
        Budget(usize),
    }

    fn nourrir(d: &mut StreamDecoder, budget: &mut MemoryBudget, data: &[u8]) -> Vec<Vu> {
        let mut vus = Vec::new();
        d.feed(data, budget, |event| {
            vus.push(match event {
                StreamEvent::Packet(p) => Vu::Paquet(p.describe(false)),
                StreamEvent::Anomaly(e) => Vu::Anomalie(e),
                StreamEvent::Resynchronized { skipped } => Vu::Resync(skipped),
                StreamEvent::MessageTooLarge { size } => Vu::TropGrand(size),
                StreamEvent::BudgetExceeded { needed } => Vu::Budget(needed),
            })
        });
        vus
    }

    fn synchronise() -> (StreamDecoder, MemoryBudget) {
        (
            StreamDecoder::new(StreamConfig::default(), true),
            MemoryBudget::default(),
        )
    }

    fn paquet_publish() -> Vu {
        Vu::Paquet(
            "PUBLISH topic=\"labo/temp\" qos=0 retain=0 dup=0 id=- payload=\"21.5\"".to_string(),
        )
    }

    #[test]
    fn message_complet_dans_un_bloc() {
        let (mut d, mut b) = synchronise();
        assert_eq!(nourrir(&mut d, &mut b, &PUBLISH), vec![paquet_publish()]);
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn le_cas_courant_ne_copie_pas_les_octets() {
        let (mut d, mut b) = synchronise();
        // Variable locale obligatoire : une `const` est recopiée à chaque
        // utilisation, deux mentions de PUBLISH n'auraient pas la même adresse.
        let data = PUBLISH;
        let mut meme_adresse = false;
        d.feed(&data, &mut b, |event| {
            if let StreamEvent::Packet(Packet::Publish(p)) = event {
                // Le topic pointe directement dans les octets reçus.
                meme_adresse = std::ptr::eq(p.topic.as_ptr(), data[4..].as_ptr());
            }
        });
        assert!(meme_adresse);
    }

    #[test]
    fn deux_messages_dans_un_bloc() {
        let (mut d, mut b) = synchronise();
        let mut bloc = PINGREQ.to_vec();
        bloc.extend_from_slice(&PUBLISH);
        assert_eq!(
            nourrir(&mut d, &mut b, &bloc),
            vec![Vu::Paquet("PINGREQ".to_string()), paquet_publish()]
        );
    }

    #[test]
    fn message_coupe_en_deux_blocs() {
        let (mut d, mut b) = synchronise();
        assert!(nourrir(&mut d, &mut b, &PUBLISH[..10]).is_empty());
        assert_eq!(d.buffered(), 10);
        assert_eq!(
            b.used(),
            10,
            "le début du message est réservé dans le budget"
        );
        assert_eq!(
            nourrir(&mut d, &mut b, &PUBLISH[10..]),
            vec![paquet_publish()]
        );
        assert_eq!(d.buffered(), 0);
        assert_eq!(b.used(), 0, "la mémoire est rendue au budget");
    }

    #[test]
    fn en_tete_coupe_entre_deux_blocs() {
        // Le premier bloc ne contient que l'octet de type : la longueur manque.
        let (mut d, mut b) = synchronise();
        assert!(nourrir(&mut d, &mut b, &PUBLISH[..1]).is_empty());
        assert!(nourrir(&mut d, &mut b, &PUBLISH[1..5]).is_empty());
        assert_eq!(
            nourrir(&mut d, &mut b, &PUBLISH[5..]),
            vec![paquet_publish()]
        );
    }

    #[test]
    fn fin_d_un_message_et_debut_du_suivant_dans_le_meme_bloc() {
        let (mut d, mut b) = synchronise();
        nourrir(&mut d, &mut b, &PUBLISH[..10]);
        // Bloc = fin du PUBLISH + PINGREQ complet + début d'un autre PUBLISH.
        let mut bloc = PUBLISH[10..].to_vec();
        bloc.extend_from_slice(&PINGREQ);
        bloc.extend_from_slice(&PUBLISH[..3]);
        assert_eq!(
            nourrir(&mut d, &mut b, &bloc),
            vec![paquet_publish(), Vu::Paquet("PINGREQ".to_string())]
        );
        assert_eq!(d.buffered(), 3);
        assert_eq!(b.used(), 3);
    }

    #[test]
    fn une_anomalie_est_signalee_une_fois_puis_le_flux_est_ignore() {
        let (mut d, mut b) = synchronise();
        // SUBSCRIBE avec des flags 0000 au lieu de 0010.
        assert_eq!(
            nourrir(&mut d, &mut b, &[0x80, 0x05, 0x00, 0x01, 0x00, 0x01, b'a']),
            vec![Vu::Anomalie(MqttError::InvalidFlags {
                packet_type: PacketType::Subscribe,
                flags: 0
            })]
        );
        // Le découpage est perdu : même un message valide est ignoré.
        assert!(nourrir(&mut d, &mut b, &PINGREQ).is_empty());
    }

    #[test]
    fn un_message_trop_grand_est_refuse_des_son_en_tete() {
        let mut d = StreamDecoder::new(
            StreamConfig {
                max_message_size: 16,
            },
            true,
        );
        let mut b = MemoryBudget::default();
        // En-tête annonçant 100 octets de corps (message de 102 octets).
        assert_eq!(
            nourrir(&mut d, &mut b, &[0x30, 0x64, 0x00, 0x01]),
            vec![Vu::TropGrand(102)]
        );
        assert_eq!(b.used(), 0, "rien n'est gardé en mémoire");
    }

    #[test]
    fn un_message_trop_grand_est_refuse_meme_si_son_en_tete_arrive_en_deux_fois() {
        let mut d = StreamDecoder::new(
            StreamConfig {
                max_message_size: 16,
            },
            true,
        );
        let mut b = MemoryBudget::default();
        // L'octet de type seul : la taille n'est pas encore connue.
        assert!(nourrir(&mut d, &mut b, &[0x30]).is_empty());
        // La Remaining Length arrive : 100 octets de corps, refusé.
        assert_eq!(
            nourrir(&mut d, &mut b, &[0x64, 0x00, 0x01]),
            vec![Vu::TropGrand(102)]
        );
        assert_eq!(b.used(), 0);
    }

    #[test]
    fn le_budget_global_est_respecte() {
        let (mut d, _) = synchronise();
        let mut b = MemoryBudget::new(5);
        assert_eq!(
            nourrir(&mut d, &mut b, &PUBLISH[..10]),
            vec![Vu::Budget(10)]
        );
        assert_eq!(b.used(), 0);
    }

    #[test]
    fn le_budget_est_partage_entre_decodeurs() {
        let mut b = MemoryBudget::new(15);
        let mut d1 = StreamDecoder::new(StreamConfig::default(), true);
        let mut d2 = StreamDecoder::new(StreamConfig::default(), true);
        assert!(nourrir(&mut d1, &mut b, &PUBLISH[..10]).is_empty());
        // Il ne reste que 5 octets de budget pour le second décodeur.
        assert_eq!(
            nourrir(&mut d2, &mut b, &PUBLISH[..10]),
            vec![Vu::Budget(10)]
        );
        assert_eq!(b.used(), 10);
    }

    #[test]
    fn un_flux_pris_en_cours_se_resynchronise_en_silence() {
        let mut d = StreamDecoder::new(StreamConfig::default(), false);
        let mut b = MemoryBudget::default();
        // Fin d'un message dont on a manqué le début : aucune anomalie signalée.
        assert!(nourrir(&mut d, &mut b, &PUBLISH[5..]).is_empty());
        // Un message complet rétablit le flux.
        assert_eq!(
            nourrir(&mut d, &mut b, &PINGREQ),
            vec![Vu::Resync(12), Vu::Paquet("PINGREQ".to_string())]
        );
        // Le flux est de nouveau normal : une anomalie serait signalée.
        assert_eq!(nourrir(&mut d, &mut b, &PUBLISH), vec![paquet_publish()]);
    }

    #[test]
    fn un_message_incomplet_ne_suffit_pas_a_se_resynchroniser() {
        let mut d = StreamDecoder::new(StreamConfig::default(), false);
        let mut b = MemoryBudget::default();
        // Début plausible d'un message, mais incomplet : on ne peut pas le valider.
        assert!(nourrir(&mut d, &mut b, &PUBLISH[..3]).is_empty());
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn un_trou_relance_la_resynchronisation() {
        let (mut d, mut b) = synchronise();
        nourrir(&mut d, &mut b, &PUBLISH[..10]);
        d.gap(&mut b);
        assert_eq!(d.buffered(), 0, "le message incomplet est abandonné");
        assert_eq!(b.used(), 0);
        // La suite de l'ancien message n'a plus de sens : ignorée en silence.
        assert!(nourrir(&mut d, &mut b, &PUBLISH[12..]).is_empty());
        assert_eq!(
            nourrir(&mut d, &mut b, &PINGREQ),
            vec![Vu::Resync(5), Vu::Paquet("PINGREQ".to_string())]
        );
    }

    #[test]
    fn la_fermeture_rend_la_memoire_et_compte_les_octets_perdus() {
        let (mut d, mut b) = synchronise();
        nourrir(&mut d, &mut b, &PUBLISH[..10]);
        assert_eq!(d.close(&mut b), 10);
        assert_eq!(b.used(), 0);
    }
}
