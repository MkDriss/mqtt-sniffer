//! Réassemblage TCP : reconstitue, pour chaque sens d'une connexion, le flux
//! d'octets dans l'ordre, à partir des segments capturés.
//!
//! Ce module ne connaît pas MQTT. Il livre des octets dans l'ordre et signale
//! tout ce qu'il observe sous forme d'événements ([`TcpEvent`]) : c'est à
//! l'appelant de décider quoi en faire (les afficher, les analyser...).
//!
//! # Politique de réassemblage
//!
//! - **Un flux par sens** : une connexion TCP transporte deux flux d'octets
//!   indépendants (client → serveur et serveur → client), identifiés par un
//!   [`FlowKey`].
//! - **Aucune copie** : les segments arrivés en avance ne sont pas mis en
//!   attente. Les octets livrés sont donc toujours un morceau du segment
//!   courant ([`TcpEvent::Data`] emprunte ses octets au segment).
//! - **Trou** : un segment arrivé en avance provoque un [`TcpEvent::Gap`], puis
//!   la livraison reprend à ce segment. Les octets manquants sont perdus.
//! - **Octets antérieurs au point de lecture** : ignorés, seule la partie
//!   nouvelle d'un segment est livrée ([`TcpEvent::Retransmission`]). Il s'agit
//!   d'une retransmission, ou d'un segment arrivé en retard après un trou : dans
//!   ce second cas, ses octets n'avaient jamais été livrés et sont perdus.
//! - **RST** : accepté seulement si son numéro de séquence est exactement le
//!   prochain attendu, comme le fait Linux (RFC 5961 §3.2). Un RST forgé avec
//!   un autre numéro ne ferme donc pas le flux, ni ici ni chez le destinataire.
//! - **SYN sur un flux ouvert** : ignoré (Linux répond alors par un « challenge
//!   ACK » sans réinitialiser la connexion), sauf si ce sens a déjà été fermé
//!   par un FIN : il s'agit alors d'une nouvelle connexion sur les mêmes ports.
//! - **Ouverture** : un flux inconnu n'est suivi qu'à partir d'un SYN ou d'un
//!   segment portant des données ; un ACK seul est ignoré.
//! - **Numéros de séquence** : comparés modulo 2³² (RFC 9293), pour rester
//!   justes quand ils repassent par zéro.
//! - **Mémoire bornée** : au plus [`Config::max_flows`] flux suivis, et les flux
//!   inactifs depuis [`Config::idle_timeout`] sont oubliés par
//!   [`Reassembler::expire_idle`].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use crate::parser::TcpSegment;

// ===========================================================================
// Types publics
// ===========================================================================

/// Un sens d'une connexion TCP : les octets envoyés par `src` à `dst`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl FlowKey {
    /// Le sens de la connexion auquel appartient ce segment.
    pub fn of(segment: &TcpSegment<'_>) -> FlowKey {
        FlowKey {
            src: SocketAddr::new(segment.src_ip, segment.src_port),
            dst: SocketAddr::new(segment.dst_ip, segment.dst_port),
        }
    }

    /// L'autre sens de la même connexion.
    pub fn reverse(self) -> FlowKey {
        FlowKey {
            src: self.dst,
            dst: self.src,
        }
    }
}

/// Réglages du réassembleur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Nombre maximal de flux (sens de connexion) suivis en même temps.
    pub max_flows: usize,
    /// Durée sans aucun segment au-delà de laquelle un flux est oublié.
    pub idle_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_flows: 256,
            idle_timeout: Duration::from_secs(5 * 60),
        }
    }
}

/// Pourquoi un flux a été fermé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Fermeture propre : l'émetteur a envoyé un FIN.
    Fin,
    /// Coupure brutale : un RST valide a été reçu.
    Reset,
    /// Aucun segment depuis plus de [`Config::idle_timeout`].
    Idle,
}

/// Ce que le réassembleur a observé en traitant un segment.
///
/// `'a` : les octets de [`TcpEvent::Data`] sont empruntés au segment traité.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpEvent<'a> {
    /// Premier segment vu pour ce sens. `from_syn` vaut `true` si c'est un SYN
    /// (début exact de la connexion), `false` si le flux est pris en cours.
    Opened { flow: FlowKey, from_syn: bool },
    /// Nouveaux octets, dans l'ordre.
    Data { flow: FlowKey, bytes: &'a [u8] },
    /// `bytes` octets situés avant le point de lecture ont été ignorés :
    /// retransmission, ou segment arrivé en retard après un [`TcpEvent::Gap`].
    Retransmission { flow: FlowKey, bytes: usize },
    /// `missing` octets n'ont jamais été vus : la livraison reprend après eux.
    Gap { flow: FlowKey, missing: u32 },
    /// Ce sens du flux est terminé.
    Closed { flow: FlowKey, reason: CloseReason },
    /// RST ignoré : son numéro de séquence n'est pas celui attendu (ou le flux
    /// est inconnu). Le destinataire l'ignore aussi (RFC 5961 §3.2).
    IgnoredReset { flow: FlowKey },
    /// SYN ignoré : il arrive sur un flux ouvert avec un autre numéro de départ.
    IgnoredSyn { flow: FlowKey },
    /// Table pleine : ce nouveau flux n'est pas suivi.
    FlowLimitReached { flow: FlowKey },
}

// ===========================================================================
// Réassembleur
// ===========================================================================

/// État mémorisé pour un sens de connexion.
#[derive(Debug)]
struct FlowState {
    /// Numéro de séquence du prochain octet attendu.
    next_seq: u32,
    /// Horodatage du dernier segment vu.
    last_seen: Duration,
    /// Un FIN a été vu dans ce sens.
    fin_seen: bool,
}

/// Reconstitue les flux d'octets de toutes les connexions observées.
#[derive(Debug)]
pub struct Reassembler {
    config: Config,
    flows: HashMap<FlowKey, FlowState>,
}

impl Reassembler {
    pub fn new(config: Config) -> Self {
        Reassembler {
            config,
            flows: HashMap::new(),
        }
    }

    /// Nombre de flux actuellement suivis.
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Traite un segment capturé à l'instant `now` et renvoie les événements
    /// observés, dans l'ordre.
    ///
    /// Les événements empruntent les octets du segment (`'a`) : aucune copie.
    pub fn process<'a>(&mut self, segment: &TcpSegment<'a>, now: Duration) -> Vec<TcpEvent<'a>> {
        let flow = FlowKey::of(segment);
        let mut events = Vec::new();

        if segment.flags.rst {
            self.handle_reset(flow, segment.seq, &mut events);
            return events;
        }

        // Numéro du premier octet de DONNÉES : un SYN consomme un numéro.
        let data_seq = if segment.flags.syn {
            segment.seq.wrapping_add(1)
        } else {
            segment.seq
        };

        // --- 1. Retrouver l'état de ce sens, ou le créer ---
        let has_data = !segment.payload.is_empty();
        if !self.open_or_check(
            flow,
            data_seq,
            segment.flags.syn,
            has_data,
            now,
            &mut events,
        ) {
            return events;
        }
        let state = self.flows.get_mut(&flow).expect("état présent");
        state.last_seen = now;

        // --- 2. Situer le segment par rapport au prochain octet attendu ---
        // Distance signée modulo 2³² : négative = début déjà reçu,
        // positive = des octets manquent avant ce segment.
        let distance = data_seq.wrapping_sub(state.next_seq) as i32;
        if distance > 0 {
            events.push(TcpEvent::Gap {
                flow,
                missing: distance as u32,
            });
            state.next_seq = data_seq;
        }

        // Octets du début du segment déjà livrés (0 si le segment est nouveau).
        let already_seen = if distance < 0 {
            distance.unsigned_abs() as usize
        } else {
            0
        };
        // `get` renvoie `None` si tout le segment est déjà connu : pas de panique.
        let new_bytes = segment.payload.get(already_seen..).unwrap_or(&[]);
        let duplicate = segment.payload.len() - new_bytes.len();

        if duplicate > 0 {
            events.push(TcpEvent::Retransmission {
                flow,
                bytes: duplicate,
            });
        }
        if !new_bytes.is_empty() {
            events.push(TcpEvent::Data {
                flow,
                bytes: new_bytes,
            });
            state.next_seq = state.next_seq.wrapping_add(new_bytes.len() as u32);
        }

        // --- 3. Fin du flux ---
        if segment.flags.fin && !state.fin_seen {
            state.fin_seen = true;
            state.next_seq = state.next_seq.wrapping_add(1); // un FIN consomme un numéro
            events.push(TcpEvent::Closed {
                flow,
                reason: CloseReason::Fin,
            });
            // Les deux sens sont terminés : on libère la mémoire.
            if self.flows.get(&flow.reverse()).is_some_and(|s| s.fin_seen) {
                self.flows.remove(&flow);
                self.flows.remove(&flow.reverse());
            }
        }

        events
    }

    /// Oublie les flux sans aucun segment depuis plus de `idle_timeout`.
    /// À appeler régulièrement (par exemple à chaque segment capturé).
    pub fn expire_idle(&mut self, now: Duration) -> Vec<TcpEvent<'static>> {
        let timeout = self.config.idle_timeout;
        let mut expired: Vec<FlowKey> = self
            .flows
            .iter()
            // `saturating_sub` : pas de panique si l'horloge recule.
            .filter(|(_, state)| now.saturating_sub(state.last_seen) > timeout)
            .map(|(flow, _)| *flow)
            .collect();
        expired.sort(); // ordre stable, indépendant de la table de hachage

        expired
            .into_iter()
            .map(|flow| {
                self.flows.remove(&flow);
                TcpEvent::Closed {
                    flow,
                    reason: CloseReason::Idle,
                }
            })
            .collect()
    }

    /// Crée l'état d'un nouveau flux, ou vérifie la cohérence d'un SYN sur un
    /// flux existant. Renvoie `false` si le segment doit être ignoré.
    ///
    /// Un flux inconnu n'est créé que par un SYN ou par un segment portant des
    /// données : un ACK seul (par exemple le dernier ACK d'une connexion déjà
    /// fermée) n'apporte rien à suivre.
    fn open_or_check(
        &mut self,
        flow: FlowKey,
        data_seq: u32,
        is_syn: bool,
        has_data: bool,
        now: Duration,
        events: &mut Vec<TcpEvent<'_>>,
    ) -> bool {
        let new_state = FlowState {
            next_seq: data_seq,
            last_seen: now,
            fin_seen: false,
        };

        match self.flows.get(&flow) {
            None => {
                if !is_syn && !has_data {
                    return false;
                }
                if self.flows.len() >= self.config.max_flows {
                    events.push(TcpEvent::FlowLimitReached { flow });
                    return false;
                }
                self.flows.insert(flow, new_state);
                events.push(TcpEvent::Opened {
                    flow,
                    from_syn: is_syn,
                });
                true
            }
            // Un SYN avec un autre numéro de départ que le flux connu.
            Some(state) if is_syn && data_seq != state.next_seq => {
                if state.fin_seen {
                    // L'ancienne connexion est terminée : nouvelle connexion.
                    self.flows.insert(flow, new_state);
                    events.push(TcpEvent::Opened {
                        flow,
                        from_syn: true,
                    });
                    true
                } else {
                    events.push(TcpEvent::IgnoredSyn { flow });
                    false
                }
            }
            Some(_) => true,
        }
    }

    /// RST : ferme les deux sens seulement si son numéro est exactement attendu.
    fn handle_reset(&mut self, flow: FlowKey, seq: u32, events: &mut Vec<TcpEvent<'_>>) {
        let valid = self.flows.get(&flow).is_some_and(|s| s.next_seq == seq);
        if !valid {
            events.push(TcpEvent::IgnoredReset { flow });
            return;
        }
        for closed in [flow, flow.reverse()] {
            // Un sens déjà fermé par un FIN a déjà été signalé comme fermé.
            if let Some(state) = self.flows.remove(&closed) {
                if !state.fin_seen {
                    events.push(TcpEvent::Closed {
                        flow: closed,
                        reason: CloseReason::Reset,
                    });
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
    use crate::parser::TcpFlags;
    use std::net::{IpAddr, Ipv4Addr};

    const CLIENT: u16 = 40000;
    const BROKER: u16 = 1883;
    const T0: Duration = Duration::from_secs(1000);

    /// Construit un segment de 127.0.0.1:`src` vers 127.0.0.1:`dst`.
    /// `flags` contient les lettres des flags levés : S (SYN), F (FIN), R (RST).
    fn seg(
        src: u16,
        dst: u16,
        seq: u32,
        flags: &str,
        payload: &'static [u8],
    ) -> TcpSegment<'static> {
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

    /// Sens client → broker.
    fn c2b() -> FlowKey {
        FlowKey::of(&seg(CLIENT, BROKER, 0, "", b""))
    }

    /// Un réassembleur dont le sens client → broker a vu son SYN (ISN 1000) :
    /// le prochain octet attendu porte donc le numéro 1001.
    fn ouvert() -> Reassembler {
        let mut r = Reassembler::new(Config::default());
        r.process(&seg(CLIENT, BROKER, 1000, "S", b""), T0);
        r
    }

    #[test]
    fn syn_ouvre_le_flux_au_bon_numero() {
        let mut r = Reassembler::new(Config::default());
        assert_eq!(
            r.process(&seg(CLIENT, BROKER, 1000, "S", b""), T0),
            vec![TcpEvent::Opened {
                flow: c2b(),
                from_syn: true
            }]
        );
        // Le SYN consomme le numéro 1000 : les données commencent à 1001.
        assert_eq!(
            r.process(&seg(CLIENT, BROKER, 1001, "", b"abc"), T0),
            vec![TcpEvent::Data {
                flow: c2b(),
                bytes: b"abc"
            }]
        );
    }

    #[test]
    fn les_octets_livres_ne_sont_pas_copies() {
        let mut r = ouvert();
        let segment = seg(CLIENT, BROKER, 1001, "", b"abc");
        let events = r.process(&segment, T0);
        let TcpEvent::Data { bytes, .. } = events[0] else {
            panic!("Data attendu")
        };
        // Même adresse mémoire : c'est un emprunt, pas une copie.
        assert!(std::ptr::eq(bytes, segment.payload));
    }

    #[test]
    fn un_ack_seul_ne_produit_aucun_evenement() {
        let mut r = ouvert();
        assert!(r
            .process(&seg(CLIENT, BROKER, 1001, "", b""), T0)
            .is_empty());
    }

    #[test]
    fn retransmission_complete_est_ignoree() {
        let mut r = ouvert();
        r.process(&seg(CLIENT, BROKER, 1001, "", b"abc"), T0);
        assert_eq!(
            r.process(&seg(CLIENT, BROKER, 1001, "", b"abc"), T0),
            vec![TcpEvent::Retransmission {
                flow: c2b(),
                bytes: 3
            }]
        );
    }

    #[test]
    fn retransmission_partielle_livre_seulement_la_suite() {
        let mut r = ouvert();
        r.process(&seg(CLIENT, BROKER, 1001, "", b"abc"), T0); // octets 1001 à 1003
                                                               // Ce segment recouvre "bc" (déjà reçus) et apporte "de".
        assert_eq!(
            r.process(&seg(CLIENT, BROKER, 1002, "", b"bcde"), T0),
            vec![
                TcpEvent::Retransmission {
                    flow: c2b(),
                    bytes: 2
                },
                TcpEvent::Data {
                    flow: c2b(),
                    bytes: b"de"
                },
            ]
        );
    }

    #[test]
    fn un_trou_est_signale_puis_la_livraison_reprend() {
        let mut r = ouvert();
        r.process(&seg(CLIENT, BROKER, 1001, "", b"abc"), T0); // attendu ensuite : 1004
        assert_eq!(
            r.process(&seg(CLIENT, BROKER, 1010, "", b"xyz"), T0),
            vec![
                TcpEvent::Gap {
                    flow: c2b(),
                    missing: 6
                },
                TcpEvent::Data {
                    flow: c2b(),
                    bytes: b"xyz"
                },
            ]
        );
        // La suite logique (1013) est de nouveau acceptée sans trou.
        assert_eq!(
            r.process(&seg(CLIENT, BROKER, 1013, "", b"!"), T0),
            vec![TcpEvent::Data {
                flow: c2b(),
                bytes: b"!"
            }]
        );
    }

    #[test]
    fn un_flux_peut_etre_pris_en_cours_de_route() {
        let mut r = Reassembler::new(Config::default());
        assert_eq!(
            r.process(&seg(CLIENT, BROKER, 5000, "", b"abc"), T0),
            vec![
                TcpEvent::Opened {
                    flow: c2b(),
                    from_syn: false
                },
                TcpEvent::Data {
                    flow: c2b(),
                    bytes: b"abc"
                },
            ]
        );
    }

    #[test]
    fn les_numeros_de_sequence_peuvent_repasser_par_zero() {
        let mut r = Reassembler::new(Config::default());
        // ISN = 2³² - 2 : les données commencent à 2³² - 1.
        r.process(&seg(CLIENT, BROKER, u32::MAX - 1, "S", b""), T0);
        r.process(&seg(CLIENT, BROKER, u32::MAX, "", b"abc"), T0);
        // 2³² - 1 + 3 = 2 (modulo 2³²) : aucun trou ne doit être signalé.
        assert_eq!(
            r.process(&seg(CLIENT, BROKER, 2, "", b"d"), T0),
            vec![TcpEvent::Data {
                flow: c2b(),
                bytes: b"d"
            }]
        );
    }

    #[test]
    fn fin_ferme_le_sens_une_seule_fois() {
        let mut r = ouvert();
        let fermeture = vec![TcpEvent::Closed {
            flow: c2b(),
            reason: CloseReason::Fin,
        }];
        assert_eq!(
            r.process(&seg(CLIENT, BROKER, 1001, "F", b""), T0),
            fermeture
        );
        // FIN retransmis : rien de nouveau.
        assert!(r
            .process(&seg(CLIENT, BROKER, 1001, "F", b""), T0)
            .is_empty());
    }

    #[test]
    fn la_fermeture_des_deux_sens_libere_la_memoire() {
        let mut r = ouvert();
        r.process(&seg(BROKER, CLIENT, 7000, "S", b""), T0);
        assert_eq!(r.flow_count(), 2);
        r.process(&seg(CLIENT, BROKER, 1001, "F", b""), T0);
        assert_eq!(r.flow_count(), 2, "un seul sens fermé");
        r.process(&seg(BROKER, CLIENT, 7001, "F", b""), T0);
        assert_eq!(r.flow_count(), 0);
    }

    #[test]
    fn rst_au_bon_numero_ferme_les_deux_sens() {
        let mut r = ouvert();
        r.process(&seg(BROKER, CLIENT, 7000, "S", b""), T0);
        assert_eq!(
            r.process(&seg(CLIENT, BROKER, 1001, "R", b""), T0),
            vec![
                TcpEvent::Closed {
                    flow: c2b(),
                    reason: CloseReason::Reset
                },
                TcpEvent::Closed {
                    flow: c2b().reverse(),
                    reason: CloseReason::Reset
                },
            ]
        );
        assert_eq!(r.flow_count(), 0);
    }

    #[test]
    fn rst_forge_avec_un_autre_numero_est_ignore() {
        let mut r = ouvert();
        // Numéro proche mais pas exact : Linux l'ignorerait (RFC 5961 §3.2).
        assert_eq!(
            r.process(&seg(CLIENT, BROKER, 1002, "R", b""), T0),
            vec![TcpEvent::IgnoredReset { flow: c2b() }]
        );
        assert_eq!(r.flow_count(), 1, "le flux est toujours suivi");
    }

    #[test]
    fn syn_forge_sur_un_flux_ouvert_est_ignore() {
        let mut r = ouvert();
        assert_eq!(
            r.process(&seg(CLIENT, BROKER, 9000, "S", b""), T0),
            vec![TcpEvent::IgnoredSyn { flow: c2b() }]
        );
        // Le flux d'origine continue normalement.
        assert_eq!(
            r.process(&seg(CLIENT, BROKER, 1001, "", b"a"), T0),
            vec![TcpEvent::Data {
                flow: c2b(),
                bytes: b"a"
            }]
        );
    }

    #[test]
    fn nouveau_syn_apres_un_fin_ouvre_une_nouvelle_connexion() {
        let mut r = ouvert();
        r.process(&seg(CLIENT, BROKER, 1001, "F", b""), T0);
        assert_eq!(
            r.process(&seg(CLIENT, BROKER, 9000, "S", b""), T0),
            vec![TcpEvent::Opened {
                flow: c2b(),
                from_syn: true
            }]
        );
    }

    #[test]
    fn la_table_de_flux_est_bornee() {
        let mut r = Reassembler::new(Config {
            max_flows: 1,
            ..Config::default()
        });
        r.process(&seg(CLIENT, BROKER, 1000, "S", b""), T0);
        let autre = seg(CLIENT + 1, BROKER, 1000, "S", b"");
        assert_eq!(
            r.process(&autre, T0),
            vec![TcpEvent::FlowLimitReached {
                flow: FlowKey::of(&autre)
            }]
        );
        assert_eq!(r.flow_count(), 1);
    }

    #[test]
    fn les_flux_inactifs_expirent() {
        let mut r = ouvert();
        let delai = Config::default().idle_timeout;
        // Pile au délai : pas encore expiré.
        assert!(r.expire_idle(T0 + delai).is_empty());
        assert_eq!(
            r.expire_idle(T0 + delai + Duration::from_secs(1)),
            vec![TcpEvent::Closed {
                flow: c2b(),
                reason: CloseReason::Idle
            }]
        );
        assert_eq!(r.flow_count(), 0);
    }

    #[test]
    fn un_horodatage_qui_recule_ne_fait_pas_paniquer() {
        let mut r = ouvert();
        assert!(r.expire_idle(T0 - Duration::from_secs(10)).is_empty());
    }

    #[test]
    fn un_ack_seul_n_ouvre_pas_de_flux() {
        let mut r = Reassembler::new(Config::default());
        assert!(r
            .process(&seg(CLIENT, BROKER, 5000, "", b""), T0)
            .is_empty());
        assert_eq!(r.flow_count(), 0);
    }

    #[test]
    fn le_dernier_ack_apres_la_fermeture_ne_rouvre_pas_le_flux() {
        let mut r = ouvert();
        r.process(&seg(BROKER, CLIENT, 7000, "S", b""), T0);
        r.process(&seg(CLIENT, BROKER, 1001, "F", b""), T0);
        r.process(&seg(BROKER, CLIENT, 7001, "F", b""), T0);
        assert_eq!(r.flow_count(), 0);
        // Le client acquitte le FIN du broker : rien de nouveau à suivre.
        assert!(r
            .process(&seg(CLIENT, BROKER, 1002, "", b""), T0)
            .is_empty());
        assert_eq!(r.flow_count(), 0);
    }

    #[test]
    fn un_rst_apres_un_fin_ne_ferme_pas_deux_fois_le_meme_sens() {
        let mut r = ouvert();
        r.process(&seg(BROKER, CLIENT, 7000, "S", b""), T0);
        r.process(&seg(BROKER, CLIENT, 7001, "F", b""), T0); // broker → client fermé
        assert_eq!(
            r.process(&seg(CLIENT, BROKER, 1001, "R", b""), T0),
            vec![TcpEvent::Closed {
                flow: c2b(),
                reason: CloseReason::Reset
            }]
        );
        assert_eq!(r.flow_count(), 0);
    }
}
