//! Tests d'intégration : chaque scénario est écrit dans un vrai fichier pcap,
//! relu par libpcap, puis analysé de bout en bout (capture → parser →
//! réassemblage TCP → décodage MQTT), sans réseau ni privilèges.

mod common;

use std::path::PathBuf;

use rnifler::analyzer::{Analyzer, ChecksumPolicy, Config};
use rnifler::{capture, parser};

/// Écrit le scénario `name` dans un fichier pcap temporaire, le relit avec
/// `capture::open_offline` et renvoie la description de chaque événement.
/// Les scénarios ont des checksums corrects : on les vérifie tous.
fn rejouer(name: &str) -> Vec<String> {
    rejouer_avec(name, ChecksumPolicy::All)
}

fn rejouer_avec(name: &str, checksums: ChecksumPolicy) -> Vec<String> {
    let scenario = common::scenarios()
        .into_iter()
        .find(|s| s.name == name)
        .expect("scénario inconnu");
    let path: PathBuf =
        std::env::temp_dir().join(format!("rnifler-{}-{name}.pcap", std::process::id()));
    common::write_pcap(&path, &scenario.frames).expect("écriture du pcap");

    let mut cap = capture::open_offline(&path, "tcp port 1883").expect("lecture du pcap");
    let mut analyzer = Analyzer::new(Config {
        checksums,
        ..Config::default()
    });
    let mut lignes = Vec::new();
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let now = capture::timestamp(packet.header);
                if let Ok(parser::Parsed::Tcp(segment)) = parser::parse_ethernet(packet.data) {
                    analyzer.process(&segment, now, |event| lignes.push(event.describe(false)));
                }
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => panic!("erreur de lecture : {e}"),
        }
    }
    std::fs::remove_file(&path).ok();
    lignes
}

const PUBLISH_DECODE: &str =
    "MQTT PUBLISH topic=\"labo/temp\" qos=0 retain=0 dup=0 id=- payload=\"21.5\"";

#[test]
fn session_normale() {
    assert_eq!(
        rejouer("session-normale"),
        vec![
            "ouverture du flux (SYN)",
            "ouverture du flux (SYN)",
            "MQTT CONNECT client_id=\"\" (vide : identifiant attribué par le broker) \
             clean_session=1 keep_alive=60s user=- pass=- will=-",
            "MQTT CONNACK code=0 (accepté) session_present=0",
            PUBLISH_DECODE,
            "MQTT DISCONNECT",
            "fermeture du flux (FIN)",
            "fermeture du flux (FIN)",
        ]
    );
}

#[test]
fn message_coupe_decode_une_seule_fois() {
    let lignes = rejouer("message-coupe");
    assert_eq!(lignes.iter().filter(|l| *l == PUBLISH_DECODE).count(), 1);
    assert!(
        !lignes.iter().any(|l| l.contains("ANOMALIE")),
        "{lignes:#?}"
    );
}

#[test]
fn segment_perdu_puis_resynchronisation() {
    let lignes = rejouer("segment-perdu");
    assert_eq!(
        lignes[lignes.len() - 3..],
        [
            "[!] trou : 17 octet(s) jamais observés",
            "décodage MQTT resynchronisé (0 octet(s) ignorés)",
            "MQTT PINGREQ",
        ]
    );
}

#[test]
fn desordre_le_message_en_retard_est_perdu() {
    // Limitation connue : les segments en avance ne sont pas mis en attente.
    let lignes = rejouer("desordre");
    assert_eq!(
        lignes[lignes.len() - 4..],
        [
            "[!] trou : 17 octet(s) jamais observés",
            "décodage MQTT resynchronisé (0 octet(s) ignorés)",
            "MQTT PINGREQ",
            "[!] 17 octet(s) ignorés : déjà reçus, ou arrivés après un trou",
        ]
    );
}

#[test]
fn anomalie_signalee_une_fois() {
    let lignes = rejouer("anomalie");
    assert_eq!(
        lignes.last().unwrap(),
        "[ANOMALIE] flags 0b0000 invalides pour SUBSCRIBE [MQTT-2.2.2-1] (suite du flux ignorée)"
    );
    assert!(!lignes.iter().any(|l| l == "MQTT PINGREQ"));
}

#[test]
fn rst_forge_ignore_et_flux_toujours_decode() {
    let lignes = rejouer("rst-forge");
    assert_eq!(
        lignes[lignes.len() - 2..],
        [
            "[!] RST ignoré (numéro de séquence inattendu, RFC 5961)",
            PUBLISH_DECODE
        ]
    );
}

#[test]
fn topic_piege_neutralise() {
    let lignes = rejouer("topic-piege");
    let derniere = lignes.last().unwrap();
    // Topic "a" + ESC [ 2 J, affiché sous forme inerte ; payload "OK".
    assert!(
        derniere.contains("topic=\"a\\u{1b}[2J\"") && derniere.ends_with("payload=\"OK\""),
        "{derniere}"
    );
    assert!(!lignes.iter().any(|l| l.contains('\u{1b}')));
}

const PUBLISH_FORGE: &str =
    "MQTT PUBLISH topic=\"labo/temp\" qos=0 retain=0 dup=0 id=- payload=\"99.9\"";

#[test]
fn insertion_dejouee_par_la_verification_des_checksums() {
    let lignes = rejouer_avec("insertion-checksum", ChecksumPolicy::All);
    assert_eq!(
        lignes[lignes.len() - 2..],
        [
            "[!] segment au checksum invalide ignoré (la destination le rejette aussi)",
            PUBLISH_DECODE,
        ]
    );
    assert!(!lignes.iter().any(|l| l == PUBLISH_FORGE));
}

#[test]
fn sans_verification_l_insertion_reussit() {
    // Ce que verrait un outil qui ne vérifie pas : le FAUX message, alors que
    // le broker, lui, a rejeté le faux et reçu le vrai.
    let lignes = rejouer_avec("insertion-checksum", ChecksumPolicy::Off);
    assert_eq!(
        lignes[lignes.len() - 2..],
        [
            PUBLISH_FORGE,
            "[!] 17 octet(s) ignorés : déjà reçus, ou arrivés après un trou",
        ]
    );
}

#[test]
fn connexion_deja_ouverte_sans_fausse_anomalie() {
    assert_eq!(
        rejouer("connexion-deja-ouverte"),
        vec![
            "flux pris en cours de route (resynchronisation MQTT)",
            "décodage MQTT resynchronisé (12 octet(s) ignorés)",
            "MQTT PINGREQ",
        ]
    );
}

#[test]
fn chaque_scenario_est_teste() {
    // Protège contre l'ajout d'un scénario sans test correspondant,
    // et vérifie que chaque scénario est décrit.
    let scenarios = common::scenarios();
    assert!(scenarios.iter().all(|s| !s.description.is_empty()));
    let noms: Vec<&str> = scenarios.iter().map(|s| s.name).collect();
    assert_eq!(
        noms,
        [
            "session-normale",
            "message-coupe",
            "segment-perdu",
            "desordre",
            "anomalie",
            "rst-forge",
            "topic-piege",
            "insertion-checksum",
            "connexion-deja-ouverte",
        ]
    );
}
