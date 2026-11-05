//! Tests d'intégration de l'enregistrement : une capture est relue par
//! libpcap, enregistrée par `Recorder`, puis les fichiers produits sont relus
//! et comparés trame par trame à l'original.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use mqtt_sniffer::capture;
use mqtt_sniffer::record::{format_utc_millis, RecordConfig, RecordNotice, Recorder};
use pcap::{Capture, Linktype};

/// Une trame relue : son horodatage et ses octets.
type Trame = (Duration, Vec<u8>);

/// Dossier temporaire propre à un test (supprimé s'il existait déjà).
fn dossier_temporaire(nom: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mqtt-sniffer-rec-{}-{nom}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// Les trames du scénario « session normale », telles que libpcap les relit.
fn trames_originales(dir: &Path) -> (PathBuf, Vec<Trame>) {
    let source = dir.with_extension("source.pcap");
    let scenario = common::scenarios()
        .into_iter()
        .find(|s| s.name == "session-normale")
        .unwrap();
    common::write_pcap(&source, &scenario.frames).unwrap();
    let trames = relire(&source);
    (source, trames)
}

/// Relit toutes les trames d'un fichier pcap.
fn relire(path: &Path) -> Vec<Trame> {
    let mut cap = Capture::from_file(path).unwrap();
    let mut trames = Vec::new();
    while let Ok(packet) = cap.next_packet() {
        trames.push((capture::timestamp(packet.header), packet.data.to_vec()));
    }
    trames
}

/// Enregistre toutes les trames de `source` dans `dir` ; renvoie les avis.
fn enregistrer(source: &Path, dir: &Path, config: RecordConfig) -> Vec<RecordNotice> {
    let mut cap = Capture::from_file(source).unwrap();
    let mut rec = Recorder::new(dir, Linktype::ETHERNET, config).unwrap();
    let mut avis = Vec::new();
    while let Ok(packet) = cap.next_packet() {
        if let Some(notice) = rec.write(&packet).unwrap() {
            avis.push(notice);
        }
    }
    avis
}

/// Les fichiers d'un dossier, triés par nom (donc par date de début).
fn fichiers(dir: &Path) -> Vec<PathBuf> {
    let mut liste: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    liste.sort();
    liste
}

fn nettoyer(dir: &Path, source: &Path) {
    let _ = fs::remove_dir_all(dir);
    let _ = fs::remove_file(source);
}

#[test]
fn les_trames_sont_enregistrees_a_l_identique() {
    let dir = dossier_temporaire("identique");
    let (source, originales) = trames_originales(&dir);
    enregistrer(&source, &dir, RecordConfig::default());

    let fichiers = fichiers(&dir);
    assert_eq!(fichiers.len(), 1);
    assert_eq!(
        relire(&fichiers[0]),
        originales,
        "octets et horodatages identiques"
    );
    nettoyer(&dir, &source);
}

#[test]
fn le_nom_est_l_horodatage_de_la_premiere_trame() {
    let dir = dossier_temporaire("nom");
    let (source, originales) = trames_originales(&dir);
    let avis = enregistrer(&source, &dir, RecordConfig::default());

    let attendu = dir.join(format!(
        "capture-{}.pcap",
        format_utc_millis(originales[0].0)
    ));
    assert_eq!(avis, vec![RecordNotice::FileOpened(attendu.clone())]);
    assert!(attendu.exists());
    nettoyer(&dir, &source);
}

#[test]
fn la_rotation_decoupe_sans_rien_perdre() {
    let dir = dossier_temporaire("rotation");
    let (source, originales) = trames_originales(&dir);
    let config = RecordConfig {
        file_max_bytes: 300,
    };
    enregistrer(&source, &dir, config);

    let fichiers = fichiers(&dir);
    assert!(fichiers.len() > 1, "plusieurs fichiers attendus");
    let mut relues = Vec::new();
    for f in &fichiers {
        assert!(
            fs::metadata(f).unwrap().len() <= 300,
            "{} trop grand",
            f.display()
        );
        relues.extend(relire(f));
    }
    // Mis bout à bout dans l'ordre des noms, les fichiers redonnent la capture.
    assert_eq!(relues, originales);
    nettoyer(&dir, &source);
}

#[test]
fn fichiers_et_dossier_lisibles_par_leur_seul_proprietaire() {
    let dir = dossier_temporaire("droits");
    let (source, _) = trames_originales(&dir);
    enregistrer(&source, &dir, RecordConfig::default());

    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700);
    for f in fichiers(&dir) {
        assert_eq!(mode(&f), 0o600, "{}", f.display());
    }
    nettoyer(&dir, &source);
}

#[test]
fn un_fichier_existant_n_est_jamais_ecrase() {
    let dir = dossier_temporaire("ecrasement");
    let (source, originales) = trames_originales(&dir);
    enregistrer(&source, &dir, RecordConfig::default());
    let premier = fichiers(&dir)[0].clone();

    // Même capture, même dossier : même horodatage, donc même nom de base.
    let avis = enregistrer(&source, &dir, RecordConfig::default());
    let second = premier.with_file_name(format!(
        "{}-1.pcap",
        premier.file_stem().unwrap().to_str().unwrap()
    ));
    assert_eq!(avis, vec![RecordNotice::FileOpened(second.clone())]);
    assert_eq!(
        relire(&premier),
        originales,
        "le premier fichier est intact"
    );
    assert_eq!(relire(&second), originales);
    nettoyer(&dir, &source);
}
