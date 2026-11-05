//! Enregistrement des trames capturées dans des fichiers pcap, avec rotation.
//!
//! - **Noms uniques** : chaque fichier est nommé d'après l'horodatage de sa
//!   première trame, en UTC et à la milliseconde, par exemple
//!   `capture-2026-11-05T17-12-30.123Z.pcap`. Un fichier existant n'est
//!   jamais écrasé : en cas de collision, un suffixe `-1`, `-2`... est ajouté.
//! - **Rotation** : un nouveau fichier commence quand le fichier courant
//!   dépasserait [`RecordConfig::file_max_bytes`]. Aucun fichier n'est
//!   supprimé : une capture peut servir de preuve.
//! - **Données sensibles** : en MQTT sans TLS, une capture contient les
//!   identifiants en clair. Le dossier est créé avec les droits `0700` et
//!   chaque fichier avec les droits `0600` (lisibles par leur seul
//!   propriétaire).
//! - **Écriture immédiate** : chaque trame est écrite sur le disque dès sa
//!   réception, pour ne rien perdre en cas d'arrêt brutal.

use std::fmt;
use std::fs::{DirBuilder, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use pcap::{Capture, Linktype, Packet, Savefile};

/// Taille de l'en-tête d'un fichier pcap (pcap-savefile(5)).
const FILE_HEADER_BYTES: u64 = 24;
/// Taille de l'en-tête qui précède chaque trame dans un fichier pcap.
const RECORD_HEADER_BYTES: u64 = 16;

// ===========================================================================
// Configuration, erreurs, avis
// ===========================================================================

/// Réglages de l'enregistrement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordConfig {
    /// Taille maximale d'un fichier, en octets : au-delà, rotation.
    pub file_max_bytes: u64,
}

impl Default for RecordConfig {
    fn default() -> Self {
        RecordConfig {
            file_max_bytes: 100 * 1024 * 1024, // 100 Mio
        }
    }
}

/// Ce que l'enregistreur signale à l'appelant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordNotice {
    /// Un nouveau fichier vient d'être ouvert (premier fichier ou rotation).
    FileOpened(PathBuf),
}

/// Erreur d'enregistrement : système de fichiers ou libpcap.
#[derive(Debug)]
pub enum RecordError {
    Io(io::Error),
    Pcap(pcap::Error),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordError::Io(e) => write!(f, "enregistrement : {e}"),
            RecordError::Pcap(e) => write!(f, "enregistrement : {e}"),
        }
    }
}

impl std::error::Error for RecordError {}

impl From<io::Error> for RecordError {
    fn from(e: io::Error) -> Self {
        RecordError::Io(e)
    }
}

impl From<pcap::Error> for RecordError {
    fn from(e: pcap::Error) -> Self {
        RecordError::Pcap(e)
    }
}

// ===========================================================================
// Enregistreur
// ===========================================================================

/// Le fichier en cours d'écriture.
struct CurrentFile {
    savefile: Savefile,
    path: PathBuf,
    bytes: u64,
}

/// Écrit les trames dans une suite de fichiers pcap d'un même dossier.
pub struct Recorder {
    dir: PathBuf,
    linktype: Linktype,
    config: RecordConfig,
    current: Option<CurrentFile>,
}

impl Recorder {
    /// Prépare l'enregistrement dans `dir`, créé avec les droits `0700` s'il
    /// n'existe pas. `linktype` est le type de lien de la capture d'origine.
    pub fn new(dir: &Path, linktype: Linktype, config: RecordConfig) -> io::Result<Self> {
        DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        Ok(Recorder {
            dir: dir.to_path_buf(),
            linktype,
            config,
            current: None,
        })
    }

    /// Chemin du fichier en cours d'écriture, s'il y en a un.
    pub fn current_path(&self) -> Option<&Path> {
        self.current.as_ref().map(|c| c.path.as_path())
    }

    /// Enregistre une trame. Renvoie un avis quand un nouveau fichier est ouvert.
    pub fn write(&mut self, packet: &Packet<'_>) -> Result<Option<RecordNotice>, RecordError> {
        let record_bytes = RECORD_HEADER_BYTES + u64::from(packet.header.caplen);

        // Rotation : la trame ne tient plus dans le fichier courant.
        let needs_new_file = match &self.current {
            None => true,
            Some(file) => file.bytes + record_bytes > self.config.file_max_bytes,
        };
        let mut notice = None;
        if needs_new_file {
            let path = self.open_new_file(packet)?;
            notice = Some(RecordNotice::FileOpened(path));
        }

        let file = self.current.as_mut().expect("fichier ouvert ci-dessus");
        file.savefile.write(packet);
        // `write` de libpcap garde les données en mémoire : `flush` les écrit
        // sur le disque, et signale une erreur éventuelle (disque plein...).
        file.savefile.flush()?;
        file.bytes += record_bytes;
        Ok(notice)
    }

    /// Crée le fichier suivant, nommé d'après l'horodatage de `first`.
    fn open_new_file(&mut self, first: &Packet<'_>) -> Result<PathBuf, RecordError> {
        let stem = format!("capture-{}", format_utc_millis(packet_time(first)));
        let path = self.create_unique(&stem)?;

        // Le fichier existe déjà (vide, droits 0600) : libpcap l'ouvre pour
        // écrire, ce qui conserve ses droits. Une capture « morte » suffit :
        // elle ne sert qu'à fournir le type de lien à l'en-tête du fichier.
        let savefile = Capture::dead(self.linktype)?.savefile(&path)?;
        self.current = Some(CurrentFile {
            savefile,
            path: path.clone(),
            bytes: FILE_HEADER_BYTES,
        });
        Ok(path)
    }

    /// Crée un fichier vide `stem.pcap` (ou `stem-1.pcap`, `stem-2.pcap`...)
    /// avec les droits 0600, sans jamais écraser un fichier existant.
    fn create_unique(&self, stem: &str) -> io::Result<PathBuf> {
        for n in 0..1000 {
            let name = if n == 0 {
                format!("{stem}.pcap")
            } else {
                format!("{stem}-{n}.pcap")
            };
            let path = self.dir.join(name);
            // `create_new` échoue si le fichier existe : jamais d'écrasement.
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(_) => return Ok(path),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("trop de fichiers nommés {stem}"),
        ))
    }
}

// ===========================================================================
// Dates
// ===========================================================================

/// Horodatage de capture d'une trame (temps écoulé depuis le 1er janvier 1970).
fn packet_time(packet: &Packet<'_>) -> Duration {
    crate::capture::timestamp(packet.header)
}

/// Formate un instant en UTC, à la milliseconde, sous une forme utilisable
/// dans un nom de fichier (sans « : ») : `2026-11-05T17-12-30.123Z`.
pub fn format_utc_millis(since_epoch: Duration) -> String {
    let secs = since_epoch.as_secs();
    let (year, month, day) = civil_from_days(secs / 86_400);
    let in_day = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}-{:02}-{:02}.{:03}Z",
        in_day / 3600,
        in_day % 3600 / 60,
        in_day % 60,
        since_epoch.subsec_millis()
    )
}

/// Convertit un nombre de jours depuis le 1er janvier 1970 en date
/// (année, mois, jour) du calendrier grégorien.
///
/// Algorithme `civil_from_days` de Howard Hinnant (« chrono-Compatible
/// Low-Level Date Algorithms »), restreint aux dates postérieures à 1970.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468; // jours depuis le 1er mars de l'an 0
    let era = z / 146_097; // ères de 400 ans
    let doe = z % 146_097; // jour dans l'ère [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // année dans l'ère
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // jour dans l'année (depuis mars)
    let mp = (5 * doy + 2) / 153; // mois, mars = 0
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

// ===========================================================================
// Tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64, millis: u32) -> Duration {
        Duration::new(secs, millis * 1_000_000)
    }

    #[test]
    fn dates_de_reference() {
        // Valeurs de référence calculées avec la bibliothèque datetime de Python.
        assert_eq!(format_utc_millis(at(0, 0)), "1970-01-01T00-00-00.000Z");
        assert_eq!(
            format_utc_millis(at(1_700_000_000, 1)),
            "2023-11-14T22-13-20.001Z"
        );
        assert_eq!(
            format_utc_millis(at(4_102_444_799, 500)),
            "2099-12-31T23-59-59.500Z"
        );
    }

    #[test]
    fn annees_bissextiles() {
        // 2024 : divisible par 4. 2000 : divisible par 400.
        assert_eq!(
            format_utc_millis(at(1_709_164_800, 0)),
            "2024-02-29T00-00-00.000Z"
        );
        assert_eq!(
            format_utc_millis(at(951_782_400, 999)),
            "2000-02-29T00-00-00.999Z"
        );
    }

    #[test]
    fn le_nom_ne_contient_pas_de_deux_points() {
        // « : » est interdit dans les noms de fichiers sous Windows.
        assert!(!format_utc_millis(at(1_700_000_000, 0)).contains(':'));
    }
}
