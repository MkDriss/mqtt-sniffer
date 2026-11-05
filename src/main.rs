//! mqtt-sniffer : interface en ligne de commande.
//!
//! Capture le trafic (interface ou fichier), confie chaque segment TCP à
//! l'analyseur de la bibliothèque et affiche les événements observés. Toute la
//! logique est dans la bibliothèque (`src/lib.rs`) ; ce fichier ne fait que
//! lire, configurer et afficher.

use std::error::Error;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser as ClapParser; // renommé pour éviter la confusion avec notre module `parser`
use clap::ValueEnum;
use mqtt_sniffer::analyzer::{Analyzer, ChecksumPolicy, Config, Event};
use mqtt_sniffer::record::{RecordConfig, RecordNotice, Recorder};
use mqtt_sniffer::{capture, parser};
use pcap::{Activated, Capture, Linktype};

/// Sniffer défensif MQTT : décode le trafic MQTT 3.1.1 en clair.
#[derive(ClapParser, Debug)]
#[command(name = "mqtt-sniffer", version, about)]
struct Args {
    /// Interface à écouter (ex. lo, wlp3s0, eth0)
    #[arg(short, long, default_value = "lo")]
    interface: String,

    /// Lit un fichier de capture (.pcap) au lieu d'écouter une interface
    #[arg(short, long, value_name = "FICHIER", conflicts_with = "interface")]
    read: Option<PathBuf>,

    /// Enregistre les trames dans ce dossier, en fichiers pcap horodatés
    #[arg(short, long, value_name = "DOSSIER")]
    write: Option<PathBuf>,

    /// Taille maximale d'un fichier enregistré, en Mio : au-delà, un nouveau
    /// fichier commence
    #[arg(long, value_name = "MIO", default_value_t = 100,
          value_parser = clap::value_parser!(u64).range(1..))]
    write_max_mb: u64,

    /// Filtre BPF (syntaxe tcpdump)
    #[arg(short, long, default_value = "tcp port 1883")]
    filter: String,

    /// Nombre de trames à lire avant de s'arrêter (0 = illimité)
    #[arg(short, long, default_value_t = 0)]
    count: u64,

    /// Affiche aussi chaque segment TCP capturé (mode détaillé)
    #[arg(long)]
    segments: bool,

    /// Affiche le contenu de chaque segment en hexadécimal (implique --segments)
    #[arg(long)]
    hex: bool,

    /// Vérification des checksums : auto (selon la source), all (tous), off (aucun)
    #[arg(long, value_enum, default_value_t = ChecksumMode::Auto)]
    checksums: ChecksumMode,

    /// Adresse IP de la machine de capture (répétable) : seuls les paquets
    /// qu'elle reçoit sont vérifiés. Indispensable avec --read sur une capture
    /// faite par le broker lui-même.
    #[arg(long = "local-ip", value_name = "IP")]
    local_ip: Vec<IpAddr>,

    /// Affiche les mots de passe MQTT en clair (masqués par défaut)
    #[arg(long)]
    show_secrets: bool,

    /// Liste les interfaces disponibles puis quitte
    #[arg(long)]
    list: bool,
}

/// Choix de l'utilisateur pour la vérification des checksums.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ChecksumMode {
    /// Selon la source : paquets reçus par la machine de capture en direct,
    /// aucun sur loopback, aucun pour un fichier sans --local-ip.
    Auto,
    /// Tous les paquets.
    All,
    /// Aucun paquet.
    Off,
}

/// Point d'entrée. Un « tube fermé » (par exemple `mqtt-sniffer | head`) n'est
/// pas une erreur : le lecteur a simplement fini, on s'arrête sans bruit.
fn main() -> Result<(), Box<dyn Error>> {
    match run_cli() {
        Err(e) if is_broken_pipe(e.as_ref()) => Ok(()),
        other => other,
    }
}

fn is_broken_pipe(error: &(dyn Error + 'static)) -> bool {
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
}

/// Le programme lui-même. `Box<dyn Error>` accepte n'importe quelle erreur :
/// `?` convertit aussi bien une `pcap::Error` qu'une `io::Error`.
fn run_cli() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let mut out = io::stdout().lock();

    if args.list {
        for dev in capture::list_interfaces()? {
            writeln!(
                out,
                "{:<16} {}",
                dev.name,
                dev.desc.as_deref().unwrap_or("-")
            )?;
        }
        return Ok(());
    }

    match &args.read {
        Some(path) => {
            writeln!(
                out,
                "[*] Lecture de {} | filtre BPF : \"{}\"",
                path.display(),
                args.filter
            )?;
            let cap = capture::open_offline(path, &args.filter)?;
            let policy = checksum_policy(&args, None, &mut out)?;
            let seen = run(cap, &args, policy, &mut out)?;
            writeln!(out, "[*] Fin du fichier : {seen} trame(s) lue(s)")?;
        }
        None => {
            writeln!(
                out,
                "[*] Écoute sur {} | filtre BPF : \"{}\"",
                args.interface, args.filter
            )?;
            let cap = capture::open_live(&args.interface, &args.filter, 65535, 1000)?;
            let device = capture::find_interface(&args.interface)?;
            let policy = checksum_policy(&args, Some(device), &mut out)?;
            run(cap, &args, policy, &mut out)?;
        }
    }
    Ok(())
}

/// Lit les trames d'une capture, interface ou fichier, et les analyse.
/// Renvoie le nombre de trames lues.
///
/// `T: Activated` : cette fonction accepte toute capture prête à être lue,
/// `Capture<Active>` (interface) comme `Capture<Offline>` (fichier).
fn run<T: Activated + ?Sized>(
    mut cap: Capture<T>,
    args: &Args,
    checksums: ChecksumPolicy,
    out: &mut impl Write,
) -> Result<u64, Box<dyn Error>> {
    // Le parser ne sait lire que des trames qui commencent par un en-tête
    // Ethernet. Sur `any`, libpcap fournit un autre en-tête (Linux SLL) :
    // on refuse proprement plutôt que d'afficher n'importe quoi.
    let linktype = cap.get_datalink();
    if linktype != Linktype::ETHERNET {
        eprintln!(
            "[!] Type de lien {linktype:?} non supporté (Ethernet attendu). \
             Choisis une interface comme lo, wlp0s20f3 ou enp0s31f6."
        );
        return Ok(0);
    }

    let mut analyzer = Analyzer::new(Config {
        checksums,
        ..Config::default()
    });
    let mut recorder = match &args.write {
        Some(dir) => {
            let config = RecordConfig {
                file_max_bytes: args.write_max_mb * 1024 * 1024,
            };
            writeln!(
                out,
                "[*] Enregistrement dans {} (fichiers de {} Mio au plus, \
                 lisibles par toi seul)",
                dir.display(),
                args.write_max_mb
            )?;
            Some(Recorder::new(dir, linktype, config)?)
        }
        None => None,
    };
    // Horodatage de la première trame : les temps affichés lui sont relatifs.
    let mut start: Option<Duration> = None;
    let mut seen: u64 = 0;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                seen += 1;
                let now = capture::timestamp(packet.header);
                let elapsed = now.saturating_sub(*start.get_or_insert(now));
                // La trame brute est enregistrée AVANT l'analyse : le fichier
                // garde aussi les trames malformées.
                if let Some(rec) = recorder.as_mut() {
                    match rec.write(&packet) {
                        Ok(None) => {}
                        Ok(Some(RecordNotice::FileOpened(path))) => {
                            writeln!(out, "[*] Nouveau fichier : {}", path.display())?;
                        }
                        Err(e) => {
                            // Disque plein, droits... : on arrête d'enregistrer,
                            // mais pas d'analyser.
                            eprintln!("[!] {e} : enregistrement arrêté, l'affichage continue");
                            recorder = None;
                        }
                    }
                }
                handle_frame(&mut analyzer, packet.data, now, elapsed, args, out)?;
                if args.count != 0 && seen >= args.count {
                    break;
                }
            }
            // Pas de trame pendant le délai d'attente : ce n'est pas une erreur.
            Err(pcap::Error::TimeoutExpired) => continue,
            // Fin du fichier de capture.
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(seen)
}

/// Détermine quels paquets doivent avoir des checksums corrects, et l'affiche.
///
/// `live` vaut `Some(interface)` pour une capture en direct, `None` pour un
/// fichier ; l'interface peut elle-même être introuvable (`Some(None)`).
fn checksum_policy(
    args: &Args,
    live: Option<Option<pcap::Device>>,
    out: &mut impl Write,
) -> io::Result<ChecksumPolicy> {
    let (policy, reason) = match args.checksums {
        ChecksumMode::Off => (ChecksumPolicy::Off, "--checksums off"),
        ChecksumMode::All => (ChecksumPolicy::All, "--checksums all"),
        ChecksumMode::Auto if !args.local_ip.is_empty() => (
            ChecksumPolicy::ReceivedBy(args.local_ip.clone()),
            "adresses données par --local-ip",
        ),
        ChecksumMode::Auto => match live {
            None => (
                ChecksumPolicy::Off,
                "fichier : précise --local-ip, ou --checksums all si la capture \
                 vient d'une machine tierce",
            ),
            Some(Some(dev)) if dev.flags.is_loopback() => (
                ChecksumPolicy::Off,
                "interface loopback : le checksum TCP n'y est jamais calculé",
            ),
            Some(Some(dev)) if !dev.addresses.is_empty() => (
                ChecksumPolicy::ReceivedBy(dev.addresses.iter().map(|a| a.addr).collect()),
                "paquets reçus par les adresses de l'interface",
            ),
            Some(_) => (
                ChecksumPolicy::Off,
                "adresses de l'interface inconnues : précise --local-ip",
            ),
        },
    };
    let what = match &policy {
        ChecksumPolicy::Off => "non vérifiés".to_string(),
        ChecksumPolicy::All => "tous vérifiés".to_string(),
        ChecksumPolicy::ReceivedBy(ips) => {
            let list: Vec<String> = ips.iter().map(IpAddr::to_string).collect();
            format!("vérifiés pour les paquets reçus par {}", list.join(", "))
        }
    };
    writeln!(out, "[*] Checksums {what} ({reason})")?;
    Ok(policy)
}

/// Parse une trame, l'affiche si demandé, puis la confie à l'analyseur.
///
/// Une trame malformée n'arrête PAS le programme : pour un outil défensif,
/// un paquet bizarre est une information, pas une raison de planter.
fn handle_frame(
    analyzer: &mut Analyzer,
    frame: &[u8],
    now: Duration,
    elapsed: Duration,
    args: &Args,
    out: &mut impl Write,
) -> io::Result<()> {
    let time = format_time(elapsed);
    match parser::parse_ethernet(frame) {
        Ok(parser::Parsed::Tcp(seg)) => {
            if args.segments || args.hex {
                writeln!(
                    out,
                    "[{time}] TCP {}:{} -> {}:{}  [{}]  seq={} ack={} len={}",
                    seg.src_ip,
                    seg.src_port,
                    seg.dst_ip,
                    seg.dst_port,
                    seg.flags,
                    seg.seq,
                    seg.ack,
                    seg.payload.len()
                )?;
                if args.hex && !seg.payload.is_empty() {
                    write_hex(seg.payload, out)?;
                }
            }
            // Les événements ne vivent que pendant l'appel : on prépare leurs
            // lignes, puis on les écrit (une écriture peut échouer).
            let mut lines = Vec::new();
            analyzer.process(&seg, now, |event| {
                lines.push(format_event(&time, &event, args.show_secrets));
            });
            for line in lines {
                writeln!(out, "{line}")?;
            }
        }
        Ok(parser::Parsed::Other) => {}
        Err(e) => eprintln!("[{time}] [!] {e}"),
    }
    Ok(())
}

/// Une ligne d'affichage : temps relatif, sens de connexion, description.
fn format_event(time: &str, event: &Event<'_>, show_secrets: bool) -> String {
    let flow = event.flow();
    format!(
        "[{time}] {} -> {}  {}",
        flow.src,
        flow.dst,
        event.describe(show_secrets)
    )
}

/// Temps en secondes, avec la microseconde (même précision que libpcap).
fn format_time(elapsed: Duration) -> String {
    format!("{:>11.6}", elapsed.as_secs_f64())
}

/// Hexdump (offset | hex | ASCII).
fn write_hex(data: &[u8], out: &mut impl Write) -> io::Result<()> {
    for (i, chunk) in data.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        writeln!(
            out,
            "              {:04x}  {:<47}  {}",
            i * 16,
            hex.join(" "),
            ascii
        )?;
    }
    Ok(())
}
