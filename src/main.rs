//! mqtt-sniffer : interface en ligne de commande.
//!
//! Capture le trafic, confie chaque segment TCP à l'analyseur de la
//! bibliothèque et affiche les événements observés. Toute la logique est dans
//! la bibliothèque (`src/lib.rs`) ; ce fichier ne fait que capturer et afficher.

use std::time::Duration;

use clap::Parser as ClapParser; // renommé pour éviter la confusion avec notre module `parser`
use mqtt_sniffer::analyzer::{Analyzer, Config, Event};
use mqtt_sniffer::{capture, parser};
use pcap::Linktype;

/// Sniffer défensif MQTT : décode le trafic MQTT 3.1.1 en clair.
#[derive(ClapParser, Debug)]
#[command(name = "mqtt-sniffer", version, about)]
struct Args {
    /// Interface à écouter (ex. lo, wlp3s0, eth0)
    #[arg(short, long, default_value = "lo")]
    interface: String,

    /// Filtre BPF exécuté dans le noyau (syntaxe tcpdump)
    #[arg(short, long, default_value = "tcp port 1883")]
    filter: String,

    /// Nombre de trames à capturer avant de s'arrêter (0 = illimité)
    #[arg(short, long, default_value_t = 0)]
    count: u64,

    /// Affiche aussi chaque segment TCP capturé (mode détaillé)
    #[arg(long)]
    segments: bool,

    /// Affiche le contenu de chaque segment en hexadécimal (implique --segments)
    #[arg(long)]
    hex: bool,

    /// Affiche les mots de passe MQTT en clair (masqués par défaut)
    #[arg(long)]
    show_secrets: bool,

    /// Liste les interfaces disponibles puis quitte
    #[arg(long)]
    list: bool,
}

fn main() -> Result<(), pcap::Error> {
    let args = Args::parse();

    if args.list {
        for dev in capture::list_interfaces()? {
            println!("{:<16} {}", dev.name, dev.desc.as_deref().unwrap_or("-"));
        }
        return Ok(());
    }

    let mut cap = capture::open_live(&args.interface, &args.filter, 65535, 1000)?;

    // Le parser ne sait lire que des trames qui commencent par un en-tête
    // Ethernet. Sur `any`, libpcap fournit un autre en-tête (Linux SLL) :
    // on refuse proprement plutôt que d'afficher n'importe quoi.
    let linktype = cap.get_datalink();
    if linktype != Linktype::ETHERNET {
        eprintln!(
            "[!] Type de lien {linktype:?} non supporté (Ethernet attendu). \
             Choisis une interface comme lo, wlp0s20f3 ou enp0s31f6."
        );
        return Ok(());
    }

    println!(
        "[*] Écoute sur {} | filtre BPF : \"{}\"",
        args.interface, args.filter
    );

    let mut analyzer = Analyzer::new(Config::default());
    // Horodatage de la première trame : les temps affichés lui sont relatifs.
    let mut start: Option<Duration> = None;
    let mut seen: u64 = 0;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                seen += 1;
                let now = timestamp(packet.header);
                let elapsed = now.saturating_sub(*start.get_or_insert(now));
                handle_frame(&mut analyzer, packet.data, now, elapsed, &args);
                if args.count != 0 && seen >= args.count {
                    break;
                }
            }
            // Pas de trame pendant le délai d'attente : ce n'est pas une erreur.
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Horodatage de capture fourni par libpcap, converti en `Duration`
/// (temps écoulé depuis le 1er janvier 1970).
fn timestamp(header: &pcap::PacketHeader) -> Duration {
    // Les champs de `timeval` sont signés ; une valeur négative est impossible
    // en pratique, et serait remplacée par 0 plutôt que de faire paniquer.
    let secs = u64::try_from(header.ts.tv_sec).unwrap_or(0);
    let micros = u32::try_from(header.ts.tv_usec).unwrap_or(0).min(999_999);
    Duration::new(secs, micros * 1000)
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
) {
    match parser::parse_ethernet(frame) {
        Ok(parser::Parsed::Tcp(seg)) => {
            if args.segments || args.hex {
                println!(
                    "[{}] TCP {}:{} -> {}:{}  [{}]  seq={} ack={} len={}",
                    format_time(elapsed),
                    seg.src_ip,
                    seg.src_port,
                    seg.dst_ip,
                    seg.dst_port,
                    seg.flags,
                    seg.seq,
                    seg.ack,
                    seg.payload.len()
                );
                if args.hex && !seg.payload.is_empty() {
                    print_hex(seg.payload);
                }
            }
            analyzer.process(&seg, now, |event| {
                print_event(elapsed, &event, args.show_secrets)
            });
        }
        Ok(parser::Parsed::Other) => {}
        Err(e) => eprintln!("[{}] [!] {e}", format_time(elapsed)),
    }
}

/// Affiche un événement : temps relatif, sens de connexion, description.
fn print_event(elapsed: Duration, event: &Event<'_>, show_secrets: bool) {
    let flow = event.flow();
    println!(
        "[{}] {} -> {}  {}",
        format_time(elapsed),
        flow.src,
        flow.dst,
        event.describe(show_secrets)
    );
}

/// Temps en secondes, avec la microseconde (même précision que libpcap).
fn format_time(elapsed: Duration) -> String {
    format!("{:>11.6}", elapsed.as_secs_f64())
}

/// Hexdump (offset | hex | ASCII).
fn print_hex(data: &[u8]) {
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
        println!(
            "              {:04x}  {:<47}  {}",
            i * 16,
            hex.join(" "),
            ascii
        );
    }
}
