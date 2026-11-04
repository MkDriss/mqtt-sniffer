//! mqtt-sniffer
//!
//! Ce fichier n'est qu'une interface en ligne de commande : toute la logique
//! vit dans la bibliothèque (`src/lib.rs`), importée ci-dessous.

use clap::Parser as ClapParser; // renommé pour éviter la confusion avec notre module `parser`
use mqtt_sniffer::{capture, mqtt, parser};
use pcap::Linktype;

/// Sniffer défensif MQTT (pédagogique).
#[derive(ClapParser, Debug)]
#[command(name = "mqtt-sniffer", version, about)]
struct Args {
    /// Interface à écouter (ex. lo, wlp3s0, eth0)
    #[arg(short, long, default_value = "lo")]
    interface: String,

    /// Filtre BPF exécuté dans le noyau (syntaxe tcpdump)
    #[arg(short, long, default_value = "tcp port 1883")]
    filter: String,

    /// Nombre de paquets à capturer avant de s'arrêter (0 = illimité)
    #[arg(short, long, default_value_t = 0)]
    count: u64,

    /// Affiche aussi le payload TCP en hexadécimal
    #[arg(long)]
    hex: bool,

    /// N'affiche que les segments qui transportent des données (masque les ACK seuls)
    #[arg(long)]
    mqtt_only: bool,

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

    let mut seen: u64 = 0;
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                seen += 1;
                handle_frame(seen, packet.data, &args);
                if args.count != 0 && seen >= args.count {
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Parse une trame et affiche une ligne de résumé, puis les messages MQTT.
///
/// Une trame malformée n'arrête PAS le programme : pour un outil défensif,
/// un paquet bizarre est une information (peut-être une attaque), pas une
/// raison de planter.
fn handle_frame(n: u64, frame: &[u8], args: &Args) {
    match parser::parse_ethernet(frame) {
        Ok(parser::Parsed::Tcp(seg)) => {
            if args.mqtt_only && seg.payload.is_empty() {
                return;
            }
            println!(
                "#{n:<5} {}:{} -> {}:{}  [{}]  seq={} ack={} len={}",
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
            let touches_mqtt = seg.src_port == mqtt::MQTT_PORT || seg.dst_port == mqtt::MQTT_PORT;
            if touches_mqtt && !seg.payload.is_empty() {
                let direction = if seg.dst_port == mqtt::MQTT_PORT {
                    "client -> broker"
                } else {
                    "broker -> client"
                };
                print_mqtt(seg.payload, direction, args.show_secrets);
            }
        }
        Ok(parser::Parsed::Other) => {
            if !args.mqtt_only {
                println!("#{n:<5} (trame non TCP, ignorée)");
            }
        }
        Err(e) => eprintln!("#{n:<5} [!] {e}"),
    }
}

/// Décode TOUS les messages MQTT présents dans un payload TCP.
///
/// Un segment peut contenir plusieurs messages collés : on avance de
/// `consumed` octets après chacun. Un message coupé en deux segments est

fn print_mqtt(payload: &[u8], direction: &str, show_secrets: bool) {
    let mut offset = 0;
    while offset < payload.len() {
        match mqtt::decode(&payload[offset..]) {
            Ok(mqtt::Decoded::Complete { packet, consumed }) => {
                println!(
                    "        MQTT {direction} : {}",
                    packet.describe(show_secrets)
                );
                offset += consumed;
            }
            Ok(mqtt::Decoded::Incomplete { needed }) => {
                println!(
                    "        MQTT {direction} : message incomplet, il manque au moins \
                     {needed} octet(s)"
                );
                break;
            }
            Err(e) => {
                println!("        MQTT {direction} : [ANOMALIE] {e}");
                break;
            }
        }
    }
}

/// Hexdump (offset | hex | ASCII)
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
        println!("        {:04x}  {:<47}  {}", i * 16, hex.join(" "), ascii);
    }
}
