//! Module `capture` : tout ce qui dépend de libpcap est isolé ici.
//!
//! Objectif d'architecture : le reste du programme (parsing, réassemblage,
//! décodage MQTT) ne manipule que des tranches d'octets `&[u8]`. Il ne sait
//! pas d'où viennent les paquets.

use pcap::{Active, Capture, Device};

/// Ouvre une capture live sur `interface` et applique le filtre BPF `bpf_filter`.
///
/// Typestate de la crate pcap :
///   `Capture::from_device()` -> `Capture<Inactive>` (on configure)
///   `.open()`                -> `Capture<Active>`   (on lit des paquets)
/// `open(self)` prend `self` PAR VALEUR : la poignée inactive est « consommée »
/// (move), le compilateur interdit donc de la réutiliser après activation.
pub fn open_live(
    interface: &str,
    bpf_filter: &str,
    snaplen: i32,
    timeout_ms: i32,
) -> Result<Capture<Active>, pcap::Error> {
    let mut cap = Capture::from_device(interface)? // Capture<Inactive>
        .snaplen(snaplen) // octets max conservés par paquet
        .timeout(timeout_ms) // next_packet() rend la main après ce délai
        .immediate_mode(true) // livre chaque paquet dès son arrivée
        .open()?; // Capture<Active> (c'est ici qu'il faut les privilèges)

    // Le filtre BPF est compilé par libpcap et exécuté dans le noyau :
    // les paquets non désirés ne remontent jamais jusqu'à notre programme.
    cap.filter(bpf_filter, true)?;

    Ok(cap)
}

/// Liste les interfaces visibles par libpcap (équivalent de `tcpdump -D`).
pub fn list_interfaces() -> Result<Vec<Device>, pcap::Error> {
    Device::list()
}
