//! Fabrication de captures réseau de test (scénarios), au format pcap.
//!
//! Partagé par les tests d'intégration (`tests/replay.rs`) et par l'exemple
//! `examples/scenarios.rs`, qui écrit ces captures sur le disque pour pouvoir
//! les rejouer avec `mqtt-sniffer --read`.
//!
//! Les trames sont construites avec le `PacketBuilder` d'etherparse, qui
//! calcule les longueurs et les checksums IP et TCP : ce sont des trames
//! Ethernet → IPv4 → TCP parfaitement valides.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

use etherparse::PacketBuilder;

// ===========================================================================
// Écriture d'un fichier pcap
// ===========================================================================

/// Écrit des trames Ethernet dans un fichier au format pcap classique
/// (pcap-savefile(5)) : un en-tête de fichier de 24 octets, puis, pour chaque
/// trame, un en-tête de 16 octets suivi des octets de la trame.
///
/// Tous les champs sont écrits en little-endian ; le nombre magique indique
/// cet ordre aux programmes qui lisent le fichier.
pub fn write_pcap(path: &Path, frames: &[(Duration, Vec<u8>)]) -> io::Result<()> {
    let mut file = File::create(path)?;

    // En-tête de fichier.
    file.write_all(&0xa1b2_c3d4_u32.to_le_bytes())?; // nombre magique (microsecondes)
    file.write_all(&2_u16.to_le_bytes())?; // version majeure
    file.write_all(&4_u16.to_le_bytes())?; // version mineure
    file.write_all(&0_i32.to_le_bytes())?; // décalage horaire (inutilisé)
    file.write_all(&0_u32.to_le_bytes())?; // précision (inutilisée)
    file.write_all(&65_535_u32.to_le_bytes())?; // longueur maximale capturée
    file.write_all(&1_u32.to_le_bytes())?; // type de lien : 1 = Ethernet

    // Une trame = en-tête de 16 octets + octets de la trame.
    for (time, frame) in frames {
        let len = u32::try_from(frame.len()).expect("trame trop longue");
        let secs = u32::try_from(time.as_secs()).expect("horodatage trop grand");
        file.write_all(&secs.to_le_bytes())?;
        file.write_all(&time.subsec_micros().to_le_bytes())?;
        file.write_all(&len.to_le_bytes())?; // octets enregistrés
        file.write_all(&len.to_le_bytes())?; // longueur d'origine
        file.write_all(frame)?;
    }
    Ok(())
}

// ===========================================================================
// Messages MQTT utilisés par les scénarios
// ===========================================================================

/// CONNECT de `mosquitto_sub` (client id vide, Clean Session, Keep Alive 60 s).
pub const CONNECT: [u8; 14] = [
    0x10, 0x0c, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00,
];
/// CONNACK : connexion acceptée.
pub const CONNACK: [u8; 4] = [0x20, 0x02, 0x00, 0x00];
/// PUBLISH `labo/temp` = `21.5`, QoS 0.
pub const PUBLISH: [u8; 17] = [
    0x30, 0x0f, 0x00, 0x09, b'l', b'a', b'b', b'o', b'/', b't', b'e', b'm', b'p', b'2', b'1', b'.',
    b'5',
];
pub const PINGREQ: [u8; 2] = [0xc0, 0x00];
pub const DISCONNECT: [u8; 2] = [0xe0, 0x00];
/// SUBSCRIBE dont les flags valent 0000 au lieu de 0010 (paquet malformé).
pub const SUBSCRIBE_MALFORME: [u8; 7] = [0x80, 0x05, 0x00, 0x01, 0x00, 0x01, b'a'];
/// PUBLISH dont le topic contient ESC [ 2 J (« efface l'écran »).
pub const PUBLISH_TOPIC_PIEGE: [u8; 11] = [
    0x30, 0x09, 0x00, 0x05, b'a', 0x1b, b'[', b'2', b'J', b'O', b'K',
];

// ===========================================================================
// Construction d'une conversation TCP
// ===========================================================================

const CLIENT_PORT: u16 = 40000;
const BROKER_PORT: u16 = 1883;
const LOCALHOST: [u8; 4] = [127, 0, 0, 1];

/// Flags TCP d'une trame à construire.
#[derive(Clone, Copy, Default)]
pub struct Flags {
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
}

/// Une connexion entre un client (port 40000) et un broker (port 1883), dont
/// on suit les numéros de séquence pour fabriquer des segments cohérents.
pub struct Conversation {
    client_seq: u32,
    broker_seq: u32,
    time: Duration,
    frames: Vec<(Duration, Vec<u8>)>,
}

impl Conversation {
    /// ISN du client : 1000 ; ISN du broker : 5000.
    pub fn new() -> Self {
        Conversation {
            client_seq: 1000,
            broker_seq: 5000,
            time: Duration::from_secs(1_700_000_000),
            frames: Vec::new(),
        }
    }

    /// Construit une trame du client (`from_client`) ou du broker, sans
    /// l'ajouter à la conversation.
    fn build(&self, from_client: bool, seq: u32, flags: Flags, payload: &[u8]) -> Vec<u8> {
        let (src, dst, ack) = if from_client {
            (CLIENT_PORT, BROKER_PORT, self.broker_seq)
        } else {
            (BROKER_PORT, CLIENT_PORT, self.client_seq)
        };
        let mut builder = PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4(LOCALHOST, LOCALHOST, 64)
            .tcp(src, dst, seq, 65_535);
        if flags.syn {
            builder = builder.syn();
        }
        if flags.fin {
            builder = builder.fin();
        }
        if flags.rst {
            builder = builder.rst();
        }
        if !payload.is_empty() {
            builder = builder.psh();
        }
        // Le tout premier segment (SYN du client) n'acquitte rien : pas d'ACK.
        let builder = if flags.syn && from_client {
            builder
        } else {
            builder.ack(ack)
        };
        let mut frame = Vec::with_capacity(builder.size(payload.len()));
        builder
            .write(&mut frame, payload)
            .expect("écriture en mémoire");
        frame
    }

    /// Ajoute une trame, une milliseconde après la précédente.
    pub fn push(&mut self, frame: Vec<u8>) {
        self.time += Duration::from_millis(1);
        self.frames.push((self.time, frame));
    }

    /// Construit un segment de données du client et avance son numéro de
    /// séquence, SANS l'ajouter : pour simuler une perte ou un désordre.
    pub fn client_segment(&mut self, payload: &[u8]) -> Vec<u8> {
        let frame = self.build(true, self.client_seq, Flags::default(), payload);
        self.client_seq = self.client_seq.wrapping_add(payload.len() as u32);
        frame
    }

    /// Le client envoie des données.
    pub fn client_sends(&mut self, payload: &[u8]) {
        let frame = self.client_segment(payload);
        self.push(frame);
    }

    /// Le broker envoie des données.
    pub fn broker_sends(&mut self, payload: &[u8]) {
        let frame = self.build(false, self.broker_seq, Flags::default(), payload);
        self.broker_seq = self.broker_seq.wrapping_add(payload.len() as u32);
        self.push(frame);
    }

    /// Ouverture TCP en trois temps : SYN, SYN+ACK, ACK.
    pub fn handshake(&mut self) {
        let syn = Flags {
            syn: true,
            ..Flags::default()
        };
        let frame = self.build(true, self.client_seq, syn, b"");
        self.push(frame);
        self.client_seq += 1;
        let frame = self.build(false, self.broker_seq, syn, b"");
        self.push(frame);
        self.broker_seq += 1;
        let frame = self.build(true, self.client_seq, Flags::default(), b"");
        self.push(frame);
    }

    /// Le client envoie un RST avec un numéro de séquence décalé : un RST forgé.
    pub fn forged_client_reset(&mut self, offset: u32) {
        let rst = Flags {
            rst: true,
            ..Flags::default()
        };
        let frame = self.build(true, self.client_seq.wrapping_add(offset), rst, b"");
        self.push(frame);
    }

    /// Fermeture : FIN du client, FIN du broker, dernier ACK du client.
    pub fn close(&mut self) {
        let fin = Flags {
            fin: true,
            ..Flags::default()
        };
        let frame = self.build(true, self.client_seq, fin, b"");
        self.push(frame);
        self.client_seq += 1;
        let frame = self.build(false, self.broker_seq, fin, b"");
        self.push(frame);
        self.broker_seq += 1;
        let frame = self.build(true, self.client_seq, Flags::default(), b"");
        self.push(frame);
    }

    /// Ouverture puis CONNECT / CONNACK : une session MQTT prête.
    pub fn mqtt_session(&mut self) {
        self.handshake();
        self.client_sends(&CONNECT);
        self.broker_sends(&CONNACK);
    }

    pub fn into_frames(self) -> Vec<(Duration, Vec<u8>)> {
        self.frames
    }
}

// ===========================================================================
// Scénarios
// ===========================================================================

/// Une capture de test : un nom de fichier, une description, des trames.
pub struct Scenario {
    pub name: &'static str,
    pub description: &'static str,
    pub frames: Vec<(Duration, Vec<u8>)>,
}

/// Tous les scénarios de test.
pub fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "session-normale",
            description: "connexion, CONNECT, CONNACK, PUBLISH, DISCONNECT, fermeture",
            frames: {
                let mut c = Conversation::new();
                c.mqtt_session();
                c.client_sends(&PUBLISH);
                c.client_sends(&DISCONNECT);
                c.close();
                c.into_frames()
            },
        },
        Scenario {
            name: "message-coupe",
            description: "un PUBLISH réparti sur deux segments TCP",
            frames: {
                let mut c = Conversation::new();
                c.mqtt_session();
                c.client_sends(&PUBLISH[..10]);
                c.client_sends(&PUBLISH[10..]);
                c.close();
                c.into_frames()
            },
        },
        Scenario {
            name: "segment-perdu",
            description: "le segment du PUBLISH n'est jamais capturé, puis un PINGREQ",
            frames: {
                let mut c = Conversation::new();
                c.mqtt_session();
                let _perdu = c.client_segment(&PUBLISH);
                c.client_sends(&PINGREQ);
                c.into_frames()
            },
        },
        Scenario {
            name: "desordre",
            description: "le PINGREQ arrive avant le PUBLISH qui le précède",
            frames: {
                let mut c = Conversation::new();
                c.mqtt_session();
                let publish = c.client_segment(&PUBLISH);
                let pingreq = c.client_segment(&PINGREQ);
                c.push(pingreq);
                c.push(publish);
                c.into_frames()
            },
        },
        Scenario {
            name: "anomalie",
            description: "un SUBSCRIBE malformé, puis un PINGREQ valide",
            frames: {
                let mut c = Conversation::new();
                c.mqtt_session();
                c.client_sends(&SUBSCRIBE_MALFORME);
                c.client_sends(&PINGREQ);
                c.into_frames()
            },
        },
        Scenario {
            name: "rst-forge",
            description: "un RST au numéro de séquence décalé, puis un PUBLISH",
            frames: {
                let mut c = Conversation::new();
                c.mqtt_session();
                c.forged_client_reset(1);
                c.client_sends(&PUBLISH);
                c.into_frames()
            },
        },
        Scenario {
            name: "topic-piege",
            description: "un PUBLISH dont le topic contient une séquence d'échappement",
            frames: {
                let mut c = Conversation::new();
                c.mqtt_session();
                c.client_sends(&PUBLISH_TOPIC_PIEGE);
                c.into_frames()
            },
        },
        Scenario {
            name: "connexion-deja-ouverte",
            description: "capture démarrée en cours de connexion, au milieu d'un message",
            frames: {
                let mut c = Conversation::new();
                let _debut_manque = c.client_segment(&PUBLISH[..5]);
                c.client_sends(&PUBLISH[5..]);
                c.client_sends(&PINGREQ);
                c.into_frames()
            },
        },
    ]
}
