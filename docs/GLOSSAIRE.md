# Glossaire du projet mqtt-sniffer

Termes techniques utilisés dans le code et la documentation du projet,
classés par thème.
Chaque définition renvoie à sa source (liste numérotée en fin de document).
Les mentions « *(explication personnelle)* » signalent une définition
pédagogique non tirée d'une source primaire.

---

## 1. Bases : données et représentation

**Bit** — Unité d'information valant 0 ou 1. Dans les spécifications réseau,
les bits d'un octet sont numérotés de 7 (poids fort) à 0 (poids faible) [MQTT].

**Octet (byte)** — Groupe de 8 bits. Unité de base de toutes les longueurs
dans les en-têtes réseau. *(explication personnelle)*

**Hexadécimal** — Écriture en base 16 (chiffres 0-9 puis a-f). Un octet
s'écrit avec exactement deux chiffres hexadécimaux : `ff` = 255, `0a` = 10.
*(explication personnelle)*

**Big-endian (ordre réseau)** — Les entiers de plusieurs octets sont transmis
octet de poids fort en premier. Exemple MQTT : un entier 16 bits est envoyé
MSB puis LSB [MQTT, §1.5.2].

**TLV (Type-Longueur-Valeur)** — Format où chaque élément commence par son
type, puis sa longueur, puis ses données. Permet à un parseur de *sauter* un
élément inconnu. Utilisé par les options TCP [IANA-TCP].

---

## 2. Capture de paquets

**Sniffer** — Programme qui copie et analyse le trafic réseau qui passe par
une interface. *(explication personnelle)*

**libpcap** — Bibliothèque C de capture de paquets, utilisée par tcpdump et
Wireshark. La crate Rust `pcap` en est un binding [PCAP-RS].

**Interface réseau** — Point de connexion du système au réseau (`wlp0s20f3`
pour le Wi-Fi, `enp0s31f6` pour l'Ethernet, `lo` pour le loopback).
*(explication personnelle)*

**Fichier pcap** — Format de fichier de capture de libpcap : un en-tête de
24 octets (nombre magique `0xa1b2c3d4`, type de lien...), puis chaque trame
précédée d'un en-tête de 16 octets (horodatage, longueurs) [PCAP-SAVEFILE].

**Rotation de fichiers** — Passage à un nouveau fichier de capture quand le
fichier courant atteint une taille donnée (`--write-max-mb`), pour garder des
fichiers de taille raisonnable. *(explication personnelle)*

**Droits Unix `0600` / `0700`** — Droits d'accès en notation octale : `6`
(lecture et écriture) ou `7` (avec exécution, nécessaire pour entrer dans un
dossier) pour le propriétaire, `0` (aucun droit) pour le groupe et les autres
utilisateurs. *(explication personnelle)*

**UTC** — Temps universel coordonné : heure de référence sans fuseau horaire
ni heure d'été, utilisée dans les noms de fichiers pour qu'ils restent uniques
et triables. Le calcul de la date utilise l'algorithme `civil_from_days` de
Howard Hinnant [HINNANT-DATES]. *(explication personnelle pour la définition)*

**Loopback (`lo`)** — Interface virtuelle qui relie la machine à elle-même
(adresse 127.0.0.1). Sous Linux, elle fournit un faux en-tête Ethernet aux
outils de capture [TCPDUMP-LO].

**Linktype / DLT** — Code indiquant par quel en-tête commencent les paquets
capturés. `DLT_EN10MB` (valeur 1) = Ethernet ; l'interface `any` utilise
`DLT_LINUX_SLL`, sans en-tête MAC [TCPDUMP-ANY].

**BPF (Berkeley Packet Filter)** — Petite machine virtuelle dans le noyau
qui filtre les paquets *avant* leur copie vers le programme. Décrit par
McCanne et Jacobson en 1993 [BPF-1993]. Sous Linux : LSF [KERNEL-BPF].

**Filtre BPF** — Expression comme `tcp port 1883`, compilée par libpcap en
bytecode BPF puis chargée dans le noyau [KERNEL-BPF].

**Mode promiscuous** — Mode où la carte réseau transmet au système toutes
les trames qu'elle voit, et pas seulement celles qui lui sont adressées.
Ne suffit pas à voir le trafic des autres sur un réseau commuté (switch)
[WS-ETH].

**Switch (commutateur)** — Équipement qui n'envoie sur chaque port que le
trafic destiné à la machine branchée dessus (plus broadcast et multicast)
[WS-ETH].

**Port miroir (SPAN)** — Configuration d'un switch qui copie le trafic d'autres
ports vers un port d'analyse [TCPDUMP-SPAN].

**Capability Linux** — Fraction des privilèges root, attribuable à un binaire.
`CAP_NET_RAW` permet d'ouvrir des sockets RAW et PACKET [CAPS] ; c'est la seule
nécessaire pour ce sniffer sans mode promiscuous [PACKET7].

**setcap** — Commande qui attache des capabilities à un fichier exécutable.
Elles sont perdues à chaque recompilation (nouveau fichier) [SETCAP-REBUILD].

---

## 3. Couche liaison : Ethernet

**Trame (frame)** — Unité de données de la couche liaison (Ethernet).
*(explication personnelle)*

**Adresse MAC** — Identifiant matériel de 6 octets d'une carte réseau.
Mises à zéro sur le loopback Linux. *(explication personnelle)*

**EtherType** — Champ de 2 octets de l'en-tête Ethernet indiquant le protocole
transporté : 0x0800 = IPv4, 0x0806 = ARP, 0x86DD = IPv6 [ETHERTYPE].

**NIC (Network Interface Card)** — Carte réseau physique.
*(explication personnelle)*

---

## 4. Couche réseau : IPv4

**Paquet (datagramme IP)** — Unité de données de la couche réseau.
*(explication personnelle)*

**IHL (Internet Header Length)** — Longueur de l'en-tête IPv4 en mots de
32 bits (minimum 5, soit 20 octets) [RFC791].

**Total Length** — Longueur totale du datagramme IP, en-tête et données
compris, en octets [RFC791].

**DF (Don't Fragment)** — Flag interdisant aux routeurs de découper le
paquet [RFC791].

**TTL (Time To Live)** — Durée de vie maximale du paquet ; décrémenté à chaque
routeur, le paquet est détruit à 0 [RFC791].

**Protocol** — Numéro du protocole transporté par IP : 6 = TCP [RFC791].

**Fragmentation IP** — Découpage d'un datagramme IP en plusieurs fragments,
recomposés par la destination ; les champs Identification, flags (dont DF)
et Fragment Offset de l'en-tête IPv4 servent à ce découpage [RFC791].

**Routeur** — Équipement qui achemine les paquets d'un réseau à un autre.
*(explication personnelle)*

---

## 5. Couche transport : TCP

**Segment** — Unité de données TCP : un en-tête suivi éventuellement de
données [RFC9293].

**Port** — Numéro 16 bits identifiant une application sur une machine
(1883 = MQTT). *(explication personnelle)*

**Flux d'octets (byte stream)** — TCP livre une suite ordonnée d'octets, pas
des messages : un message applicatif peut être coupé en plusieurs segments
ou plusieurs messages peuvent partager un segment [RFC9293].

**Numéro de séquence** — Numéro du premier octet de données du segment. Avec
SYN, c'est l'ISN, et le premier octet de données porte ISN+1 [RFC9293].

**ISN (Initial Sequence Number)** — Numéro de séquence initial, choisi à
l'ouverture de la connexion [RFC9293].

**ACK / numéro d'acquittement** — Prochain numéro de séquence que l'émetteur
s'attend à recevoir, c'est-à-dire « j'ai tout reçu jusque-là » [RFC9293].

**Flags TCP** — Bits de contrôle : CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
[RFC9293]. SYN = ouverture, FIN = fermeture propre, RST = coupure brutale,
PSH = « transmets à l'application sans attendre ».

**Handshake en trois temps** — Ouverture d'une connexion TCP :
SYN → SYN+ACK → ACK. *(explication personnelle)*

**Fermeture en quatre temps** — Fermeture propre d'une connexion TCP : chaque
côté envoie son FIN et reçoit un ACK (FIN → ACK, puis FIN → ACK). Comme le SYN,
le FIN consomme un numéro de séquence (observable dans une capture).
*(explication personnelle)*

**Quadruplet (4-tuple)** — Le couple (IP source, port source, IP destination,
port destination) qui identifie de façon unique une connexion TCP.
*(explication personnelle)*

**Flux (sens de connexion)** — Les octets envoyés par une extrémité d'une
connexion TCP à l'autre. Une connexion en comporte deux, indépendants, chacun
avec ses propres numéros de séquence (`FlowKey` dans `src/tcp.rs`).
*(explication personnelle)*

**Retransmission** — Nouvel envoi de données déjà envoyées, en l'absence
d'acquittement ; ses octets déjà reçus sont ignorés par le réassemblage.
*(explication personnelle)*

**Trou (gap)** — Octets d'un flux jamais observés, parce qu'un segment manque
ou arrive en retard ; le réassemblage reprend au segment suivant.
*(explication personnelle)*

**Arithmétique modulo 2³²** — Les numéros de séquence font 32 bits et
repassent par zéro ; on les compare par différence modulo 2³²
(`wrapping_sub` en Rust) [RFC9293].

**Réinitialisation aveugle (blind reset)** — Attaque qui coupe une connexion
avec un RST forgé. Depuis la RFC 5961, un RST n'est accepté que si son numéro
de séquence est exactement le prochain attendu ; sinon le destinataire
répond par un *challenge ACK* [RFC5961] [LINUX-RFC5961].

**Data offset** — Longueur de l'en-tête TCP en mots de 32 bits ; indique où
commencent les données [RFC9293].

**Fenêtre de réception (window)** — Quantité de données que le récepteur
accepte avant acquittement. Champ de 16 bits, donc 64 Kio maximum sans
extension [RFC7323].

**Options TCP** — Champs facultatifs ajoutés après les 20 octets fixes de
l'en-tête, au format TLV (sauf kinds 0 et 1, d'un seul octet) [IANA-TCP].

**MSS (Maximum Segment Size, kind 2)** — Taille maximale des *données* d'un
segment que l'émetteur de l'option peut recevoir [RFC9293].

**SACK (Selective Acknowledgment, kinds 4 et 5)** — Acquittement sélectif qui
indique précisément quels segments sont arrivés après un trou [RFC7323, §1.1].

**Timestamps (kind 8)** — Option portant TSval (horloge de l'émetteur) et
TSecr (écho de la dernière valeur reçue) ; TSecr vaut 0 quand ACK n'est pas
levé [RFC7323, §3.2].

**RTT (Round-Trip Time)** — Temps d'un aller-retour entre deux machines.
*(explication personnelle)*

**RTTM (Round-Trip Time Measurement)** — Mesure du RTT grâce aux
timestamps [RFC7323, §4].

**RTO (Retransmission TimeOut)** — Délai au bout duquel TCP retransmet un
segment non acquitté [RFC7323].

**PAWS (Protection Against Wrapped Sequences)** — Rejet des vieux segments
dupliqués grâce aux timestamps, quand les numéros de séquence 32 bits
« font le tour » [RFC7323, §5].

**Window Scale (kind 3)** — Exposant (0 à 14) multipliant la fenêtre par une
puissance de 2. Jamais appliqué à la fenêtre d'un SYN [RFC7323, §2].

**NOP (kind 1)** — Octet de bourrage servant à aligner les options sur
4 octets [IANA-TCP] [RFC7323, annexe A].

**Fingerprinting (prise d'empreinte)** — Identification d'un système
d'exploitation par les particularités de son trafic, par exemple la
combinaison et l'ordre de ses options TCP [RFC7323, §7.1].

---

## 6. Intégrité : checksums et offload

**Checksum (somme de contrôle)** — Valeur calculée sur des données pour
détecter une corruption *accidentelle*. N'apporte aucune protection contre
un attaquant, qui peut la recalculer. *(explication personnelle)*

**Checksum Internet** — Complément à un de la somme en complément à un des
mots de 16 bits ; le champ checksum vaut 0 pendant le calcul. À la
vérification, la somme totale doit valoir 0xFFFF [RFC1071].

**Complément à un** — Inversion de tous les bits d'un nombre. L'addition en
complément à un réinjecte la retenue qui déborde (*end-around carry*)
[RFC1071].

**Checksum IP** — Ne couvre que l'en-tête IPv4 ; recalculé à chaque routeur
car le TTL change [RFC791]. IPv6 n'en a pas [BORTZ-1071].

**Pseudo-en-tête** — Champs ajoutés pour le calcul du checksum TCP mais non
transmis : adresses source et destination, protocole, longueur TCP [RFC9293].

**Pseudo-en-tête IPv6** — Version IPv6 du pseudo-en-tête TCP : adresses de
128 bits, longueur sur 32 bits, puis le numéro du protocole ; avec un en-tête
de routage, c'est l'adresse de destination finale qui est utilisée
[RFC8200, §8.1].

**Politique de vérification des checksums** — Choix des segments qui doivent
avoir des checksums corrects pour être analysés : aucun, tous, ou seulement
ceux reçus par la machine de capture, dont les paquets émis ont des checksums
faussés par l'offload (`analyzer::ChecksumPolicy`). *(explication
personnelle)*

**Offload du checksum** — Délégation du calcul des checksums à la carte
réseau. Les paquets *émis* par la machine qui capture sont vus avant ce
calcul et portent seulement la somme du pseudo-en-tête [WS-OFFLOAD]. Le
loopback ne calcule jamais le checksum TCP [HARRIS-LO]. Les paquets reçus
depuis le câble ne sont pas concernés [PL-CHECKSUM].

---

## 7. MQTT

**MQTT** — Protocole de messagerie publish/subscribe léger, conçu pour l'IoT,
fonctionnant au-dessus de TCP [MQTT].

**Broker (serveur)** — Intermédiaire qui reçoit les messages publiés et les
retransmet aux clients abonnés (ici : Mosquitto) [MQTT, §1.2].

**Client** — Programme ou objet qui se connecte au broker pour publier
et/ou s'abonner [MQTT, §1.2].

**Topic** — Libellé hiérarchique d'un message (`labo/temp`) ; niveaux séparés
par `/` [MQTT, §1.2].

**Wildcard `#`** — Joker multi-niveaux d'un filtre d'abonnement ; doit être
le dernier caractère (`labo/#`) [MQTT, §4.7.1.2].

**Paquet de contrôle** — Unité MQTT : en-tête fixe, puis en-tête variable et
payload selon le type. Types utilisés ici : CONNECT 1, CONNACK 2, PUBLISH 3,
PUBACK 4, PUBREC 5, PUBREL 6, PUBCOMP 7, SUBSCRIBE 8, SUBACK 9, PINGREQ 12,
PINGRESP 13, DISCONNECT 14 [MQTT, §2.2.1].

**Remaining Length** — Nombre d'octets restants après l'en-tête fixe, codé
sur 1 à 4 octets avec un bit de continuation [MQTT, §2.2.3]. Sert à
redécouper le flux TCP en messages.

**Packet Identifier** — Numéro 16 bits liant un message à son acquittement ;
absent des PUBLISH en QoS 0 [MQTT, §2.3.1].

**Payload** — Données utiles d'un paquet ; pour PUBLISH, le message
applicatif, dont MQTT ignore le format [MQTT].

**QoS (Quality of Service)** — Garantie de livraison : 0 = au plus une fois,
1 = au moins une fois (PUBACK), 2 = exactement une fois
(PUBREC/PUBREL/PUBCOMP) [MQTT, §3.3.4]. Négociée par tronçon : un abonné reçoit
au plus la QoS de son abonnement [MQTT, §3.8.4].

**Client Identifier** — Identifiant du client dans le CONNECT. S'il est vide,
le broker en attribue un [MQTT, §3.1.3.1].

**Clean Session** — Flag du CONNECT : à 1, le broker ne conserve aucun état
après la déconnexion [MQTT, §3.1.2.4].

**Keep Alive** — Intervalle maximal (en secondes) entre deux paquets d'un
client ; en l'absence de trafic, le client envoie un PINGREQ
[MQTT, §3.1.2.10].

**Session** — État conservé entre un client et le broker (abonnements,
messages QoS 1/2 en attente), éventuellement sur plusieurs connexions
[MQTT, §1.2].

**Will (message testament)** — Message déposé dans le CONNECT, que le broker
publie si le client disparaît sans envoyer de DISCONNECT [MQTT, §3.1.2.5].

**Session Present** — Bit du CONNACK indiquant si le broker avait déjà un état
de session pour ce client [MQTT, §3.2.2.2].

**Rétrogradation de QoS** — Le broker relaie un message avec la plus petite des
deux QoS : celle de la publication et celle de l'abonnement. Exemple : un
message publié en QoS 1 est relayé en QoS 0 à un client abonné en QoS 0
[MQTT, §3.8.4].

**Idempotent** — Se dit d'une commande qui a le même effet exécutée une ou
plusieurs fois (« ON » l'est, « bascule » ne l'est pas). Important en QoS 1.
*(explication personnelle)*

**Local only mode** — Comportement de Mosquitto ≥ 2.0 sans listener
configuré : écoute uniquement sur le loopback, connexions anonymes acceptées
[MOSQ-2].

---

## 8. Rust

**Crate** — Plus petite unité que le compilateur Rust traite ; binaire (avec
`main`) ou bibliothèque [RUST-BOOK, ch. 7.1].

**Package** — Ensemble d'un ou plusieurs crates décrit par un `Cargo.toml` ;
au plus une bibliothèque, autant de binaires que voulu [RUST-BOOK, ch. 7.1].

**Module** — Subdivision d'un crate (`mod parser;` → `src/parser.rs`)
[RUST-BOOK, ch. 7].

**Nom du crate bibliothèque** — Nom du package avec les tirets remplacés par
des underscores : `mqtt-sniffer` → `mqtt_sniffer` [CARGO-TARGETS].

**Ownership / move** — Chaque valeur a un unique propriétaire ; passer une
valeur par valeur (`self`) la *déplace*, l'ancienne variable devient
inutilisable. Exemple : `Capture::open(self)` [PCAP-RS].

**Typestate** — Encodage de l'état d'un objet dans son type
(`Capture<Inactive>` → `Capture<Active>`) pour interdire à la compilation les
appels dans le mauvais ordre [PCAP-RS].

**Référence / emprunt (`&`)** — Accès à une valeur sans en prendre la
propriété. *(explication personnelle)*

**Slice (`&[u8]`)** — Vue (pointeur + longueur) sur une suite d'octets
appartenant à quelqu'un d'autre ; aucune copie. *(explication personnelle)*

**Zéro-copie** — Traitement des données sur place, via des slices, sans les
dupliquer en mémoire. *(explication personnelle)*

**Durée de vie (lifetime, `'a`)** — Portée pendant laquelle une référence est
valide ; les annotations décrivent les relations entre durées de vie sans
les modifier [RUST-BOOK, ch. 10.3].

**Enum** — Type « l'un OU l'autre », dont chaque variante peut porter des
données (`Parsed::Tcp(segment)`). *(explication personnelle)*

**`match`** — Expression qui compare une valeur à des motifs ; elle doit
couvrir tous les cas possibles (exhaustivité), `_` servant de cas par
défaut [RUST-BOOK, ch. 6.2].

**`Result<T, E>`** — Enum `Ok(T)` (succès) ou `Err(E)` (échec) [RUST-BOOK,
ch. 9.2].

**`Option<T>`** — Enum `Some(T)` (valeur présente) ou `None` (absente)
[RUST-BOOK, ch. 6.2].

**Opérateur `?`** — Extrait la valeur d'un `Ok`, ou renvoie immédiatement
l'`Err` à l'appelant [RUST-BOOK, ch. 9.2].

**Trait** — Ensemble de comportements qu'un type peut implémenter (`Display`
pour l'affichage, `Error` pour les erreurs). *(explication personnelle)*

**`#[derive(...)]`** — Demande au compilateur de générer automatiquement
l'implémentation de certains traits (`Debug`, `Clone`, `PartialEq`...).
*(explication personnelle)*

**`let … else`** — Instruction qui lie des variables si un motif correspond, et
sinon exécute un bloc qui doit quitter la portée (`return`, `break`,
`panic!`). Stable depuis Rust 1.65 [RUST-BY-EXAMPLE].

**`str::from_utf8`** — Convertit une slice d'octets en `&str` après avoir
vérifié que c'est de l'UTF-8 valide, sans copier les octets [RUST-STD-STR].

**Curseur (reader)** — Structure qui mémorise une position dans un buffer et
lit les champs les uns après les autres en vérifiant les limites
(`Reader` dans `src/mqtt/reader.rs`). *(explication personnelle)*

**Avertissement (warning)** — Message du compilateur qui n'empêche pas la
compilation mais signale un problème probable (import inutilisé, branche
inatteignable...). Objectif du projet : zéro avertissement. *(explication
personnelle)*

**Branche inatteignable (unreachable pattern)** — Branche d'un `match` qu'aucune
valeur ne peut atteindre, parce qu'une branche précédente attrape déjà les mêmes
valeurs ; les branches sont testées dans l'ordre [RUST-BOOK, ch. 6.2].

**Fourre-tout (catch-all)** — Dernière branche d'un `match` (`_` ou un nom de
variable comme `other`) qui accepte toute valeur. Elle rend le `match`
exhaustif, mais empêche le compilateur de signaler une branche oubliée.
*(explication personnelle)*

**`use` / conflit de noms** — `use` crée un raccourci vers un chemin. Rust
refuse d'importer deux éléments portant le même nom dans une même portée ;
on lève l'ambiguïté avec le chemin complet (`PacketType::PubAck`) ou un alias
`as` [RUST-BOOK, ch. 7.4].

**`todo!()`** — Macro qui marque du code inachevé : le programme compile, mais
panique toujours si ce code est exécuté [RUST-STD-TODO].

**Construction d'une structure (struct literal)** — `Nom { champ: valeur }`,
accolades directement après le nom ; des parenthèses `Nom(...)` désignent un
appel ou une variante d'enum transportant une donnée [RUST-BOOK, ch. 5.1].

**`str::escape_debug`** — Méthode qui remplace les caractères non
imprimables d'une chaîne par une écriture inerte (`\u{1b}`…). Utilisée par
`show_text` pour neutraliser les chaînes venues du réseau. *(explication
personnelle, comportement vérifié par test)*

**Test de mutation** — Vérification qu'un test détecte bien un défaut : on
réintroduit volontairement le défaut et on contrôle que le test échoue.
*(explication personnelle)*

**Closure** — Fonction anonyme, qu'on peut passer en argument à une autre
fonction (comme une lambda en Java). `StreamDecoder::feed` reçoit une closure
qu'il appelle pour chaque événement observé. *(explication personnelle)*

**`const` (constante)** — Valeur fixée à la compilation et recopiée à chaque
endroit où elle est utilisée : deux références à la même constante n'ont pas
forcément la même adresse mémoire [RUST-REF-CONST].

**Test d'intégration** — Test placé dans le dossier `tests/`, compilé comme un
programme séparé qui n'utilise que l'interface publique de la bibliothèque ;
le code partagé entre tests va dans `tests/common/mod.rs` [RUST-BOOK, ch. 11.3].

**Scénario de test** — Capture fabriquée pour reproduire une situation précise
(perte, désordre, RST forgé...), rejouable avec `--read`
(`tests/common/mod.rs`). *(explication personnelle)*

**`Box<dyn Error>`** — Type qui peut contenir n'importe quelle erreur ;
l'opérateur `?` y convertit automatiquement une `pcap::Error` comme une
`io::Error`. *(explication personnelle)*

**Tube fermé (broken pipe)** — Erreur reçue en écrivant dans un tube dont le
lecteur s'est arrêté (`mqtt-sniffer ... | head`) ; le sniffer la traite comme
une fin normale. *(explication personnelle)*

**Version minimale de Rust (MSRV)** — Plus ancienne version du compilateur
capable de compiler le projet, déclarée par `rust-version` dans
`Cargo.toml` (1.88 ici). *(explication personnelle)*

**Test unitaire** — Fonction `#[test]` placée dans un module `#[cfg(test)]`
du même fichier, compilée seulement par `cargo test` [RUST-BOOK, ch. 11.3].

---

## 9. Sécurité

**Analyse passive** — Observation du trafic sans y participer, comme le fait
ce sniffer. L'outil ne voit pas forcément le trafic exactement comme la
machine destinataire le traite [PTACEK-1998].

**Insertion** — Attaque contre un outil d'analyse passive : lui faire accepter
un paquet que la destination rejettera (par exemple un segment au checksum
invalide), pour qu'il affiche un contenu que la destination n'a jamais reçu
[PTACEK-1998].

**Évasion** — Attaque inverse de l'insertion : l'outil d'analyse ignore un
paquet que la destination, elle, accepte [PTACEK-1998].

**Injection de séquences d'échappement (CWE-150)** — Faille où des données
non fiables contenant des séquences de contrôle (commençant par ESC, `0x1b`)
sont affichées telles quelles : le terminal les interprète comme des
commandes (effacer l'écran, déplacer le curseur, changer le titre)
[CWE-150].

**Caractère d'inversion bidirectionnelle (U+202E)** — Caractère Unicode qui
inverse le sens d'affichage du texte qui le suit ; il permet de falsifier ce
que l'utilisateur lit. Ce n'est pas un « caractère de contrôle » au sens de
`char::is_control`, d'où l'usage de `escape_debug`. *(explication
personnelle)*

**Sécurité par défaut** — Principe selon lequel le comportement obtenu sans
réglage particulier est le plus sûr (ex. mots de passe masqués sauf
`--show-secrets`) [OWASP-DEVGUIDE].

**IANA** — Organisme qui tient les registres officiels des numéros de
protocoles (EtherTypes, options TCP, ports...) [IANA-TCP].

**RFC (Request for Comments)** — Documents de l'IETF qui définissent les
protocoles Internet (RFC 791 = IPv4, RFC 9293 = TCP). *(explication
personnelle)*

---

## 10. Conception logicielle

**Framing (découpage en trames applicatives)** — Opération qui consiste à
retrouver où commence et où finit chaque message applicatif dans un flux
d'octets. En MQTT, c'est le champ Remaining Length qui le permet [MQTT, §2.2.3].

**Réassemblage TCP** — Reconstitution, connexion par connexion, du flux
d'octets transporté par plusieurs segments, afin d'y appliquer le framing.
*(explication personnelle)*

**Resynchronisation** — Recherche du début d'un message dans un flux dont on
a perdu le découpage (après un trou, ou sur un flux pris en cours de route) :
chaque nouveau bloc est essayé depuis son début, et le premier message complet
décodé rétablit le flux. C'est une heuristique. *(explication personnelle)*

**Budget mémoire** — Quantité totale de mémoire que l'ensemble des décodeurs
peut utiliser pour garder des messages incomplets (`MemoryBudget`) ; il borne
la mémoire consommée quelles que soient les données reçues. *(explication
personnelle)*

**Événement** — Constat signalé par l'analyse (message MQTT décodé, trou,
fermeture de flux, anomalie...) ; l'appelant décide quoi en faire, par
exemple l'afficher (`analyzer::Event`). *(explication personnelle)*

**Horodatage de capture** — Instant de capture d'une trame, fourni par
libpcap avec la précision de la microseconde [PCAP-RS].

---

## Sources

- **[BORTZ-1071]** S. Bortzmeyer, « RFC 1071 : Computing the Internet checksum ». https://www.bortzmeyer.org/1071.html
- **[BPF-1993]** S. McCanne, V. Jacobson, « The BSD Packet Filter: A New Architecture for User-level Packet Capture », USENIX Winter 1993. https://www.usenix.org/conference/usenix-winter-1993-conference/bsd-packet-filter-new-architecture-user-level-packet
- **[CAPS]** capabilities(7), Linux man-pages. https://manpath.be/f38/7/capabilities
- **[CARGO-TARGETS]** The Cargo Book, « Cargo Targets ». https://doc.rust-lang.org/cargo/reference/cargo-targets.html
- **[CWE-150]** MITRE, « CWE-150: Improper Neutralization of Escape, Meta, or Control Sequences ». https://cwe.mitre.org/data/definitions/150.html
- **[OWASP-DEVGUIDE]** OWASP Developer Guide, « Implement Security Logging and Monitoring Checklist ». https://owasp.org/www-project-developer-guide/draft/design/web_app_checklist/security_logging_and_monitoring
- **[ETHERTYPE]** S. Bortzmeyer, « RFC 7042 : IANA Considerations and IETF Protocol and Documentation Usage for IEEE 802 Parameters ». https://www.bortzmeyer.org/7042.pdf
- **[HINNANT-DATES]** H. Hinnant, « chrono-Compatible Low-Level Date Algorithms ». https://howardhinnant.github.io/date_algorithms.html
- **[HARRIS-LO]** G. Harris, « BAD TCP CHECKSUM in loopback interface », wireshark-users, 2008. https://lists.wireshark.org/archives/wireshark-users/200801/msg00031.html
- **[IANA-TCP]** IANA, « Transmission Control Protocol (TCP) Parameters ». https://www.iana.org/assignments/tcp-parameters
- **[KERNEL-BPF]** Linux kernel documentation, « Linux Socket Filtering aka Berkeley Packet Filter (BPF) ». https://docs.kernel.org/networking/filter.html
- **[RFC5961]** A. Ramaiah, R. Stewart, M. Dalal, RFC 5961, *Improving TCP's Robustness to Blind In-Window Attacks*, 2010. https://www.rfc-editor.org/rfc/rfc5961
- **[LINUX-RFC5961]** E. Dumazet, « tcp: implement RFC 5961 3.2 », correctif du noyau Linux, netdev, juillet 2012. https://lore.kernel.org/netdev/20120717.013634.138750003911972637.davem@davemloft.net/T/
- **[MOSQ-2]** Eclipse Mosquitto, « Migrating from 1.x to 2.0 ». https://mosquitto.org/documentation/migrating-to-2-0/
- **[MQTT]** OASIS, *MQTT Version 3.1.1*, A. Banks, R. Gupta (éd.), 2014. https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html
- **[PACKET7]** packet(7), Linux man-pages. https://man7.org/linux/man-pages/man7/packet.7.html
- **[PCAP-RS]** Documentation de la crate `pcap`. https://docs.rs/pcap
- **[PCAP-SAVEFILE]** pcap-savefile(5), « libpcap savefile format », manuel de libpcap. https://www.mankier.com/5/pcap-savefile
- **[PL-CHECKSUM]** J. Stretch, « Disabling checksum validation in Wireshark », PacketLife.net, 2008. https://packetlife.net/blog/2008/aug/23/disabling-checksum-validation-wireshark/
- **[PTACEK-1998]** T. H. Ptacek, T. N. Newsham, « Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection », Secure Networks, Inc., janvier 1998. https://crypto.stanford.edu/cs155old/cs155-spring08/papers/IDSpaper.pdf
- **[RFC791]** J. Postel, RFC 791, *Internet Protocol*, 1981. https://www.rfc-editor.org/rfc/rfc791
- **[RFC1071]** R. Braden, D. Borman, C. Partridge, RFC 1071, *Computing the Internet Checksum*, 1988. https://www.rfc-editor.org/rfc/rfc1071
- **[RFC7323]** D. Borman et al., RFC 7323, *TCP Extensions for High Performance*, 2014. https://www.rfc-editor.org/rfc/rfc7323
- **[RFC8200]** S. Deering, R. Hinden, RFC 8200, *Internet Protocol, Version 6 (IPv6) Specification*, 2017. https://www.rfc-editor.org/rfc/rfc8200
- **[RFC9293]** W. Eddy (éd.), RFC 9293, *Transmission Control Protocol (TCP)*, 2022. https://www.rfc-editor.org/rfc/rfc9293
- **[RUST-BOOK]** S. Klabnik, C. Nichols, *The Rust Programming Language*. https://doc.rust-lang.org/book/
- **[RUST-BY-EXAMPLE]** *Rust by Example*, « let-else ». https://doc.rust-lang.org/stable/rust-by-example/flow_control/let_else.html
- **[RUST-REF-CONST]** *The Rust Reference*, « Constant items ». https://doc.rust-lang.org/reference/items/constant-items.html
- **[RUST-STD-STR]** Documentation de la bibliothèque standard Rust, type primitif `str`. https://doc.rust-lang.org/std/primitive.str.html
- **[RUST-STD-TODO]** Documentation de la bibliothèque standard Rust, macro `todo!`. https://doc.rust-lang.org/std/macro.todo.html
- **[SETCAP-REBUILD]** Source secondaire : README de projets Rust tiers (ex. rawgrep) signalant la perte des capabilities à la recompilation. https://docs.rs/crate/rawgrep/latest/source/README.md
- **[TCPDUMP-ANY]** G. Harris, réponse sur tcpdump-workers à propos de l'interface `any`, 2009. https://seclists.org/tcpdump/2009/q4/73
- **[TCPDUMP-LO]** G. Harris, réponse sur tcpdump-workers à propos du loopback Linux, 2003. https://seclists.org/tcpdump/2003/q3/6
- **[TCPDUMP-SPAN]** Réponse sur tcpdump-workers à propos de la capture sur réseau commuté, 2007. https://seclists.org/tcpdump/2007/q3/4
- **[WS-ETH]** Wireshark Wiki, « Ethernet capture setup ». https://wiki.wireshark.org/CaptureSetup/Ethernet
- **[WS-OFFLOAD]** Wireshark Wiki, « Offloading ». https://wiki.wireshark.org/CaptureSetup/Offloading
