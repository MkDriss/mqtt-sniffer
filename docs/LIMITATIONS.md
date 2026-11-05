# Limitations connues

État de la version 1.1.0. Chaque limitation indique son impact sur ce que le
sniffer affiche.

## Réassemblage TCP

| Limitation | Impact |
|---|---|
| **Segments en avance non mis en attente** | Une perte ou un désordre produit un *trou* : les octets manquants sont perdus, même si le segment arrive ensuite en retard. Le décodage MQTT se resynchronise et le ou les messages concernés sont perdus. Rare sur un réseau local filaire ; possible en Wi-Fi lors de rafales de messages. |
| **Contenu des retransmissions non comparé** | Un segment qui recouvre des octets déjà reçus avec un contenu *différent* n'est pas détecté : la première version reçue est conservée, alors que la machine destinataire pourrait appliquer une autre règle (attaque par *évasion*, voir le glossaire). |
| **Resynchronisation heuristique** | Après un trou, ou sur une connexion déjà ouverte au démarrage du sniffer, le premier message complet décodé sert de point de départ. Une suite d'octets quelconque peut, rarement, être prise pour un message valide. |
| **Recopie du segment suivant entier** | Quand un message MQTT attend sa suite, tout le segment suivant est recopié dans le tampon, et pas seulement la partie qui complète le message. La mémoire reste bornée par le budget global. |

## Capture et protocoles

| Limitation | Impact |
|---|---|
| **Checksums non vérifiés dans certains contextes** | La vérification dépend de la source (`--checksums auto`) : elle est désactivée sur l'interface loopback, où le checksum TCP n'est jamais calculé, et pour un fichier lu avec `--read` sans `--local-ip`. Dans ces cas, un segment au checksum invalide est analysé (attaque par *insertion*, voir le glossaire). |
| **D'autres formes d'insertion restent possibles** | Seul le checksum est vérifié. La machine destinataire peut aussi rejeter un segment pour d'autres raisons (numéro de séquence hors de sa fenêtre de réception, horodatage refusé par PAWS...), que le sniffer ne reproduit pas. |
| **Pseudo-en-tête IPv6 et en-tête de routage** | Le checksum TCP sur IPv6 est calculé avec l'adresse de destination de l'en-tête IPv6 ; en présence d'un en-tête de routage, la RFC 8200 impose l'adresse de destination finale. Un tel segment serait jugé invalide à tort. |
| **Fragments IP non réassemblés** | Un datagramme IP fragmenté n'est pas recomposé : son contenu TCP n'est pas lu correctement. Les messages MQTT courts ne sont normalement jamais fragmentés. |
| **Lecture de fichiers testée avec le format pcap classique** | L'option `--read` a été testée avec des fichiers pcap (ceux de `tcpdump -w` et ceux de `examples/scenarios.rs`), pas avec le format pcapng que Wireshark utilise par défaut. |
| **Seul MQTT 3.1.1 est supporté** | Un client MQTT 3.1 ou 5 provoque l'erreur `UnsupportedProtocolLevel`. |
| **Seul le type de lien Ethernet est supporté** | L'interface pseudo `any` (en-tête Linux SLL) est refusée au démarrage. |
| **Port MQTT fixé à 1883 dans la ligne de commande** | Avec un autre filtre BPF, le trafic des autres ports est réassemblé mais pas décodé. Le port est réglable dans la bibliothèque (`analyzer::Config::mqtt_port`), pas encore par une option. |
| **Limites mémoire non réglables en ligne de commande** | 256 sens de connexion, 1 Mio par message, 64 Mio pour l'ensemble des messages incomplets et 5 minutes d'inactivité : valeurs fixes dans le binaire, réglables seulement dans la bibliothèque (`analyzer::Config`). |

## Enregistrement (`--write`)

| Limitation | Impact |
|---|---|
| **La rotation coupe les connexions** | Un nouveau fichier commence dès que la taille est atteinte, même au milieu d'une connexion ou d'un message. Rejoué seul, le fichier suivant commence donc par un flux « pris en cours de route ». Pour rejouer une session complète, il faut fusionner les fichiers dans l'ordre (par exemple avec `mergecap`, fourni avec Wireshark). |
| **Aucune limite sur l'ensemble des fichiers** | Seule la taille de chaque fichier est limitée (`--write-max-mb`), et aucun fichier n'est supprimé automatiquement : un enregistrement de très longue durée peut remplir le disque. Si le disque est plein, l'enregistrement s'arrête avec un message, et l'affichage continue. |
| **Droits d'un dossier existant inchangés** | Le dossier est créé en `0700` seulement s'il n'existe pas. Les fichiers restent en `0600` dans tous les cas, mais leurs noms sont visibles si le dossier est plus ouvert. |

## Affichage

| Limitation | Impact |
|---|---|
| **Payloads tronqués à 64 octets** | Au-delà, seuls les 64 premiers octets sont affichés, suivis de la taille totale. Les chaînes (topics, identifiants) ne sont pas tronquées. |
| **Temps relatifs** | Les temps affichés sont relatifs à la première trame capturée, pas l'heure absolue. |
| **Caractères de contrôle dans les chaînes** | Neutralisés à l'affichage (CWE-150, voir `show_text`), mais sans avertissement particulier, alors que la spécification MQTT les déconseille (§1.5.3). |
| **`--show-secrets` affiche les mots de passe en clair** | Comportement volontaire et explicite ; les mots de passe sont masqués par défaut. |

## Défauts corrigés

- **Injection de séquences d'échappement dans le terminal (CWE-150).** Les
  champs `client_id`, `username`, topic du Will, topic et filtres d'abonnement
  étaient affichés sans neutralisation : un client pouvait effacer ou réécrire
  l'affichage du sniffer. `show_bytes` laissait aussi passer le caractère
  d'inversion bidirectionnelle U+202E. Corrigé par `show_text`
  (`str::escape_debug`) ; couvert par trois tests, validés par test de
  mutation (ils échouent si la protection est retirée).
- **Message coupé entre plusieurs segments TCP.** Sans réassemblage, un tel
  message était signalé incomplet et la suite produisait une fausse anomalie.
  Corrigé par le réassemblage TCP (`tcp`) et le décodage par flux
  (`mqtt::StreamDecoder`).
- **Analyse de segments au checksum invalide (insertion).** Un segment forgé
  au checksum invalide, rejeté par la machine destinataire, était analysé :
  le sniffer pouvait afficher un faux message à la place du vrai. Corrigé par
  la vérification des checksums (`checksum`, `analyzer::ChecksumPolicy`) ;
  démontré par le scénario `insertion-checksum`, rejoué avec et sans
  vérification.
- **Panique sur un tube fermé.** `rnifler ... | head` provoquait une
  panique (« Broken pipe ») quand `head` avait fini de lire. Le sniffer
  s'arrête désormais sans erreur.
