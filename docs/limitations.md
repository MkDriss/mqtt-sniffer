# Limitations connues

État de la version 0.2.0. Chaque limitation indique son impact sur ce que le
sniffer affiche.

| Limitation | Impact |
|---|---|
| **Pas de réassemblage TCP** | Un message MQTT coupé en plusieurs segments est signalé « incomplet ». La suite, qui arrive dans le segment suivant, est décodée comme un nouveau paquet et produit une **fausse anomalie**. |
| **Checksums IP et TCP non vérifiés** | Choix lié à l'offload, qui rend faux les checksums des paquets émis par la machine de capture. Conséquences : une trame corrompue n'est pas détectée, et un segment au checksum volontairement invalide, rejeté par le système de la machine destinataire, est quand même affiché et décodé (attaque par *insertion*, voir le glossaire). |
| **Fragments IP non réassemblés** | Un datagramme IP fragmenté n'est pas recomposé : son contenu TCP n'est pas lu correctement. Les messages MQTT courts ne sont normalement jamais fragmentés. |
| **Seul MQTT 3.1.1 est supporté** | Un client MQTT 3.1 ou 5 provoque l'erreur `UnsupportedProtocolLevel`. |
| **Seul le type de lien Ethernet est supporté** | L'interface pseudo `any` (en-tête Linux SLL) est refusée au démarrage. |
| **Pas d'horodatage dans l'affichage** | L'ordre relatif des paquets de deux connexions différentes ne peut pas être établi précisément. |
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