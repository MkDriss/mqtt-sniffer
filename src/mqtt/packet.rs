//! Ce que renvoie le décodeur : un paquet décodé ([`Packet`]) et le résultat
//! du framing ([`Decoded`]).

use super::{
    ConnAck, Connect, PubAck, PubComp, PubRec, PubRel, Publish, SubAck, Subscribe, UnsubAck,
    Unsubscribe,
};

/// Un paquet MQTT décodé.
///
/// Une variante par type de paquet (les 14 de la spec) : il n'y a plus de
/// variante « fourre-tout », donc le compilateur vérifie que chaque `match`
/// traite bien tous les types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet<'a> {
    Connect(Connect<'a>),
    ConnAck(ConnAck),
    Publish(Publish<'a>),
    PubAck(PubAck),
    PubRec(PubRec),
    PubRel(PubRel),
    PubComp(PubComp),
    Subscribe(Subscribe<'a>),
    SubAck(SubAck<'a>),
    Unsubscribe(Unsubscribe<'a>),
    UnsubAck(UnsubAck),
    PingReq,
    PingResp,
    Disconnect,
}

/// Résultat du décodage d'un buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded<'a> {
    /// Un paquet complet a été décodé ; il occupait les `consumed` premiers
    /// octets du buffer. Le paquet suivant, s'il existe, commence juste après.
    Complete { packet: Packet<'a>, consumed: usize },
    /// Le buffer contient le début d'un paquet, mais il manque au moins
    /// `needed` octets (ils arriveront dans un prochain segment TCP).
    Incomplete { needed: usize },
}
