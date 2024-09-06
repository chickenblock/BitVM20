use crate::treepp::{script, Script};
use crate::signatures::winternitz::PublicKey;
use super::bitvm20_merkel_tree::bitvm20_merkel_tree;
use super::bitvm20_execution_context::bitvm20_execution_context;
use super::bitvm20_transaction::bitvm20_transaction;

pub struct bitvm20_broadcast_packet {
    pub tx : bitvm20_transaction,
    pub winternitz_public_keys : Vec<PublicKey>,
    pub winternitz_signatures : Vec<Script>,
    
    // this may additionally also contain merkel proofs of from-user and to-user
    // which will allow challengers and other third person parties to compute the new state root
    // this has been omitted as of now to simplify the implementation
}

impl bitvm20_broadcast_packet {
    pub fn new(tx : &bitvm20_transaction, exec_contexts : Vec<bitvm20_execution_context>) -> bitvm20_broadcast_packet{
        let mut broadcast_packet = bitvm20_broadcast_packet {
            tx : tx.clone(),
            winternitz_public_keys : vec![],
            winternitz_signatures : vec![],
        };
        for ec in exec_contexts {
            broadcast_packet.winternitz_public_keys.push(ec.get_winternitz_public_key());
            broadcast_packet.winternitz_signatures.push(ec.get_winternitz_signatures());
        }
        return broadcast_packet;
    }

    // TODO
    // to be used by the operator after validation
    pub fn build_execution_contexts(&self, mt : &bitvm20_merkel_tree) -> Option<Vec<bitvm20_execution_context>> {
        return None;
    }
}