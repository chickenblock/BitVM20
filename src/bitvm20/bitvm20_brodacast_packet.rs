use crate::treepp::{script, Script};
use crate::signatures::winternitz::PublicKey;
use super::{bitvm20_execution_context::bitvm20_execution_context, bitvm20_transaction::bitvm20_transaction};

pub struct bitvm20_broadcast_packet {
    pub tx : bitvm20_transaction,
    pub winternitz_public_keys : Vec<PublicKey>,
    pub winternitz_signatures : Vec<Script>,
}

impl bitvm20_broadcast_packet {
    // TODO
    pub fn new(tx : &bitvm20_transaction, exec_contexts : Vec<bitvm20_execution_context>) {
        let mut broadcast_packet = bitvm20_broadcast_packet {
            tx : tx.clone(),
            winternitz_public_keys : vec![],
            winternitz_signatures : vec![],
        };
    }

    // TODO
    // to be used by the operator
    pub fn build_execution_contexts(&self, mt : &bitvm20_merkel_tree) -> Option<Vec<bitvm20_execution_context>> {
        return None;
    }
}