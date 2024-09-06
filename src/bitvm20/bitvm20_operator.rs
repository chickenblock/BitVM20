use crate::treepp::{script, Script};
use num_bigint::BigUint;
use crate::signatures::winternitz::PublicKey;
use super::bitvm20_brodacast_packet::bitvm20_broadcast_packet;
use super::bitvm20_merkel_tree::{bitvm20_merkel_proof, bitvm20_merkel_tree};
use super::bitvm20_transaction::{bitvm20_transaction};
use super::bitvm20_entry::{bitvm20_entry};
use num_traits::Zero;

pub struct bitvm20_operator {
    pub bitcoin_private_key : BigUint,

    pub state_tree : bitvm20_merkel_tree,      // current state of the tree
    pub tx_history : Vec<bitvm20_transaction>, // all transactions applied so far
}

impl bitvm20_operator {
    // take database file as input
    pub fn new() -> bitvm20_operator {
        return bitvm20_operator {
            bitcoin_private_key: BigUint::zero(),

            state_tree: bitvm20_merkel_tree::new(),
            tx_history: vec![],
        };
    }

    // TODO
    pub fn assign_user(user : &bitvm20_entry) -> Option<usize> {
        return None;
    }

    // TODO
    pub fn post_transaction_and_receive_broadcast(tx : &bitvm20_transaction) -> Option<bitvm20_broadcast_packet> {
        // validate transaction signature
        // primary validate transaction
        // generate merkel proofs


        return None;
    }
}