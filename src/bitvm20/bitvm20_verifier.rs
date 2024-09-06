use num_bigint::BigUint;

use super::bitvm20_brodacast_packet::bitvm20_broadcast_packet;
use super::bitvm20_merkel_tree::{bitvm20_merkel_proof, bitvm20_merkel_tree};
use super::bitvm20_transaction::{bitvm20_transaction};
use num_traits::Zero;

pub struct bitvm20_verifier {
    pub bitcoin_private_key : BigUint,

    pub state_tree : bitvm20_merkel_tree,      // current state of the tree
    pub tx_history : Vec<bitvm20_transaction>, // all transactions applied so far
}

impl bitvm20_verifier {
    // take database file as input
    pub fn new() -> bitvm20_verifier {
        return bitvm20_verifier {
            bitcoin_private_key: BigUint::zero(),

            state_tree: bitvm20_merkel_tree::new(),
            tx_history: vec![],
        };
    }

    pub fn receive_broadcast(bitvm20_broadcast_packet : &bitvm20_broadcast_packet) -> Option<String> {
        // ensure that that the bitvm20_broadcast packet has enough signatures for a transaction

        // construct exection contexts out of the input parameters

        // validate each of the exection contexts for a valid input_parameters and their winternitz_signatures

        // construct a bitcoin transaction out of script1 and the execution contexts

        // construct a bitcoin's take transaction out of the earlier mentioned transaction

        // sign this transaction and reveal it to the operator

        // apply this transaction to the merkel tree

        return None
    }
}