use crate::treepp::{script, Script};
use num_bigint::BigUint;
use crate::signatures::winternitz::PublicKey;
use super::bitvm20_brodacast_packet::bitvm20_broadcast_packet;
use super::bitvm20_merkel_tree::{bitvm20_merkel_proof, bitvm20_merkel_tree};
use super::bitvm20_transaction::{bitvm20_transaction};
use super::bitvm20_entry::{bitvm20_entry};
use super::bitvm20_user_transaction::bitvm20_user_transaction;
use num_traits::Zero;

pub struct bitvm20_operator {
    pub bitcoin_private_key : BigUint,

    pub state_tree : bitvm20_merkel_tree,      // current state of the tree
    pub tx_history : Vec<bitvm20_transaction>, // all transactions applied so far

    pub tx_on_hold : Option<bitvm20_transaction>, // a transaction for which verification signatures have not been received
}

impl bitvm20_operator {
    // take database file as input
    pub fn new() -> bitvm20_operator {
        return bitvm20_operator {
            bitcoin_private_key: BigUint::zero(),

            state_tree: bitvm20_merkel_tree::new(),
            tx_history: vec![],

            tx_on_hold: None,
        };
    }

    // TODO
    pub fn assign_user(user : &bitvm20_entry) -> Option<usize> {
        return None;
    }

    // TODO
    // called by the user to generate the transaction object and the broadcast
    pub fn post_transaction_and_receive_broadcast(utx : &bitvm20_user_transaction) -> Option<bitvm20_broadcast_packet> {
        // fail if there is a transaction already on hold
        
        // generate bitvm20_transaction from user_transaction

        // primary validate transaction
        // generate merkel proofs, merkel proofs must exist, if a bitvm20_transaction can be created from the user_transaction
        // validate transaction signature

        // if the above validations pass then the transation can be applied to the current state

        // generate random vector strings of winternitz signatures
        // generate all execution contexts

        // put the transaction on hold

        // generate broadcast_packet out of bitvm20_transaction and the execution contexts and return it

        return None;
    }

    // TODO
    // called after the operator received all the necessary signatures
    pub fn receive_verifier_signatures(signatures : Vec<String>) {
        // note down verifier signatures for the transaction on hold

        // apply the transaction on hold

        // move the transaction on hold to applied transactions
    }
}