use bitcoin::{absolute, key::{Keypair, Secp256k1}, network::Network, taproot::{TaprootBuilder, TaprootSpendInfo}, Address, Amount, OutPoint, PublicKey, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey};
use crate::treepp::{script, Script};
use super::{bitvm20_execution_context::bitvm20_execution_context, script0::construct_script0};

const network: Network = Network::Regtest;

const challenege_blocks_count : u32 = 10;

pub fn build_funding_transaction_taproot(public_keys_for_take_tx : &Vec<PublicKey>, exec_contexts : &Vec<bitvm20_execution_context>, secret : &str) -> TaprootSpendInfo {
    let mut txScripts = TaprootBuilder::new();
    let mut consumed_scripts = 0;
    let total_scripts = exec_contexts.len();
    let mut b = 0; // bit in context
    while(b < usize::BITS && consumed_scripts < total_scripts)
    {
        let p = 1 << b;
        if (total_scripts & p) == p {
            for _ in 0..p {
                if(consumed_scripts == 0) {
                    txScripts = txScripts.add_leaf((b+1) as u8, construct_script0(challenege_blocks_count, public_keys_for_take_tx).compile()).expect("unable to add script");
                } else {
                    txScripts = txScripts.add_leaf((b+1) as u8, exec_contexts[consumed_scripts-1].get_script().compile()).expect("Unable to add script");
                }
                consumed_scripts += 1;
            }
        }
        b += 1;
    }

    let secp = Secp256k1::new();
    let keypair = Keypair::from_seckey_str(&secp, secret).unwrap();

    return txScripts.finalize(&Secp256k1::new(), keypair.x_only_public_key().0).expect("Unable to finalize funding tx's taproot");
}

pub fn generate_funding_transaction(funds_input : &Vec<TxIn>, funds_withdrawable : Amount, public_keys_for_take_tx : &Vec<PublicKey>, exec_contexts : &Vec<bitvm20_execution_context>, secret : &str) -> Transaction {
    return Transaction {
        version : bitcoin::transaction::Version(2),
        lock_time : absolute::LockTime::ZERO,
        input: funds_input.clone(),
        output : vec![TxOut{
            value : funds_withdrawable,
            script_pubkey: Address::p2tr_tweaked(
                build_funding_transaction_taproot(public_keys_for_take_tx, exec_contexts, secret).output_key(),
                network,
            ).script_pubkey(),
        }],
    };
}

pub fn generate_take_transaction(funds_withdrawable : Amount, funding_tx : &Transaction, operator_public_key : &PublicKey) -> Transaction {
    let secp = Secp256k1::new();
    return Transaction {
        version : bitcoin::transaction::Version(2),
        lock_time : absolute::LockTime::ZERO,
        input: vec![TxIn{
            previous_output : OutPoint {
                txid: funding_tx.compute_txid(),
                vout: 1,
            },
            script_sig : script!{}.compile(),
            sequence : Sequence(challenege_blocks_count),
            witness : Witness::new(),
        }],
        output : vec![TxOut{
            value : funds_withdrawable,
            script_pubkey: Address::p2tr(
                &secp,
                XOnlyPublicKey::from(operator_public_key.clone()),
                None,
                network,
            ).script_pubkey(),
        }],
    };
}