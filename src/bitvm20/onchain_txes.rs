use bitcoin::{key::Secp256k1, key::Keypair, taproot::{TaprootBuilder, TaprootSpendInfo}, PublicKey};

use super::{bitvm20_execution_context::bitvm20_execution_context, script0::construct_script0};

const challenege_blocks_count : i32 = 10;

pub fn build_funding_transaction_taproot(public_keys : &Vec<PublicKey>, exec_contexts : &Vec<bitvm20_execution_context>, secret : &str) -> TaprootSpendInfo {
    let mut txScripts = TaprootBuilder::new();
    let mut consumed_scripts = 0;
    let total_scripts = exec_contexts.len();
    let mut b = 0; // bit in context
    while(b < usize::BITS && consumed_scripts < total_scripts)
    {
        let p = 1 << b;
        if(total_scripts & p == p )
        {
            for _ in 0..p {
                if(consumed_scripts == 0) {
                    txScripts = txScripts.add_leaf((b+1) as u8, construct_script0(challenege_blocks_count, public_keys).compile()).expect("unable to add script");
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