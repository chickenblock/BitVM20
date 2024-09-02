use crate::treepp::{script, Script};
use crate::signatures::winternitz::{PublicKey,generate_public_key,sign_digits,N};
use crate::bitvm20::utils::data_to_signable_balke3_digits;

pub struct bitvm20_execution_context
{
    winternitz_private_key : String, // it is possible to not have this
    winternitz_public_key : PublicKey,

    input_parameters : Vec<u8>,
    winternitz_signatures : Script,
    script : Script,
}

impl bitvm20_execution_context {
    // generate a new executuon context without any information of winternitz signatures
    pub fn new(input_parameters: &Vec<u8>, script: &Script) -> bitvm20_execution_context {
        return bitvm20_execution_context {
            winternitz_private_key: String::from(""),
            winternitz_public_key: [[0; 20]; N as usize],

            input_parameters: input_parameters.clone(),
            winternitz_signatures: script!{},
            script: script.clone()
        };
    }

    pub fn add_winternitz_private_key(&mut self, winternitz_private_key: &str) {
        let signable_hash_digits : [u8; 40] = data_to_signable_balke3_digits(&(self.input_parameters));
        self.winternitz_private_key = String::from(winternitz_private_key);
        self.winternitz_public_key = generate_public_key(winternitz_private_key);
        self.winternitz_signatures = sign_digits(winternitz_private_key, signable_hash_digits);
    }

    pub fn add_winternitz_public_key(&mut self, winternitz_public_key: PublicKey, winternitz_signatures: &Script) {
        self.winternitz_public_key = winternitz_public_key.clone();
        self.winternitz_signatures = winternitz_signatures.clone();
    }

    pub fn get_executable(&self) -> Script {
        return script!{
            for x in (&(self.input_parameters)).iter().rev() {
                {(*x)}
            }
            { self.winternitz_signatures.clone() }
            { self.script.clone() }
        };
    }

    // TO DO
    pub fn validate_winternitz_signatures(&self) -> bool {
        return false;
    }

    // TODO : convert into an overloaded == operator
    pub fn compare_equals(&self, other: &bitvm20_execution_context) -> bool {
        return (self.winternitz_signatures.clone().compile() == other.winternitz_signatures.clone().compile()) &&
                (self.input_parameters == other.input_parameters) && 
                (self.script.clone().compile() == other.script.clone().compile());
    }
}