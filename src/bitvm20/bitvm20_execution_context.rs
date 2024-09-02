use crate::treepp::{script, Script};
use crate::signatures::winternitz::{PublicKey,generate_public_key,sign_digits,N};
use crate::bitvm20::utils::data_to_signable_balke3_digits;

pub trait script_generator {
    fn generate_script(&self, winternitz_public_key: &PublicKey) -> Script;
}

pub struct simple_script_generator {
    pub script_generator_function : fn(&PublicKey) -> Script,
}

impl script_generator for simple_script_generator {
    fn generate_script(&self, winternitz_public_key: &PublicKey) -> Script {
        return (self.script_generator_function)(winternitz_public_key);
    }
}

pub struct bitvm20_execution_context
{
    winternitz_private_key : String, // it is possible to not have this
    winternitz_public_key : PublicKey,

    input_parameters : Vec<u8>,
    winternitz_signatures : Script,
    script_generator : Box<dyn script_generator>,
}

impl bitvm20_execution_context {
    pub fn new(winternitz_private_key: &str, input_parameters: &Vec<u8>, script_generator: Box<dyn script_generator>) -> bitvm20_execution_context {
        return bitvm20_execution_context {
            winternitz_private_key: String::from(winternitz_private_key),
            winternitz_public_key: [[0; 20]; N as usize],

            input_parameters: input_parameters.clone(),
            winternitz_signatures: script!{},
            script_generator: script_generator,
        };
    }

    pub fn new2(winternitz_public_key: &PublicKey, input_parameters: &Vec<u8>, winternitz_signatures: &Script, script_generator: Box<dyn script_generator>) -> bitvm20_execution_context {
        return bitvm20_execution_context {
            winternitz_private_key: String::from(""),
            winternitz_public_key: winternitz_public_key.clone(),

            input_parameters: input_parameters.clone(),
            winternitz_signatures: winternitz_signatures.clone(),
            script_generator: script_generator
        };
    }

    pub fn get_winternitz_public_key(&self) -> PublicKey {
        if(self.winternitz_private_key.len() > 0) {
            return generate_public_key(&self.winternitz_private_key);
        } else {
            return self.winternitz_public_key.clone();
        }
    }

    pub fn get_winternitz_signatures(&self) -> Script {
        if(self.winternitz_private_key.len() > 0) {
            let signable_hash_digits : [u8; 40] = data_to_signable_balke3_digits(&self.input_parameters);
            return sign_digits(&self.winternitz_private_key, signable_hash_digits);
        } else {
            return self.winternitz_signatures.clone();
        }
    }

    pub fn get_script(&self) -> Script {
        return self.script_generator.generate_script(&self.get_winternitz_public_key());
    }

    pub fn get_executable(&self) -> Script {
        return script!{
            for x in (&(self.input_parameters)).iter().rev() {
                {(*x)}
            }
            { self.get_winternitz_signatures() }
            { self.get_script() }
        };
    }

    // TO DO
    pub fn validate_winternitz_signatures(&self) -> bool {
        return false;
    }

    // TODO : convert into an overloaded == operator
    pub fn compare_equals(&self, other: &bitvm20_execution_context) -> bool {
        return (self.get_winternitz_signatures().compile() == other.get_winternitz_signatures().compile()) &&
                (self.input_parameters == other.input_parameters) && 
                (self.get_script().compile() == other.get_script().compile());
    }
}