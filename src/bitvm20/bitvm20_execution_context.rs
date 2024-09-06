use crate::execute_script_without_stack_limit;
use crate::treepp::{script, Script};
use crate::signatures::winternitz::{generate_public_key, sign_digits, PublicKey, ZeroPublicKey};
use crate::bitvm20::utils::data_to_signable_balke3_digits;
use super::utils::{pop_bytes, verify_input_data};

pub trait script_generator {
    fn generate_script(&self, winternitz_public_key: &PublicKey) -> Script;
}

pub struct script1_generator {
    pub script_generator_input_param : Vec<u8>,
    pub script_generator_function : fn(&PublicKey, script_generator_input_param : &Vec<u8>) -> Script,
}

impl script1_generator {
    pub fn new(script_generator_function : fn(&PublicKey, script_generator_input_param : &Vec<u8>) -> Script, script_generator_input_param : &Vec<u8>) -> script1_generator {
        return script1_generator {
            script_generator_input_param: script_generator_input_param.clone(),
            script_generator_function: script_generator_function,
        };
    }
}

impl script_generator for script1_generator {
    fn generate_script(&self, winternitz_public_key: &PublicKey) -> Script {
        return (self.script_generator_function)(winternitz_public_key, &self.script_generator_input_param);
    }
}

pub struct simple_script_generator {
    pub script_generator_function : fn(&PublicKey) -> Script,
}

impl simple_script_generator {
    pub fn new(script_generator_function : fn(&PublicKey) -> Script) -> simple_script_generator {
        return simple_script_generator {
            script_generator_function: script_generator_function,
        };
    }
}

impl script_generator for simple_script_generator {
    fn generate_script(&self, winternitz_public_key: &PublicKey) -> Script {
        return (self.script_generator_function)(winternitz_public_key);
    }
}

pub struct bitvm20_execution_context
{
    pub winternitz_private_key : String, // it is possible to not have this
    pub winternitz_public_key : PublicKey,

    pub input_parameters : Vec<u8>,
    pub winternitz_signatures : Script,
    pub script_generator : Box<dyn script_generator>,
}

impl bitvm20_execution_context {
    pub fn new(winternitz_private_key: &str, input_parameters: &Vec<u8>, script_generator: Box<dyn script_generator>) -> bitvm20_execution_context {
        return bitvm20_execution_context {
            winternitz_private_key: String::from(winternitz_private_key),
            winternitz_public_key: ZeroPublicKey,

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

    pub fn get_input(&self) ->Script {
        return script!{
            for x in (&(self.input_parameters)).iter().rev() {
                {(*x)}
            }
            { self.get_winternitz_signatures() }
        };
    }

    pub fn get_script(&self) -> Script {
        return self.script_generator.generate_script(&self.get_winternitz_public_key());
    }

    pub fn get_executable(&self) -> Script {
        return script!{
            { self.get_input() }
            { self.get_script() }
        };
    }

    // to be used by verifier to ensure that correct winternitz signatures are provided
    // TODO : currently implemented as if it is a bitcoin script, but to be replaced with rust implementation
    pub fn validate_input_parameters_and_winternitz_signatures(&self) -> bool {
        let validation_script = script!{
            { self.get_input() } // put input_parameters and then winternitz_signatures right after that
            { verify_input_data(&self.get_winternitz_public_key(), self.input_parameters.len()) } // verify the winternitz_signatures against the winternitz_public_key and only input_parameters will be left on stack after this
            { pop_bytes(self.input_parameters.len()) }
            OP_TRUE
        };
        return execute_script_without_stack_limit(validation_script).success;
    }

    // TODO : convert into an overloaded == operator
    pub fn compare_equals(&self, other: &bitvm20_execution_context) -> bool {
        return (self.get_winternitz_signatures().compile() == other.get_winternitz_signatures().compile()) &&
                (self.input_parameters == other.input_parameters) && 
                (self.get_script().compile() == other.get_script().compile());
    }
}