use lambdaworks_math::{
    field::fields::montgomery_backed_prime_fields::IsModulus, unsigned_integer::element::U256,
};

use crate::{
    secp256k1::fields::{ScalarFelt, ScalarFieldModulus},
    private_key::PrivateKey,
};
use rand::Rng;

pub(crate) struct RandomScalarGenerator;
pub(crate) struct RandomPrivateKeyGenerator;

pub(crate) trait IsRandomGenerator<T> {
    fn random_scalar(&mut self) -> T;
}

impl RandomScalarGenerator {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

impl IsRandomGenerator<ScalarFelt> for RandomScalarGenerator {
    fn random_scalar(&mut self) -> ScalarFelt {
        let mut rng = rand::thread_rng();

        let mut representative = U256::from_limbs([rng.gen(), rng.gen(), rng.gen(), rng.gen()]);

        while representative >= ScalarFieldModulus::MODULUS {
            representative = U256::from_limbs([rng.gen(), rng.gen(), rng.gen(), rng.gen()]);
        }

        ScalarFelt::new(representative)
    }
}

impl RandomPrivateKeyGenerator {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

impl IsRandomGenerator<PrivateKey> for RandomPrivateKeyGenerator {
    fn random_scalar(&mut self) -> PrivateKey {
        let mut rng = rand::thread_rng();
        let mut result = [0u8; 32];
        for byte in result.iter_mut() {
            *byte = rng.gen()
        }
        PrivateKey::new(result)
    }
}
