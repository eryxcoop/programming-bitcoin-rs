use lambdaworks_math::{
    field::fields::montgomery_backed_prime_fields::IsModulus, unsigned_integer::element::U256,
};

use crate::{
    secp256k1::{self, ScalarFelt, ScalarFieldModulus},
    signature::RandomScalarGenerator,
};

use rand::Rng;

pub(crate) trait IsRandomScalarGenerator {
    fn random_scalar(&mut self) -> ScalarFelt;
}

impl IsRandomScalarGenerator for RandomScalarGenerator {
    fn random_scalar(&mut self) -> ScalarFelt {
        let mut rng = rand::thread_rng();

        let mut representative = U256::from_limbs([rng.gen(), rng.gen(), rng.gen(), rng.gen()]);

        while representative >= ScalarFieldModulus::MODULUS {
            representative = U256::from_limbs([rng.gen(), rng.gen(), rng.gen(), rng.gen()]);
        }

        ScalarFelt::new(representative)
    }
}
