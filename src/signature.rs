use crate::{
    hash::hash256,
    random::IsRandomScalarGenerator,
    secp256k1::{Secp256k1, Secp256k1ScalarFelt},
};
use lambdaworks_math::{
    cyclic_group::IsGroup, elliptic_curve::traits::IsEllipticCurve, traits::ByteConversion,
    unsigned_integer::element::U256,
};

pub(crate) struct EllipticCurveDigitalSignatureAlgorithm;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ECDSASignature {
    r: Secp256k1ScalarFelt,
    s: Secp256k1ScalarFelt,
}
pub(crate) type PrivateKey = [u8; 32];

pub(crate) struct RandomScalarGenerator;

impl ECDSASignature {
    fn new(r: Secp256k1ScalarFelt, s: Secp256k1ScalarFelt) -> Self {
        Self { r, s }
    }
}

impl EllipticCurveDigitalSignatureAlgorithm {
    fn sign(
        z: &[u8],
        private_key: PrivateKey,
        random: &mut impl IsRandomScalarGenerator,
    ) -> ECDSASignature {
        let z = Secp256k1ScalarFelt::new(U256::from_bytes_be(&hash256(z)).unwrap());
        let e = Secp256k1ScalarFelt::new(U256::from_bytes_be(&private_key).unwrap());

        let k = random.random_scalar();
        let R = Secp256k1::generator()
            .operate_with_self(k.representative())
            .to_affine();
        let r = Secp256k1ScalarFelt::new(R.x().representative());
        let k_inv = k.inv().unwrap();
        let s = (z + e * &r) * k_inv;
        ECDSASignature::new(r, s)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{
        hash::hash256,
        secp256k1::Secp256k1ScalarFelt,
        signature::{ECDSASignature, EllipticCurveDigitalSignatureAlgorithm as ECDSA},
    };

    use super::IsRandomScalarGenerator;

    struct TestRandomScalarGenerator;
    impl IsRandomScalarGenerator for TestRandomScalarGenerator {
        fn random_scalar(&mut self) -> Secp256k1ScalarFelt {
            Secp256k1ScalarFelt::from(1234567890)
        }
    }

    #[test]
    fn test_signature() {
        let private_key = hash256("my secret".as_bytes());
        let z = "my message".as_bytes();

        let signature = ECDSA::sign(z, private_key, &mut TestRandomScalarGenerator);

        let signature_expected = ECDSASignature::new(
            Secp256k1ScalarFelt::from_hex_unchecked(
                "2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22",
            ),
            Secp256k1ScalarFelt::from_hex_unchecked(
                "bb14e602ef9e3f872e25fad328466b34e6734b7a0fcd58b1eb635447ffae8cb9",
            ),
        );

        assert_eq!(signature, signature_expected);
    }
}
