use crate::secp256k1::{Secp256k1, Secp256k1ScalarFelt};
use lambdaworks_math::{
    cyclic_group::IsGroup, elliptic_curve::traits::IsEllipticCurve, unsigned_integer::element::U256,
};
use rand::Rng;

pub(crate) struct ECDSA;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ECDSASignature(Secp256k1ScalarFelt, Secp256k1ScalarFelt);

pub(crate) trait IsEllipticCurveDigitalSignatureAlgorithm {
    fn random_scalar() -> Secp256k1ScalarFelt {
        let mut rng = rand::thread_rng();
        Secp256k1ScalarFelt::new(U256::from_limbs([
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
        ]))
    }

    fn sign(z: Secp256k1ScalarFelt, private_key: Secp256k1ScalarFelt) -> ECDSASignature {
        let k = Self::random_scalar();
        let R = Secp256k1::generator()
            .operate_with_self(k.representative())
            .to_affine();
        let r = Secp256k1ScalarFelt::new(R.x().representative());
        let k_inv = k.inv().unwrap();
        let s = (z + private_key * &r) * k_inv;
        ECDSASignature(r, s)
    }
}

impl IsEllipticCurveDigitalSignatureAlgorithm for ECDSA {}

#[cfg(test)]
pub mod tests {
    use lambdaworks_math::{traits::ByteConversion, unsigned_integer::element::U256};

    use crate::{hash::hash256, secp256k1::Secp256k1ScalarFelt, signature::ECDSASignature};

    use super::IsEllipticCurveDigitalSignatureAlgorithm;

    struct TestECDSA;
    impl IsEllipticCurveDigitalSignatureAlgorithm for TestECDSA {
        fn random_scalar() -> Secp256k1ScalarFelt {
            Secp256k1ScalarFelt::from(1234567890)
        }
    }

    #[test]
    fn test_signature() {
        let private_key = Secp256k1ScalarFelt::new(
            U256::from_bytes_be(&hash256("my secret".as_bytes())).unwrap(),
        );
        let z = Secp256k1ScalarFelt::new(
            U256::from_bytes_be(&hash256("my message".as_bytes())).unwrap(),
        );

        let signature = TestECDSA::sign(z, private_key);
        let signature_expected = ECDSASignature(
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
