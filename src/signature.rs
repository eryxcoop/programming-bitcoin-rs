use crate::{
    hash::hash256,
    random::IsRandomScalarGenerator,
    secp256k1::{BaseFelt, ScalarFelt, ScalarFieldModulus, Secp256k1},
};
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{
        short_weierstrass::{point::ShortWeierstrassProjectivePoint, traits::IsShortWeierstrass},
        traits::IsEllipticCurve,
    },
    field::fields::montgomery_backed_prime_fields::IsModulus,
    traits::ByteConversion,
    unsigned_integer::element::U256,
};

pub(crate) struct EllipticCurveDigitalSignatureAlgorithm;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ECDSASignature {
    r: ScalarFelt,
    s: ScalarFelt,
}
pub(crate) type PrivateKey = [u8; 32];
pub(crate) type PublicKey = ShortWeierstrassProjectivePoint<Secp256k1>;

pub(crate) struct RandomScalarGenerator;

impl ECDSASignature {
    fn new(r: ScalarFelt, s: ScalarFelt) -> Self {
        Self { r, s }
    }
}

impl EllipticCurveDigitalSignatureAlgorithm {
    fn sign(
        z: &[u8],
        private_key: PrivateKey,
        random: &mut impl IsRandomScalarGenerator,
    ) -> ECDSASignature {
        let z = ScalarFelt::new(U256::from_bytes_be(&hash256(z)).unwrap());
        let e = ScalarFelt::new(U256::from_bytes_be(&private_key).unwrap());

        loop {
            let k = random.random_scalar();
            if let Ok(k_inv) = k.inv() {
                let point = Secp256k1::generator()
                    .operate_with_self(k.representative())
                    .to_affine();
                let r = ScalarFelt::new(point.x().representative());
                if r != ScalarFelt::zero() {
                    let s = (&z + &e * &r) * k_inv;
                    if s != ScalarFelt::zero() {
                        return ECDSASignature::new(r, s);
                    }
                }
            }
        }
    }

    fn verify(z: &[u8], signature: ECDSASignature, public_key: PublicKey) -> bool {
        if public_key.z() == &BaseFelt::zero() {
            return false;
        }

        let public_key = public_key.to_affine();
        if Secp256k1::defining_equation(public_key.x(), public_key.y()) != BaseFelt::zero() {
            return false;
        }

        if !public_key
            .operate_with_self(ScalarFieldModulus::MODULUS)
            .is_neutral_element()
        {
            return false;
        }

        if signature.r == ScalarFelt::zero() || signature.s == ScalarFelt::zero() {
            return false;
        }

        let z = ScalarFelt::new(U256::from_bytes_be(&hash256(z)).unwrap());
        let u = z * signature.s.inv().unwrap();
        let v = &signature.r * signature.s.inv().unwrap();
        let point = Secp256k1::generator()
            .operate_with_self(u.representative())
            .operate_with(&public_key.operate_with_self(v.representative()))
            .to_affine();

        let r = ScalarFelt::new(point.x().representative());

        r == signature.r
    }
}

#[cfg(test)]
pub mod tests {
    use lambdaworks_math::{
        cyclic_group::IsGroup,
        elliptic_curve::traits::{FromAffine, IsEllipticCurve},
    };

    use crate::{
        hash::hash256,
        secp256k1::{BaseFelt, Point, ScalarFelt, Secp256k1},
        signature::{ECDSASignature, EllipticCurveDigitalSignatureAlgorithm as ECDSA},
    };

    use super::IsRandomScalarGenerator;

    struct TestRandomScalarGenerator;
    impl IsRandomScalarGenerator for TestRandomScalarGenerator {
        fn random_scalar(&mut self) -> ScalarFelt {
            ScalarFelt::from(1234567890)
        }
    }

    #[test]
    fn test_signature() {
        let private_key = hash256("my secret".as_bytes());
        let z = "my message".as_bytes();

        let signature = ECDSA::sign(z, private_key, &mut TestRandomScalarGenerator);

        let signature_expected = ECDSASignature::new(
            ScalarFelt::from_hex_unchecked(
                "2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22",
            ),
            ScalarFelt::from_hex_unchecked(
                "bb14e602ef9e3f872e25fad328466b34e6734b7a0fcd58b1eb635447ffae8cb9",
            ),
        );

        assert_eq!(signature, signature_expected);
    }

    #[test]
    fn test_verify_signature() {
        let z = "my message".as_bytes();

        // public key corresponding to the private key = `hash256("my secret".as_bytes())`
        let public_key = Point::from_affine(
            BaseFelt::from_hex_unchecked(
                "28d003eab2e428d11983f3e97c3fa0addf3b42740df0d211795ffb3be2f6c52",
            ),
            BaseFelt::from_hex_unchecked(
                "ae987b9ec6ea159c78cb2a937ed89096fb218d9e7594f02b547526d8cd309e2",
            ),
        )
        .unwrap();

        let signature = ECDSASignature::new(
            ScalarFelt::from_hex_unchecked(
                "2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22",
            ),
            ScalarFelt::from_hex_unchecked(
                "bb14e602ef9e3f872e25fad328466b34e6734b7a0fcd58b1eb635447ffae8cb9",
            ),
        );

        assert!(ECDSA::verify(z, signature, public_key));
    }

    #[test]
    fn test_verify_invalid_signature() {
        let z = "my message".as_bytes();

        // public key corresponding to the private key = `hash256("my secret".as_bytes())`
        let mut public_key = Point::from_affine(
            BaseFelt::from_hex_unchecked(
                "28d003eab2e428d11983f3e97c3fa0addf3b42740df0d211795ffb3be2f6c52",
            ),
            BaseFelt::from_hex_unchecked(
                "ae987b9ec6ea159c78cb2a937ed89096fb218d9e7594f02b547526d8cd309e2",
            ),
        )
        .unwrap();

        let signature = ECDSASignature::new(
            ScalarFelt::from_hex_unchecked(
                "2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22",
            ),
            ScalarFelt::from_hex_unchecked(
                "bb14e602ef9e3f872e25fad328466b34e6734b7a0fcd58b1eb635447ffae8cb9",
            ),
        );

        // Add noise to public key to make it invalid
        public_key = public_key.operate_with(&Secp256k1::generator());

        assert!(!ECDSA::verify(z, signature, public_key));
    }
}
