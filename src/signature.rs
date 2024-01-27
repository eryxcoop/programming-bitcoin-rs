use crate::{
    private_key::PrivateKey,
    public_key::PublicKey,
    random::IsRandomGenerator,
    secp256k1::{
        curve::{Point, Secp256k1},
        fields::{BaseFelt, ScalarFelt, ScalarFieldModulus},
    },
};
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{short_weierstrass::traits::IsShortWeierstrass, traits::IsEllipticCurve},
    field::fields::montgomery_backed_prime_fields::IsModulus,
    traits::ByteConversion,
    unsigned_integer::element::U256,
};

pub(crate) struct EllipticCurveDigitalSignatureAlgorithm;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ECDSASignature {
    pub(crate) r: ScalarFelt,
    pub(crate) s: ScalarFelt,
}

impl ECDSASignature {
    pub(crate) fn new(r: ScalarFelt, s: ScalarFelt) -> Self {
        Self { r, s }
    }
}

impl EllipticCurveDigitalSignatureAlgorithm {
    fn sign(
        z: &[u8; 32],
        private_key: PrivateKey,
        random: &mut impl IsRandomGenerator<ScalarFelt>,
    ) -> ECDSASignature {
        let z = ScalarFelt::new(U256::from_bytes_be(z).unwrap());
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

    fn verify(z: &[u8; 32], signature: ECDSASignature, public_key: PublicKey) -> bool {
        if public_key.point.z() == &BaseFelt::zero() {
            return false;
        }

        let point = public_key.point.to_affine();
        if Secp256k1::defining_equation(point.x(), point.y()) != BaseFelt::zero() {
            return false;
        }

        if !point
            .operate_with_self(ScalarFieldModulus::MODULUS)
            .is_neutral_element()
        {
            return false;
        }

        if signature.r != ScalarFelt::zero() {
            if let Ok(s_inv) = signature.s.inv() {
                let z = ScalarFelt::new(U256::from_bytes_be(z).unwrap());
                let u = z * &s_inv;
                let v = &signature.r * s_inv;
                let point = Secp256k1::generator()
                    .operate_with_self(u.representative())
                    .operate_with(&point.operate_with_self(v.representative()))
                    .to_affine();
                let r = ScalarFelt::new(point.x().representative());

                r == signature.r
            } else {
                false
            }
        } else {
            false
        }
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
        secp256k1::{
            curve::{Point, Secp256k1},
            fields::{BaseFelt, ScalarFelt},
        },
        signature::{ECDSASignature, EllipticCurveDigitalSignatureAlgorithm as ECDSA, PublicKey},
    };

    use super::IsRandomGenerator;

    struct TestRandomScalarGenerator;
    impl IsRandomGenerator<ScalarFelt> for TestRandomScalarGenerator {
        fn random_scalar(&mut self) -> ScalarFelt {
            ScalarFelt::from(1234567890)
        }
    }

    #[test]
    fn test_signature_1() {
        let private_key = hash256("my secret".as_bytes());
        let z = hash256("my message".as_bytes());

        let signature = ECDSA::sign(&z, private_key, &mut TestRandomScalarGenerator);

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
    fn test_signature_2() {
        let private_key = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 48, 57,
        ];
        let z = hash256("Programming Bitcoin!".as_bytes());

        let signature = ECDSA::sign(&z, private_key, &mut TestRandomScalarGenerator);

        let signature_expected = ECDSASignature::new(
            ScalarFelt::from_hex_unchecked(
                "2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22",
            ),
            ScalarFelt::from_hex_unchecked(
                "1dbc63bfef4416705e602a7b564161167076d8b20990a0f26f316cff2cb0bc1a",
            ),
        );

        assert_eq!(signature, signature_expected);
    }

    #[test]
    fn test_verify_signature_1() {
        let z = hash256("my message".as_bytes());

        // public key corresponding to the private key = `hash256("my secret".as_bytes())`
        let public_key = PublicKey::new(
            Point::from_affine(
                BaseFelt::from_hex_unchecked(
                    "28d003eab2e428d11983f3e97c3fa0addf3b42740df0d211795ffb3be2f6c52",
                ),
                BaseFelt::from_hex_unchecked(
                    "ae987b9ec6ea159c78cb2a937ed89096fb218d9e7594f02b547526d8cd309e2",
                ),
            )
            .unwrap(),
        );

        let signature = ECDSASignature::new(
            ScalarFelt::from_hex_unchecked(
                "2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22",
            ),
            ScalarFelt::from_hex_unchecked(
                "bb14e602ef9e3f872e25fad328466b34e6734b7a0fcd58b1eb635447ffae8cb9",
            ),
        );

        assert!(ECDSA::verify(&z, signature, public_key));
    }

    #[test]
    fn test_verify_signature_2() {
        let z = [
            236, 32, 139, 170, 15, 193, 193, 159, 112, 138, 156, 169, 111, 222, 255, 58, 195, 242,
            48, 187, 74, 123, 164, 174, 222, 73, 66, 173, 0, 60, 15, 96,
        ];

        let public_key = PublicKey::new(
            Point::from_affine(
                BaseFelt::from_hex_unchecked(
                    "887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c",
                ),
                BaseFelt::from_hex_unchecked(
                    "61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34",
                ),
            )
            .unwrap(),
        );

        let signature = ECDSASignature::new(
            ScalarFelt::from_hex_unchecked(
                "ac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395",
            ),
            ScalarFelt::from_hex_unchecked(
                "68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4",
            ),
        );

        assert!(ECDSA::verify(&z, signature, public_key));
    }

    #[test]
    fn test_verify_signature_3() {
        let z = [
            124, 7, 111, 243, 22, 105, 42, 61, 126, 179, 195, 187, 15, 139, 20, 136, 207, 114, 225,
            175, 205, 146, 158, 41, 48, 112, 50, 153, 122, 131, 138, 61,
        ];

        let public_key = PublicKey::new(
            Point::from_affine(
                BaseFelt::from_hex_unchecked(
                    "887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c",
                ),
                BaseFelt::from_hex_unchecked(
                    "61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34",
                ),
            )
            .unwrap(),
        );

        let signature = ECDSASignature::new(
            ScalarFelt::from_hex_unchecked(
                "eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c",
            ),
            ScalarFelt::from_hex_unchecked(
                "c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6",
            ),
        );

        assert!(ECDSA::verify(&z, signature, public_key));
    }

    #[test]
    fn test_verify_invalid_signature() {
        let z = hash256("my message".as_bytes());

        // public key corresponding to the private key = `hash256("my secret".as_bytes())`
        let mut public_key = PublicKey::new(
            Point::from_affine(
                BaseFelt::from_hex_unchecked(
                    "28d003eab2e428d11983f3e97c3fa0addf3b42740df0d211795ffb3be2f6c52",
                ),
                BaseFelt::from_hex_unchecked(
                    "ae987b9ec6ea159c78cb2a937ed89096fb218d9e7594f02b547526d8cd309e2",
                ),
            )
            .unwrap(),
        );

        let signature = ECDSASignature::new(
            ScalarFelt::from_hex_unchecked(
                "2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22",
            ),
            ScalarFelt::from_hex_unchecked(
                "bb14e602ef9e3f872e25fad328466b34e6734b7a0fcd58b1eb635447ffae8cb9",
            ),
        );

        // Add noise to public key to make it invalid
        public_key = PublicKey::new(public_key.point().operate_with(&Secp256k1::generator()));

        assert!(!ECDSA::verify(&z, signature, public_key));
    }
}
