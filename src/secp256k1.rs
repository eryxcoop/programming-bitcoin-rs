use lambdaworks_math::{
    elliptic_curve::{
        short_weierstrass::{point::ShortWeierstrassProjectivePoint, traits::IsShortWeierstrass},
        traits::{FromAffine, IsEllipticCurve},
    },
    field::{
        element::FieldElement,
        fields::montgomery_backed_prime_fields::{IsModulus, MontgomeryBackendPrimeField},
    },
    unsigned_integer::element::U256,
};

#[derive(Debug, Clone)]
pub(crate) struct Secp256k1BaseFieldModulus;
pub(crate) type Secp256k1BaseField = MontgomeryBackendPrimeField<Secp256k1BaseFieldModulus, 4>;
pub(crate) type Secp256k1BaseFelt = FieldElement<Secp256k1BaseField>;

#[derive(Debug, Clone)]
pub(crate) struct Secp256k1ScalarFieldModulus;
pub(crate) type Secp256k1ScalarField = MontgomeryBackendPrimeField<Secp256k1ScalarFieldModulus, 4>;
pub(crate) type Secp256k1ScalarFelt = FieldElement<Secp256k1ScalarField>;

#[derive(Debug, Clone)]
pub(crate) struct Secp256k1;

/// p = 2**256 - 2**32 - 977
impl IsModulus<U256> for Secp256k1BaseFieldModulus {
    const MODULUS: U256 = U256::from_hex_unchecked(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
    );
}

impl IsModulus<U256> for Secp256k1ScalarFieldModulus {
    const MODULUS: U256 = U256::from_hex_unchecked(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    );
}

pub(crate) const SECP256K1_GENERATOR_X: Secp256k1BaseFelt = Secp256k1BaseFelt::from_hex_unchecked(
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
);
pub(crate) const SECP256K1_GENERATOR_Y: Secp256k1BaseFelt = Secp256k1BaseFelt::from_hex_unchecked(
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
);

impl IsEllipticCurve for Secp256k1 {
    type BaseField = Secp256k1BaseField;
    type PointRepresentation = ShortWeierstrassProjectivePoint<Self>;

    fn generator() -> Self::PointRepresentation {
        ShortWeierstrassProjectivePoint::from_affine(SECP256K1_GENERATOR_X, SECP256K1_GENERATOR_Y)
            .unwrap()
    }
}

impl IsShortWeierstrass for Secp256k1 {
    fn a() -> FieldElement<Secp256k1BaseField> {
        Secp256k1BaseFelt::zero()
    }

    fn b() -> FieldElement<Secp256k1BaseField> {
        Secp256k1BaseFelt::from(7)
    }
}

#[cfg(test)]
pub mod tests {
    use lambdaworks_math::{
        cyclic_group::IsGroup, elliptic_curve::traits::IsEllipticCurve,
        field::fields::montgomery_backed_prime_fields::IsModulus, unsigned_integer::element::U256,
    };

    use crate::secp256k1::{Secp256k1, Secp256k1ScalarFieldModulus};

    #[test]
    fn test_generator_order() {
        let expected_order = Secp256k1ScalarFieldModulus::MODULUS;
        assert!(!Secp256k1::generator()
            .operate_with_self(expected_order - U256::from_u64(1))
            .is_neutral_element());

        assert!(Secp256k1::generator()
            .operate_with_self(expected_order)
            .is_neutral_element())
    }
}
