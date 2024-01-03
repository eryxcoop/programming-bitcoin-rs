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

pub(crate) const SECP256K1_SUBGROUP_ORDER: U256 =
    U256::from_hex_unchecked("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

/// p = 2**256 - 2**32 - 977
impl IsModulus<U256> for Secp256k1ScalarFieldModulus {
    const MODULUS: U256 = SECP256K1_SUBGROUP_ORDER;
}

pub(crate) const Secp256k1GeneratorX: Secp256k1BaseFelt = Secp256k1BaseFelt::from_hex_unchecked(
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
);
pub(crate) const Secp256k1GeneratorY: Secp256k1BaseFelt = Secp256k1BaseFelt::from_hex_unchecked(
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
);

impl IsEllipticCurve for Secp256k1 {
    type BaseField = Secp256k1BaseField;

    type PointRepresentation = ShortWeierstrassProjectivePoint<Self>;

    fn generator() -> Self::PointRepresentation {
        ShortWeierstrassProjectivePoint::from_affine(Secp256k1GeneratorX, Secp256k1GeneratorY)
            .unwrap()
    }
}

impl IsShortWeierstrass for Secp256k1 {
    fn a() -> FieldElement<Self::BaseField> {
        Secp256k1BaseFelt::zero()
    }

    fn b() -> FieldElement<Self::BaseField> {
        Secp256k1BaseFelt::from_hex_unchecked("7")
    }
}

#[cfg(test)]
pub mod tests {
    use lambdaworks_math::{
        cyclic_group::IsGroup,
        elliptic_curve::{
            short_weierstrass::point::ShortWeierstrassProjectivePoint, traits::IsEllipticCurve,
        },
        unsigned_integer::element::U256,
    };

    use crate::secp256k1::{Secp256k1, SECP256K1_SUBGROUP_ORDER};

    #[test]
    fn test_generator_order() {
        assert_ne!(
            ShortWeierstrassProjectivePoint::<Secp256k1>::neutral_element(),
            Secp256k1::generator().operate_with_self(SECP256K1_SUBGROUP_ORDER - U256::from_u64(1))
        );

        assert_eq!(
            ShortWeierstrassProjectivePoint::<Secp256k1>::neutral_element(),
            Secp256k1::generator().operate_with_self(SECP256K1_SUBGROUP_ORDER)
        )
    }
}
