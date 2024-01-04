use lambdaworks_math::{
    elliptic_curve::{
        short_weierstrass::{point::ShortWeierstrassProjectivePoint, traits::IsShortWeierstrass},
        traits::{FromAffine, IsEllipticCurve},
    },
    field::element::FieldElement,
};

use super::fields::{BaseFelt, BaseField};

#[derive(Debug, Clone)]
pub(crate) struct Secp256k1;
pub(crate) type Point = ShortWeierstrassProjectivePoint<Secp256k1>;

impl Secp256k1 {
    const GENERATOR_X: BaseFelt = BaseFelt::from_hex_unchecked(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    );

    const GENERATOR_Y: BaseFelt = BaseFelt::from_hex_unchecked(
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    );
}

impl IsEllipticCurve for Secp256k1 {
    type BaseField = BaseField;
    type PointRepresentation = ShortWeierstrassProjectivePoint<Self>;

    fn generator() -> Self::PointRepresentation {
        ShortWeierstrassProjectivePoint::from_affine(Self::GENERATOR_X, Self::GENERATOR_Y).unwrap()
    }
}

impl IsShortWeierstrass for Secp256k1 {
    fn a() -> FieldElement<BaseField> {
        BaseFelt::zero()
    }

    fn b() -> FieldElement<BaseField> {
        BaseFelt::from(7)
    }
}

#[cfg(test)]
pub mod tests {
    use lambdaworks_math::{
        cyclic_group::IsGroup, elliptic_curve::traits::IsEllipticCurve,
        field::fields::montgomery_backed_prime_fields::IsModulus, unsigned_integer::element::U256,
    };

    use crate::secp256k1::{curve::Secp256k1, fields::ScalarFieldModulus};

    #[test]
    fn test_generator_order() {
        let expected_order = ScalarFieldModulus::MODULUS;
        assert!(!Secp256k1::generator()
            .operate_with_self(expected_order - U256::from_u64(1))
            .is_neutral_element());

        assert!(Secp256k1::generator()
            .operate_with_self(expected_order)
            .is_neutral_element())
    }
}
