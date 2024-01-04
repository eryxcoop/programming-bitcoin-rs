use lambdaworks_math::{
    field::{
        element::FieldElement,
        fields::montgomery_backed_prime_fields::{IsModulus, MontgomeryBackendPrimeField},
    },
    unsigned_integer::element::U256,
};

/// The field of definition of `secp256k1`. That is, coordinates of a point in the curve belong
/// to this field.
pub(crate) type BaseField = MontgomeryBackendPrimeField<BaseFieldModulus, 4>;

/// The field with modulus equal to the order of the curve `secp256k1`. Elements of this field
/// can be used as scalars to multiply points on the curve.
pub(crate) type ScalarField = MontgomeryBackendPrimeField<ScalarFieldModulus, 4>;

#[derive(Debug, Clone)]
pub(crate) struct BaseFieldModulus;
pub(crate) type BaseFelt = FieldElement<BaseField>;

#[derive(Debug, Clone)]
pub(crate) struct ScalarFieldModulus;
pub(crate) type ScalarFelt = FieldElement<ScalarField>;

/// p = 2**256 - 2**32 - 977
impl IsModulus<U256> for BaseFieldModulus {
    const MODULUS: U256 = U256::from_hex_unchecked(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
    );
}

impl IsModulus<U256> for ScalarFieldModulus {
    const MODULUS: U256 = U256::from_hex_unchecked(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    );
}
