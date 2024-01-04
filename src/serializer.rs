use std::marker::PhantomData;

use crate::secp256k1::{curve::Point, fields::BaseFelt};

pub(crate) struct Serializer;

impl Serializer {
    pub fn serialize_base_felt_be(element: &BaseFelt) -> [u8; 32] {
        let representative_limbs = element.representative().limbs;
        let mut result = [0u8; 32];
        for (i, limb) in representative_limbs.iter().enumerate() {
            let bytes = limb.to_be_bytes();
            bytes.iter().enumerate().for_each(|(j, byte)| {
                result[8 * i + j] = *byte;
            })
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::secp256k1::fields::BaseFelt;

    use super::Serializer;

    #[test]
    fn test_serialize_base_felt_be() {
        let base_felt = BaseFelt::from_hex_unchecked(
            "42653bc665797082029f028451150bb340b35f2af1f4c52b0210fb91aea670c3",
        );
        let expected_bytes = [
            66, 101, 59, 198, 101, 121, 112, 130, 2, 159, 2, 132, 81, 21, 11, 179, 64, 179, 95, 42,
            241, 244, 197, 43, 2, 16, 251, 145, 174, 166, 112, 195,
        ];
        let serialized_base_felt = Serializer::serialize_base_felt_be(&base_felt);
        assert_eq!(serialized_base_felt, expected_bytes);
    }
}
