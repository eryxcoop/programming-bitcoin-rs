use lambdaworks_math::unsigned_integer::element::U256;

use super::CanSerialize;

pub(crate) struct U256BigEndianSerializer;
pub(crate) struct U256DERSerializer;

impl CanSerialize<U256> for U256BigEndianSerializer {
    type Output = [u8; 32];

    fn serialize(element: &U256) -> Self::Output {
        let mut result = [0u8; 32];
        for (i, limb) in element.limbs.iter().enumerate() {
            let bytes = limb.to_be_bytes();
            for (j, byte) in bytes.iter().enumerate() {
                result[8 * i + j] = *byte;
            }
        }
        result
    }

    fn parse(object: &[u8]) -> Result<(U256, usize), super::ParserError> {
        todo!()
    }
}

impl CanSerialize<U256> for U256DERSerializer {
    type Output = Vec<u8>;

    fn serialize(element: &U256) -> Self::Output {
        let mut serialized: Vec<u8> = U256BigEndianSerializer::serialize(element)
            .into_iter()
            .skip_while(|&byte| byte == 0)
            .collect();

        if serialized.first().map_or(false, |&byte| byte > 0x80) {
            serialized.insert(0, 0x00);
        }

        let len = serialized.len();
        let mut result = Vec::with_capacity(len + 1);
        result.push(len as u8);
        result.extend(serialized);

        result
    }

    fn parse(object: &[u8]) -> Result<(U256, usize), super::ParserError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use lambdaworks_math::unsigned_integer::element::U256;

    use crate::serializer::{U256DERSerializer, CanSerialize};


    #[test]
    fn test_serialize_u256_element_der_format() {
        let element =
            U256::from_hex_unchecked("05c63fdc786d6a6b904080b58f72edb08da1cf2d309539336a");
        let expected_bytes = [
            25, 5, 198, 63, 220, 120, 109, 106, 107, 144, 64, 128, 181, 143, 114, 237, 176, 141,
            161, 207, 45, 48, 149, 57, 51, 106,
        ];
        let serialized_element = U256DERSerializer::serialize(&element);
        assert_eq!(serialized_element, expected_bytes);
    }
}
