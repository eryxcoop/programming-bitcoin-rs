use lambdaworks_math::unsigned_integer::element::U256;

use super::CanSerialize;

pub(crate) struct U256Serializer;

impl CanSerialize<U256> for U256Serializer {
    type Output = [u8; 32];

    fn serialize(element: &U256) -> Result<Self::Output, super::SerializerError> {
        let mut result = [0u8; 32];
        for (i, limb) in element.limbs.iter().enumerate() {
            let bytes = limb.to_be_bytes();
            for (j, byte) in bytes.iter().enumerate() {
                result[8 * i + j] = *byte;
            }
        }
        Ok(result)
    }

    fn parse(object: &[u8]) -> Result<(U256, usize), super::ParserError> {
        todo!()
    }
}
