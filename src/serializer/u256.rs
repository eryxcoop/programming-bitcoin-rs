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

    fn serialize(object: &U256) -> Self::Output {
        todo!()
    }

    fn parse(object: &[u8]) -> Result<(U256, usize), super::ParserError> {
        todo!()
    }
}
