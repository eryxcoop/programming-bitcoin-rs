use crate::signature::{self, ECDSASignature};

use super::{CanSerialize, U256DERSerializer};

pub(crate) struct ECDSASignatureSerializer;

impl CanSerialize<ECDSASignature> for ECDSASignatureSerializer {
    type Output = Vec<u8>;

    fn serialize(signature: &ECDSASignature) -> Self::Output {
        let serialized_r = U256DERSerializer::serialize(&signature.r.representative());
        let serialized_s = U256DERSerializer::serialize(&signature.s.representative());
        let signature_length = 2 + serialized_r.len() + serialized_s.len();
        let mut result = Vec::with_capacity(signature_length);
        result.push(0x30);
        result.push(signature_length as u8);
        result.push(2);
        result.extend_from_slice(&serialized_r);
        result.push(2);
        result.extend_from_slice(&serialized_s);
        result
    }

    fn parse(object: &[u8]) -> Result<(ECDSASignature, usize), super::ParserError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        secp256k1::fields::ScalarFelt,
        serializer::{signature::ECDSASignatureSerializer, CanSerialize},
        signature::ECDSASignature,
    };

    #[test]
    fn test_serialize_ecdsa_signature() {
        let r = ScalarFelt::from_hex_unchecked(
            "37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6",
        );
        let s = ScalarFelt::from_hex_unchecked(
            "8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec",
        );
        let signature = ECDSASignature::new(r, s);
        let expected_bytes = vec![
            48, 69, 2, 32, 55, 32, 106, 6, 16, 153, 92, 88, 7, 73, 153, 203, 151, 103, 184, 122,
            244, 196, 151, 141, 182, 140, 6, 232, 230, 232, 29, 40, 32, 71, 167, 198, 2, 33, 0,
            140, 166, 55, 89, 193, 21, 126, 190, 174, 192, 208, 60, 236, 202, 17, 159, 201, 167,
            91, 248, 230, 208, 250, 101, 200, 65, 200, 226, 115, 140, 218, 236,
        ];
        let serialized_signature = ECDSASignatureSerializer::serialize(&signature);
        assert_eq!(serialized_signature, expected_bytes);
    }
}
