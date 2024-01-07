use lambdaworks_math::{
    field::{
        element::FieldElement,
        fields::montgomery_backed_prime_fields::{IsModulus, U256PrimeField},
    },
    unsigned_integer::element::U256,
};

use crate::{hash::hash256, secp256k1::curve::Point, signature::ECDSASignature};

pub(crate) struct Serializer;

impl Serializer {
    pub fn serialize_u64_varint(uint: u64) -> Vec<u8> {
        if uint < 253 {
            vec![uint as u8]
        } else if uint < 0x10000 {
            let mut result = [0u8; 3];
            result[0] = 253;
            result[1..].copy_from_slice(&u64::to_le_bytes(uint)[..2]);
            result.to_vec()
        } else if uint < 0x100000000 {
            let mut result = [0u8; 5];
            result[0] = 254;
            result[1..].copy_from_slice(&u64::to_le_bytes(uint)[..4]);
            result.to_vec()
        } else {
            let mut result = [0u8; 9];
            result[0] = 255;
            result[1..].copy_from_slice(&u64::to_le_bytes(uint));
            result.to_vec()
        }
    }

    pub fn serialize_u256_element_be(element: &U256) -> [u8; 32] {
        let mut result = [0u8; 32];
        for (i, limb) in element.limbs.iter().enumerate() {
            let bytes = limb.to_be_bytes();
            for (j, byte) in bytes.iter().enumerate() {
                result[8 * i + j] = *byte;
            }
        }
        result
    }
    pub fn serialize_u256_element_der_format(element: &U256) -> Vec<u8> {
        let mut serialized: Vec<u8> = Self::serialize_u256_element_be(element)
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

    pub fn serialize_felt_be<M>(element: &FieldElement<U256PrimeField<M>>) -> [u8; 32]
    where
        M: IsModulus<U256> + Clone,
    {
        Self::serialize_u256_element_be(&element.representative())
    }

    pub fn serialize_point_uncompressed_sec(point: &Point) -> [u8; 65] {
        let point = point.to_affine();
        let [x, y, _] = point.coordinates();
        let serialized_x = Self::serialize_felt_be(x);
        let serialized_y = Self::serialize_felt_be(y);

        let mut result = [0u8; 1 + 32 + 32];
        result[0] = 4;
        result[1..(32 + 1)].copy_from_slice(&serialized_x);
        result[(32 + 1)..].copy_from_slice(&serialized_y);
        result
    }

    pub fn serialize_point_compressed_sec(point: &Point) -> [u8; 33] {
        let point = point.to_affine();
        let [x, y, _] = point.coordinates();
        let serialized_x = Self::serialize_felt_be(x);

        let mut result = [0u8; 1 + 32];
        if y.representative().limbs[3] & 1 == 0 {
            result[0] = 2
        } else {
            result[0] = 3
        }
        result[1..(1 + 32)].copy_from_slice(&serialized_x);
        result
    }

    pub fn serialize_ecdsa_signature(signature: &ECDSASignature) -> Vec<u8> {
        let serialized_r = Self::serialize_u256_element_der_format(&signature.r.representative());
        let serialized_s = Self::serialize_u256_element_der_format(&signature.s.representative());
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

    pub fn base58_encode_with_checksum(input: &[u8]) -> String {
        let mut input_with_checksum = Vec::with_capacity(input.len() + 32);
        input_with_checksum.extend_from_slice(input);
        input_with_checksum.extend_from_slice(&hash256(input)[..4]);
        Self::base58_encode(&input_with_checksum)
    }

    pub fn base58_encode(input: &[u8]) -> String {
        const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut number = input.to_vec();
        let mut result = Vec::new();

        while !number.is_empty() {
            let mut quotient_by_58 = Vec::new();
            let mut remainder = 0;
            for byte in number.iter() {
                let acc = *byte as u32 + 256 * remainder;
                let digit = acc / 58;
                remainder = acc % 58;

                if digit > 0 || !quotient_by_58.is_empty() {
                    quotient_by_58.push(digit as u8);
                }
            }
            result.push(ALPHABET[remainder as usize]);
            number = quotient_by_58;
        }

        for _ in input.iter().take_while(|&&byte| byte == 0) {
            result.push(0x31);
        }
        result.reverse();

        String::from_utf8(result).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use lambdaworks_math::{
        cyclic_group::IsGroup,
        elliptic_curve::traits::{FromAffine, IsEllipticCurve},
        unsigned_integer::element::U256,
    };

    use crate::{
        secp256k1::{
            curve::{Point, Secp256k1},
            fields::{BaseFelt, ScalarFelt},
        },
        signature::ECDSASignature,
    };

    use super::Serializer;

    #[test]
    fn test_serialize_varint_1() {
        let uint = 1u64;
        let expected_bytes = [1];
        let bytes = Serializer::serialize_u64_varint(uint);
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_serialize_varint_2() {
        let uint = 62500u64;
        let expected_bytes = [253, 36, 244];
        let bytes = Serializer::serialize_u64_varint(uint);
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_serialize_varint_3() {
        let uint = 15625000u64;
        let expected_bytes = [254, 40, 107, 238, 0];
        let bytes = Serializer::serialize_u64_varint(uint);
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_serialize_varint_4() {
        let uint = 15258789066406312607_u64;
        let expected_bytes = [255, 159, 58, 195, 181, 207, 27, 194, 211];
        let bytes = Serializer::serialize_u64_varint(uint);
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_serialize_base_felt_be() {
        let base_felt = BaseFelt::from_hex_unchecked(
            "42653bc665797082029f028451150bb340b35f2af1f4c52b0210fb91aea670c3",
        );
        let expected_bytes = [
            66, 101, 59, 198, 101, 121, 112, 130, 2, 159, 2, 132, 81, 21, 11, 179, 64, 179, 95, 42,
            241, 244, 197, 43, 2, 16, 251, 145, 174, 166, 112, 195,
        ];
        let serialized_base_felt = Serializer::serialize_felt_be(&base_felt);
        assert_eq!(serialized_base_felt, expected_bytes);
    }

    #[test]
    fn test_serialize_point_uncompressed_sec_1() {
        let point = Secp256k1::generator();
        let expected_bytes = [
            4, 121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155,
            252, 219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152, 72, 58, 218, 119, 38,
            163, 196, 101, 93, 164, 251, 252, 14, 17, 8, 168, 253, 23, 180, 72, 166, 133, 84, 25,
            156, 71, 208, 143, 251, 16, 212, 184,
        ];
        let serialized_point = Serializer::serialize_point_uncompressed_sec(&point);
        assert_eq!(serialized_point, expected_bytes);
    }

    #[test]
    fn test_serialize_point_uncompressed_sec_2() {
        let point = Secp256k1::generator().operate_with_self(5000u64);
        let expected_bytes = [
            4, 255, 229, 88, 227, 136, 133, 47, 1, 32, 228, 106, 242, 209, 179, 112, 248, 88, 84,
            168, 235, 8, 65, 129, 30, 206, 14, 62, 3, 210, 130, 213, 124, 49, 93, 199, 40, 144,
            164, 241, 10, 20, 129, 192, 49, 176, 59, 53, 27, 13, 199, 153, 1, 202, 24, 160, 12,
            240, 9, 219, 219, 21, 122, 29, 16,
        ];
        let serialized_point = Serializer::serialize_point_uncompressed_sec(&point);
        assert_eq!(serialized_point, expected_bytes);
    }

    #[test]
    fn test_serialize_point_uncompressed_sec_3() {
        let point = Secp256k1::generator().operate_with_self(33466154331649568u64);
        let expected_bytes = [
            4, 2, 127, 61, 161, 145, 132, 85, 224, 60, 70, 246, 89, 38, 106, 27, 181, 32, 78, 149,
            157, 183, 54, 77, 47, 71, 59, 223, 143, 10, 19, 204, 157, 255, 135, 100, 127, 208, 35,
            193, 59, 74, 73, 148, 241, 118, 145, 137, 88, 6, 225, 180, 11, 87, 244, 253, 34, 88,
            26, 79, 70, 133, 31, 59, 6,
        ];
        let serialized_point = Serializer::serialize_point_uncompressed_sec(&point);
        assert_eq!(serialized_point, expected_bytes);
    }

    #[test]
    fn test_serialize_point_uncompressed_sec_4() {
        let point = Secp256k1::generator().operate_with_self(0xdeadbeef12345u64);
        let expected_bytes = [
            4, 217, 12, 214, 37, 238, 135, 221, 56, 101, 109, 217, 92, 247, 159, 101, 246, 15, 114,
            115, 182, 125, 48, 150, 230, 139, 216, 30, 79, 83, 66, 105, 31, 132, 46, 250, 118, 47,
            213, 153, 97, 208, 233, 152, 3, 198, 30, 219, 168, 179, 227, 247, 220, 58, 52, 24, 54,
            249, 119, 51, 174, 191, 152, 113, 33,
        ];
        let serialized_point = Serializer::serialize_point_uncompressed_sec(&point);
        assert_eq!(serialized_point, expected_bytes);
    }

    #[test]
    fn test_serialize_point_compressed_sec_generator() {
        let point = Secp256k1::generator();
        let expected_bytes = [
            2, 121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155,
            252, 219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152,
        ];
        let serialized_point = Serializer::serialize_point_compressed_sec(&point);
        assert_eq!(serialized_point, expected_bytes);
    }

    #[test]
    fn test_serialize_point_compressed_sec_odd() {
        let point = Point::from_affine(
            BaseFelt::from_hex_unchecked(
                "49fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a",
            ),
            BaseFelt::from_hex_unchecked(
                "a56c896489c71dfc65701ce25050f542f336893fb8cd15f4e8e5c124dbf58e47",
            ),
        )
        .unwrap();
        let expected_bytes = [
            3, 73, 252, 78, 99, 30, 54, 36, 165, 69, 222, 63, 137, 245, 216, 104, 76, 123, 129, 56,
            189, 148, 189, 213, 49, 210, 226, 19, 191, 1, 107, 39, 138,
        ];
        let serialized_point = Serializer::serialize_point_compressed_sec(&point);
        assert_eq!(serialized_point, expected_bytes);
    }

    #[test]
    fn test_serialize_point_compressed_sec_even() {
        let point = Point::from_affine(
            BaseFelt::from_hex_unchecked(
                "49fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a",
            ),
            BaseFelt::from_hex_unchecked(
                "5a93769b7638e2039a8fe31dafaf0abd0cc976c04732ea0b171a3eda240a6de8",
            ),
        )
        .unwrap();
        let expected_bytes = [
            2, 73, 252, 78, 99, 30, 54, 36, 165, 69, 222, 63, 137, 245, 216, 104, 76, 123, 129, 56,
            189, 148, 189, 213, 49, 210, 226, 19, 191, 1, 107, 39, 138,
        ];
        let serialized_point = Serializer::serialize_point_compressed_sec(&point);
        assert_eq!(serialized_point, expected_bytes);
    }

    #[test]
    fn test_serialize_point_compressed_sec_1() {
        let point = Secp256k1::generator().operate_with_self(5001u64);
        let serialized_point = Serializer::serialize_point_compressed_sec(&point);
        let expected_bytes = [
            3, 87, 164, 243, 104, 134, 138, 138, 109, 87, 41, 145, 228, 132, 230, 100, 129, 15,
            241, 76, 5, 192, 250, 2, 50, 117, 37, 17, 81, 254, 14, 83, 209,
        ];
        assert_eq!(serialized_point, expected_bytes);
    }

    #[test]
    fn test_serialize_point_compressed_sec_2() {
        let point = Secp256k1::generator().operate_with_self(33549155665686099u64);
        let serialized_point = Serializer::serialize_point_compressed_sec(&point);
        let expected_bytes = [
            2, 147, 62, 194, 210, 177, 17, 185, 39, 55, 236, 18, 241, 197, 210, 15, 50, 51, 160,
            173, 33, 205, 139, 54, 208, 188, 167, 160, 207, 165, 203, 135, 1,
        ];
        assert_eq!(serialized_point, expected_bytes);
    }

    #[test]
    fn test_serialize_point_compressed_sec_3() {
        let point = Secp256k1::generator().operate_with_self(0xdeadbeef54321u64);
        let serialized_point = Serializer::serialize_point_compressed_sec(&point);
        let expected_bytes = [
            2, 150, 190, 91, 18, 146, 246, 200, 86, 179, 197, 101, 78, 136, 111, 193, 53, 17, 70,
            32, 89, 8, 156, 223, 156, 71, 150, 35, 191, 203, 231, 118, 144,
        ];
        assert_eq!(serialized_point, expected_bytes);
    }

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
        let serialized_signature = Serializer::serialize_ecdsa_signature(&signature);
        assert_eq!(serialized_signature, expected_bytes);
    }

    #[test]
    fn test_serialize_u256_element_der_format() {
        let element =
            U256::from_hex_unchecked("05c63fdc786d6a6b904080b58f72edb08da1cf2d309539336a");
        let expected_bytes = [
            25, 5, 198, 63, 220, 120, 109, 106, 107, 144, 64, 128, 181, 143, 114, 237, 176, 141,
            161, 207, 45, 48, 149, 57, 51, 106,
        ];
        let serialized_element = Serializer::serialize_u256_element_der_format(&element);
        assert_eq!(serialized_element, expected_bytes);
    }

    #[test]
    fn test_base58_encoding_1() {
        let bytes = [
            124, 7, 111, 243, 22, 105, 42, 61, 126, 179, 195, 187, 15, 139, 20, 136, 207, 114, 225,
            175, 205, 146, 158, 41, 48, 112, 50, 153, 122, 131, 138, 61,
        ];
        let expected_string = "9MA8fRQrT4u8Zj8ZRd6MAiiyaxb2Y1CMpvVkHQu5hVM6".to_string();
        let base58_encoded = Serializer::base58_encode(&bytes);
        assert_eq!(base58_encoded, expected_string);
    }

    #[test]
    fn test_base58_encoding_2() {
        let bytes = [
            239, 246, 158, 242, 177, 189, 147, 166, 110, 213, 33, 154, 221, 79, 181, 30, 17, 168,
            64, 244, 4, 135, 99, 37, 161, 232, 255, 224, 82, 154, 44,
        ];
        let expected_string = "4fE3H2E6XMp4SsxtwinF7w9a34ooUrwWe4WsW1458Pd".to_string();
        let base58_encoded = Serializer::base58_encode(&bytes);
        assert_eq!(base58_encoded, expected_string);
    }

    #[test]
    fn test_base58_encoding_3() {
        let bytes = [
            199, 32, 127, 238, 25, 125, 39, 198, 24, 174, 166, 33, 64, 111, 107, 245, 239, 111,
            202, 56, 104, 29, 130, 178, 240, 111, 221, 189, 206, 111, 234, 182,
        ];
        let expected_string = "EQJsjkd6JaGwxrjEhfeqPenqHwrBmPQZjJGNSCHBkcF7".to_string();
        let base58_encoded = Serializer::base58_encode(&bytes);
        assert_eq!(base58_encoded, expected_string);
    }
}
