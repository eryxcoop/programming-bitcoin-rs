use lambdaworks_math::{
    field::{
        element::FieldElement,
        fields::montgomery_backed_prime_fields::{IsModulus, U256PrimeField},
    },
    unsigned_integer::element::U256,
};

use crate::{
    hash::hash256,
    secp256k1::curve::Point,
    signature::ECDSASignature,
    transaction::{Command, Script},
};

use super::{CanSerialize, SerializerError, U256BigEndianSerializer, VarIntSerializer, U256DERSerializer};

pub(crate) struct Serializer;

impl Serializer {
    pub fn serialize_felt_be<M>(element: &FieldElement<U256PrimeField<M>>) -> [u8; 32]
    where
        M: IsModulus<U256> + Clone,
    {
        U256BigEndianSerializer::serialize(&element.representative())
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

    fn serialize_command(command: &Command) -> Vec<u8> {
        match command {
            Command::Operation(value) => vec![*value],
            Command::Element(element_bytes) => {
                let length = element_bytes.len();
                if length <= 75 {
                    let mut result = vec![length as u8];
                    result.extend_from_slice(element_bytes);
                    result
                } else if 75 < length && length < 0x100 {
                    let mut result = vec![76, length as u8];
                    result.extend_from_slice(element_bytes);
                    result
                } else if (0x100..0x10000).contains(&length) {
                    let length_as_bytes = &length.to_le_bytes()[..2];
                    let mut result = vec![77];
                    result.extend_from_slice(length_as_bytes);
                    result.extend_from_slice(element_bytes);
                    result
                } else {
                    // Code unreachable given Script's invariants
                    vec![]
                }
            }
        }
    }

    pub fn serialize_script(script: &Script) -> Result<Vec<u8>, SerializerError> {
        let serialized_script: Vec<u8> = script
            .commands()
            .iter()
            .flat_map(Self::serialize_command)
            .collect();
        let mut result = VarIntSerializer::serialize(&(serialized_script.len() as u64));
        result.extend_from_slice(&serialized_script);
        Ok(result)
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
        transaction::{Command, Script},
    };

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
        let expected_bytes = [
            3, 87, 164, 243, 104, 134, 138, 138, 109, 87, 41, 145, 228, 132, 230, 100, 129, 15,
            241, 76, 5, 192, 250, 2, 50, 117, 37, 17, 81, 254, 14, 83, 209,
        ];
        let serialized_point = Serializer::serialize_point_compressed_sec(&point);
        assert_eq!(serialized_point, expected_bytes);
    }

    #[test]
    fn test_serialize_point_compressed_sec_2() {
        let point = Secp256k1::generator().operate_with_self(33549155665686099u64);
        let expected_bytes = [
            2, 147, 62, 194, 210, 177, 17, 185, 39, 55, 236, 18, 241, 197, 210, 15, 50, 51, 160,
            173, 33, 205, 139, 54, 208, 188, 167, 160, 207, 165, 203, 135, 1,
        ];
        let serialized_point = Serializer::serialize_point_compressed_sec(&point);
        assert_eq!(serialized_point, expected_bytes);
    }

    #[test]
    fn test_serialize_point_compressed_sec_3() {
        let point = Secp256k1::generator().operate_with_self(0xdeadbeef54321u64);
        let expected_bytes = [
            2, 150, 190, 91, 18, 146, 246, 200, 86, 179, 197, 101, 78, 136, 111, 193, 53, 17, 70,
            32, 89, 8, 156, 223, 156, 71, 150, 35, 191, 203, 231, 118, 144,
        ];
        let serialized_point = Serializer::serialize_point_compressed_sec(&point);
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

    #[test]
    fn test_serialize_script_1() {
        let script = Script::new(vec![
            Command::Element(vec![
                4, 136, 115, 135, 228, 82, 184, 234, 204, 74, 207, 222, 16, 217, 170, 247, 246,
                217, 160, 249, 117, 170, 187, 16, 208, 6, 228, 218, 86, 135, 68, 208, 108, 97, 222,
                109, 149, 35, 28, 216, 144, 38, 226, 134, 223, 59, 106, 228, 168, 148, 163, 55,
                142, 57, 62, 147, 160, 244, 91, 102, 99, 41, 160, 174, 52,
            ]),
            Command::Operation(0xac),
        ])
        .unwrap();
        let expected_bytes = [
            67, 65, 4, 136, 115, 135, 228, 82, 184, 234, 204, 74, 207, 222, 16, 217, 170, 247, 246,
            217, 160, 249, 117, 170, 187, 16, 208, 6, 228, 218, 86, 135, 68, 208, 108, 97, 222,
            109, 149, 35, 28, 216, 144, 38, 226, 134, 223, 59, 106, 228, 168, 148, 163, 55, 142,
            57, 62, 147, 160, 244, 91, 102, 99, 41, 160, 174, 52, 172,
        ];
        let bytes = Serializer::serialize_script(&script).unwrap();
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_serialize_script_2() {
        let script = Script::new(vec![
            Command::Element(vec![
                48, 69, 2, 33, 0, 237, 129, 255, 25, 46, 117, 163, 253, 35, 4, 0, 77, 202, 219,
                116, 111, 165, 226, 76, 80, 49, 204, 252, 242, 19, 32, 176, 39, 116, 87, 201, 143,
                2, 32, 122, 152, 109, 149, 92, 110, 12, 179, 93, 68, 106, 137, 211, 245, 97, 0,
                244, 215, 246, 120, 1, 195, 25, 103, 116, 58, 156, 142, 16, 97, 91, 237, 1,
            ]),
            Command::Element(vec![
                3, 73, 252, 78, 99, 30, 54, 36, 165, 69, 222, 63, 137, 245, 216, 104, 76, 123, 129,
                56, 189, 148, 189, 213, 49, 210, 226, 19, 191, 1, 107, 39, 138,
            ]),
        ])
        .unwrap();
        let expected_bytes = [
            107, 72, 48, 69, 2, 33, 0, 237, 129, 255, 25, 46, 117, 163, 253, 35, 4, 0, 77, 202,
            219, 116, 111, 165, 226, 76, 80, 49, 204, 252, 242, 19, 32, 176, 39, 116, 87, 201, 143,
            2, 32, 122, 152, 109, 149, 92, 110, 12, 179, 93, 68, 106, 137, 211, 245, 97, 0, 244,
            215, 246, 120, 1, 195, 25, 103, 116, 58, 156, 142, 16, 97, 91, 237, 1, 33, 3, 73, 252,
            78, 99, 30, 54, 36, 165, 69, 222, 63, 137, 245, 216, 104, 76, 123, 129, 56, 189, 148,
            189, 213, 49, 210, 226, 19, 191, 1, 107, 39, 138,
        ];
        let bytes = Serializer::serialize_script(&script).unwrap();
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_serialize_script_3() {
        let script = Script::new(vec![
            Command::Element(vec![
                37, 80, 68, 70, 45, 49, 46, 51, 10, 37, 226, 227, 207, 211, 10, 10, 10, 49, 32, 48,
                32, 111, 98, 106, 10, 60, 60, 47, 87, 105, 100, 116, 104, 32, 50, 32, 48, 32, 82,
                47, 72, 101, 105, 103, 104, 116, 32, 51, 32, 48, 32, 82, 47, 84, 121, 112, 101, 32,
                52, 32, 48, 32, 82, 47, 83, 117, 98, 116, 121, 112, 101, 32, 53, 32, 48, 32, 82,
                47, 70, 105, 108, 116, 101, 114, 32, 54, 32, 48, 32, 82, 47, 67, 111, 108, 111,
                114, 83, 112, 97, 99, 101, 32, 55, 32, 48, 32, 82, 47, 76, 101, 110, 103, 116, 104,
                32, 56, 32, 48, 32, 82, 47, 66, 105, 116, 115, 80, 101, 114, 67, 111, 109, 112,
                111, 110, 101, 110, 116, 32, 56, 62, 62, 10, 115, 116, 114, 101, 97, 109, 10, 255,
                216, 255, 254, 0, 36, 83, 72, 65, 45, 49, 32, 105, 115, 32, 100, 101, 97, 100, 33,
                33, 33, 33, 33, 133, 47, 236, 9, 35, 57, 117, 156, 57, 177, 161, 198, 60, 76, 151,
                225, 255, 254, 1, 127, 70, 220, 147, 166, 182, 126, 1, 59, 2, 154, 170, 29, 178,
                86, 11, 69, 202, 103, 214, 136, 199, 248, 75, 140, 76, 121, 31, 224, 43, 61, 246,
                20, 248, 109, 177, 105, 9, 1, 197, 107, 69, 193, 83, 10, 254, 223, 183, 96, 56,
                233, 114, 114, 47, 231, 173, 114, 143, 14, 73, 4, 224, 70, 194, 48, 87, 15, 233,
                212, 19, 152, 171, 225, 46, 245, 188, 148, 43, 227, 53, 66, 164, 128, 45, 152, 181,
                215, 15, 42, 51, 46, 195, 127, 172, 53, 20, 231, 77, 220, 15, 44, 193, 168, 116,
                205, 12, 120, 48, 90, 33, 86, 100, 97, 48, 151, 137, 96, 107, 208, 191, 63, 152,
                205, 168, 4, 70, 41, 161,
            ]),
            Command::Element(vec![
                37, 80, 68, 70, 45, 49, 46, 51, 10, 37, 226, 227, 207, 211, 10, 10, 10, 49, 32, 48,
                32, 111, 98, 106, 10, 60, 60, 47, 87, 105, 100, 116, 104, 32, 50, 32, 48, 32, 82,
                47, 72, 101, 105, 103, 104, 116, 32, 51, 32, 48, 32, 82, 47, 84, 121, 112, 101, 32,
                52, 32, 48, 32, 82, 47, 83, 117, 98, 116, 121, 112, 101, 32, 53, 32, 48, 32, 82,
                47, 70, 105, 108, 116, 101, 114, 32, 54, 32, 48, 32, 82, 47, 67, 111, 108, 111,
                114, 83, 112, 97, 99, 101, 32, 55, 32, 48, 32, 82, 47, 76, 101, 110, 103, 116, 104,
                32, 56, 32, 48, 32, 82, 47, 66, 105, 116, 115, 80, 101, 114, 67, 111, 109, 112,
                111, 110, 101, 110, 116, 32, 56, 62, 62, 10, 115, 116, 114, 101, 97, 109, 10, 255,
                216, 255, 254, 0, 36, 83, 72, 65, 45, 49, 32, 105, 115, 32, 100, 101, 97, 100, 33,
                33, 33, 33, 33, 133, 47, 236, 9, 35, 57, 117, 156, 57, 177, 161, 198, 60, 76, 151,
                225, 255, 254, 1, 115, 70, 220, 145, 102, 182, 126, 17, 143, 2, 154, 182, 33, 178,
                86, 15, 249, 202, 103, 204, 168, 199, 248, 91, 168, 76, 121, 3, 12, 43, 61, 226,
                24, 248, 109, 179, 169, 9, 1, 213, 223, 69, 193, 79, 38, 254, 223, 179, 220, 56,
                233, 106, 194, 47, 231, 189, 114, 143, 14, 69, 188, 224, 70, 210, 60, 87, 15, 235,
                20, 19, 152, 187, 85, 46, 245, 160, 168, 43, 227, 49, 254, 164, 128, 55, 184, 181,
                215, 31, 14, 51, 46, 223, 147, 172, 53, 0, 235, 77, 220, 13, 236, 193, 168, 100,
                121, 12, 120, 44, 118, 33, 86, 96, 221, 48, 151, 145, 208, 107, 208, 175, 63, 152,
                205, 164, 188, 70, 41, 177,
            ]),
            Command::Operation(0x6e),
            Command::Operation(0x87),
            Command::Operation(0x91),
            Command::Operation(0x69),
            Command::Operation(0xa7),
            Command::Operation(0x7c),
            Command::Operation(0xa7),
            Command::Operation(0x87),
        ])
        .unwrap();
        let expected_bytes = [
            253, 142, 2, 77, 64, 1, 37, 80, 68, 70, 45, 49, 46, 51, 10, 37, 226, 227, 207, 211, 10,
            10, 10, 49, 32, 48, 32, 111, 98, 106, 10, 60, 60, 47, 87, 105, 100, 116, 104, 32, 50,
            32, 48, 32, 82, 47, 72, 101, 105, 103, 104, 116, 32, 51, 32, 48, 32, 82, 47, 84, 121,
            112, 101, 32, 52, 32, 48, 32, 82, 47, 83, 117, 98, 116, 121, 112, 101, 32, 53, 32, 48,
            32, 82, 47, 70, 105, 108, 116, 101, 114, 32, 54, 32, 48, 32, 82, 47, 67, 111, 108, 111,
            114, 83, 112, 97, 99, 101, 32, 55, 32, 48, 32, 82, 47, 76, 101, 110, 103, 116, 104, 32,
            56, 32, 48, 32, 82, 47, 66, 105, 116, 115, 80, 101, 114, 67, 111, 109, 112, 111, 110,
            101, 110, 116, 32, 56, 62, 62, 10, 115, 116, 114, 101, 97, 109, 10, 255, 216, 255, 254,
            0, 36, 83, 72, 65, 45, 49, 32, 105, 115, 32, 100, 101, 97, 100, 33, 33, 33, 33, 33,
            133, 47, 236, 9, 35, 57, 117, 156, 57, 177, 161, 198, 60, 76, 151, 225, 255, 254, 1,
            127, 70, 220, 147, 166, 182, 126, 1, 59, 2, 154, 170, 29, 178, 86, 11, 69, 202, 103,
            214, 136, 199, 248, 75, 140, 76, 121, 31, 224, 43, 61, 246, 20, 248, 109, 177, 105, 9,
            1, 197, 107, 69, 193, 83, 10, 254, 223, 183, 96, 56, 233, 114, 114, 47, 231, 173, 114,
            143, 14, 73, 4, 224, 70, 194, 48, 87, 15, 233, 212, 19, 152, 171, 225, 46, 245, 188,
            148, 43, 227, 53, 66, 164, 128, 45, 152, 181, 215, 15, 42, 51, 46, 195, 127, 172, 53,
            20, 231, 77, 220, 15, 44, 193, 168, 116, 205, 12, 120, 48, 90, 33, 86, 100, 97, 48,
            151, 137, 96, 107, 208, 191, 63, 152, 205, 168, 4, 70, 41, 161, 77, 64, 1, 37, 80, 68,
            70, 45, 49, 46, 51, 10, 37, 226, 227, 207, 211, 10, 10, 10, 49, 32, 48, 32, 111, 98,
            106, 10, 60, 60, 47, 87, 105, 100, 116, 104, 32, 50, 32, 48, 32, 82, 47, 72, 101, 105,
            103, 104, 116, 32, 51, 32, 48, 32, 82, 47, 84, 121, 112, 101, 32, 52, 32, 48, 32, 82,
            47, 83, 117, 98, 116, 121, 112, 101, 32, 53, 32, 48, 32, 82, 47, 70, 105, 108, 116,
            101, 114, 32, 54, 32, 48, 32, 82, 47, 67, 111, 108, 111, 114, 83, 112, 97, 99, 101, 32,
            55, 32, 48, 32, 82, 47, 76, 101, 110, 103, 116, 104, 32, 56, 32, 48, 32, 82, 47, 66,
            105, 116, 115, 80, 101, 114, 67, 111, 109, 112, 111, 110, 101, 110, 116, 32, 56, 62,
            62, 10, 115, 116, 114, 101, 97, 109, 10, 255, 216, 255, 254, 0, 36, 83, 72, 65, 45, 49,
            32, 105, 115, 32, 100, 101, 97, 100, 33, 33, 33, 33, 33, 133, 47, 236, 9, 35, 57, 117,
            156, 57, 177, 161, 198, 60, 76, 151, 225, 255, 254, 1, 115, 70, 220, 145, 102, 182,
            126, 17, 143, 2, 154, 182, 33, 178, 86, 15, 249, 202, 103, 204, 168, 199, 248, 91, 168,
            76, 121, 3, 12, 43, 61, 226, 24, 248, 109, 179, 169, 9, 1, 213, 223, 69, 193, 79, 38,
            254, 223, 179, 220, 56, 233, 106, 194, 47, 231, 189, 114, 143, 14, 69, 188, 224, 70,
            210, 60, 87, 15, 235, 20, 19, 152, 187, 85, 46, 245, 160, 168, 43, 227, 49, 254, 164,
            128, 55, 184, 181, 215, 31, 14, 51, 46, 223, 147, 172, 53, 0, 235, 77, 220, 13, 236,
            193, 168, 100, 121, 12, 120, 44, 118, 33, 86, 96, 221, 48, 151, 145, 208, 107, 208,
            175, 63, 152, 205, 164, 188, 70, 41, 177, 110, 135, 145, 105, 167, 124, 167, 135,
        ];
        let bytes = Serializer::serialize_script(&script).unwrap();
        assert_eq!(bytes, expected_bytes);
    }
}
