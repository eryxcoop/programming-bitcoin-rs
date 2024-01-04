use std::marker::PhantomData;

use lambdaworks_math::unsigned_integer::element::U256;

use crate::{
    secp256k1::{
        curve::Point,
        fields::{BaseFelt, ScalarFelt},
    },
    signature::ECDSASignature,
};

pub(crate) struct Serializer;

impl Serializer {
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

    pub fn serialize_base_felt_be(element: &BaseFelt) -> [u8; 32] {
        Self::serialize_u256_element_be(&element.representative())
    }

    pub fn serialize_scalar_felt_be(element: &ScalarFelt) -> [u8; 32] {
        Self::serialize_u256_element_be(&element.representative())
    }

    pub fn serialize_point_uncompressed_sec(point: &Point) -> [u8; 65] {
        let point = point.to_affine();
        let [x, y, _] = point.coordinates();
        let serialized_x = Self::serialize_base_felt_be(x);
        let serialized_y = Self::serialize_base_felt_be(y);

        let mut result = [0u8; 1 + 32 + 32];
        result[0] = 4;
        result[1..(32 + 1)].copy_from_slice(&serialized_x);
        result[(32 + 1)..].copy_from_slice(&serialized_y);
        result
    }

    pub fn serialize_point_compressed_sec(point: &Point) -> [u8; 33] {
        let point = point.to_affine();
        let [x, y, _] = point.coordinates();
        let serialized_x = Self::serialize_base_felt_be(x);

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
}

#[cfg(test)]
mod tests {
    use lambdaworks_math::{
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

    #[test]
    fn test_serialize_point_uncompressed_sec() {
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
        let element = U256::from_hex_unchecked("05c63fdc786d6a6b904080b58f72edb08da1cf2d309539336a");
        let expected_bytes = [
            25, 5, 198, 63, 220, 120, 109, 106, 107, 144, 64, 128, 181, 143, 114, 237, 176, 141,
            161, 207, 45, 48, 149, 57, 51, 106,
        ];
        let serialized_element = Serializer::serialize_u256_element_der_format(&element);
        assert_eq!(serialized_element, expected_bytes);
    }
}
