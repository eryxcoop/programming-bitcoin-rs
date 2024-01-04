use std::marker::PhantomData;

use crate::secp256k1::{curve::Point, fields::BaseFelt};

pub(crate) struct Serializer;

impl Serializer {
    pub fn serialize_base_felt_be(element: &BaseFelt) -> [u8; 32] {
        let representative_limbs = element.representative().limbs;
        let mut result = [0u8; 32];
        for (i, limb) in representative_limbs.iter().enumerate() {
            let bytes = limb.to_be_bytes();
            for (j, byte) in bytes.iter().enumerate() {
                result[8 * i + j] = *byte;
            }
        }
        result
    }

    pub fn serialize_point_uncompressed_sec(point: &Point) -> [u8; 65] {
        let point = point.to_affine();
        let [x, y, _] = point.coordinates();
        let serialized_x = Self::serialize_base_felt_be(x);
        let serialized_y = Self::serialize_base_felt_be(y);

        let mut result = [0u8; 1 + 32 + 32];
        result[0] = 0x04;
        result[1..(32 + 1)].copy_from_slice(&serialized_x);
        result[(32 + 1)..].copy_from_slice(&serialized_y);
        result
    }

    pub fn serialize_point_compressed_sec(point: &Point) -> [u8; 33] {
        let point = point.to_affine();
        let [x, y, _] = point.coordinates();
        let serialized_x = Self::serialize_base_felt_be(x);
        let serialized_y = Self::serialize_base_felt_be(y);
        let mut result = [0u8; 1 + 32];
        result[1..(1 + 32)].copy_from_slice(&serialized_x);
        if serialized_y[31] & 1 == 0 {
            result[0] = 0x2
        } else {
            result[0] = 0x3
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use lambdaworks_math::elliptic_curve::traits::{FromAffine, IsEllipticCurve};

    use crate::secp256k1::{
        curve::{Point, Secp256k1},
        fields::BaseFelt,
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
}
