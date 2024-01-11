use lambdaworks_math::{
    field::{
        element::FieldElement,
        fields::montgomery_backed_prime_fields::{IsModulus, MontgomeryBackendPrimeField},
    },
    unsigned_integer::element::U256,
};

use crate::signature::PublicKey;

use super::{CanSerialize, U256BigEndianSerializer};

pub(crate) struct FeltSerializer;

pub struct PublicKeyCompressedSerializer;

pub struct PublicKeyUncompressedSerializer;

impl<M> CanSerialize<FieldElement<MontgomeryBackendPrimeField<M, 4>>> for FeltSerializer
where
    M: IsModulus<U256> + Clone,
{
    type Output = [u8; 32];

    fn serialize(element: &FieldElement<MontgomeryBackendPrimeField<M, 4>>) -> Self::Output {
        U256BigEndianSerializer::serialize(&element.representative())
    }
}

impl CanSerialize<PublicKey> for PublicKeyCompressedSerializer {
    type Output = [u8; 33];

    fn serialize(point: &PublicKey) -> Self::Output {
        let point = point.to_affine();
        let [x, y, _] = point.coordinates();
        let serialized_x = FeltSerializer::serialize(x);

        let mut result = [0u8; 1 + 32];
        if y.representative().limbs[3] & 1 == 0 {
            result[0] = 2
        } else {
            result[0] = 3
        }
        result[1..(1 + 32)].copy_from_slice(&serialized_x);
        result
    }
}

impl CanSerialize<PublicKey> for PublicKeyUncompressedSerializer {
    type Output = [u8; 65];

    fn serialize(point: &PublicKey) -> Self::Output {
        let point = point.to_affine();
        let [x, y, _] = point.coordinates();
        let serialized_x = FeltSerializer::serialize(x);
        let serialized_y = FeltSerializer::serialize(y);

        let mut result = [0u8; 1 + 32 + 32];
        result[0] = 4;
        result[1..(32 + 1)].copy_from_slice(&serialized_x);
        result[(32 + 1)..].copy_from_slice(&serialized_y);
        result
    }
}

#[cfg(test)]
mod tests {
    use lambdaworks_math::{
        cyclic_group::IsGroup,
        elliptic_curve::traits::{FromAffine, IsEllipticCurve},
    };

    use crate::{
        secp256k1::{
            curve::{Point, Secp256k1},
            fields::BaseFelt,
        },
        serializer::{
            public_key::{
                FeltSerializer, PublicKeyCompressedSerializer, PublicKeyUncompressedSerializer,
            },
            CanSerialize,
        },
    };

    #[test]
    fn test_serialize_base_felt_be() {
        let base_felt = BaseFelt::from_hex_unchecked(
            "42653bc665797082029f028451150bb340b35f2af1f4c52b0210fb91aea670c3",
        );
        let expected_bytes = [
            66, 101, 59, 198, 101, 121, 112, 130, 2, 159, 2, 132, 81, 21, 11, 179, 64, 179, 95, 42,
            241, 244, 197, 43, 2, 16, 251, 145, 174, 166, 112, 195,
        ];
        let serialized_base_felt = FeltSerializer::serialize(&base_felt);
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
        let serialized_point = PublicKeyUncompressedSerializer::serialize(&point);
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
        let serialized_point = PublicKeyUncompressedSerializer::serialize(&point);
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
        let serialized_point = PublicKeyUncompressedSerializer::serialize(&point);
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
        let serialized_point = PublicKeyUncompressedSerializer::serialize(&point);
        assert_eq!(serialized_point, expected_bytes);
    }

    #[test]
    fn test_serialize_point_compressed_sec_generator() {
        let point = Secp256k1::generator();
        let expected_bytes = [
            2, 121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155,
            252, 219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152,
        ];
        let serialized_point = PublicKeyCompressedSerializer::serialize(&point);
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
        let serialized_point = PublicKeyCompressedSerializer::serialize(&point);
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
        let serialized_point = PublicKeyCompressedSerializer::serialize(&point);
        assert_eq!(serialized_point, expected_bytes);
    }

    #[test]
    fn test_serialize_point_compressed_sec_1() {
        let point = Secp256k1::generator().operate_with_self(5001u64);
        let expected_bytes = [
            3, 87, 164, 243, 104, 134, 138, 138, 109, 87, 41, 145, 228, 132, 230, 100, 129, 15,
            241, 76, 5, 192, 250, 2, 50, 117, 37, 17, 81, 254, 14, 83, 209,
        ];
        let serialized_point = PublicKeyCompressedSerializer::serialize(&point);
        assert_eq!(serialized_point, expected_bytes);
    }

    #[test]
    fn test_serialize_point_compressed_sec_2() {
        let point = Secp256k1::generator().operate_with_self(33549155665686099u64);
        let expected_bytes = [
            2, 147, 62, 194, 210, 177, 17, 185, 39, 55, 236, 18, 241, 197, 210, 15, 50, 51, 160,
            173, 33, 205, 139, 54, 208, 188, 167, 160, 207, 165, 203, 135, 1,
        ];
        let serialized_point = PublicKeyCompressedSerializer::serialize(&point);
        assert_eq!(serialized_point, expected_bytes);
    }

    #[test]
    fn test_serialize_point_compressed_sec_3() {
        let point = Secp256k1::generator().operate_with_self(0xdeadbeef54321u64);
        let expected_bytes = [
            2, 150, 190, 91, 18, 146, 246, 200, 86, 179, 197, 101, 78, 136, 111, 193, 53, 17, 70,
            32, 89, 8, 156, 223, 156, 71, 150, 35, 191, 203, 231, 118, 144,
        ];
        let serialized_point = PublicKeyCompressedSerializer::serialize(&point);
        assert_eq!(serialized_point, expected_bytes);
    }
}
