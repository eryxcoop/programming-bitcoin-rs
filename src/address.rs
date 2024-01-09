use crate::{
    hash::{hash160, hash256},
    serializer::{serializer::Serializer, CanSerialize, PublicKeyUncompressedSerializer, PublicKeyCompressedSerializer},
    signature::PublicKey,
};

pub(crate) enum Chain {
    TestNet,
    MainNet,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Address(String);

impl Chain {
    fn code(self) -> u8 {
        match self {
            Chain::TestNet => 0x6f,
            Chain::MainNet => 0x00,
        }
    }
}

impl Address {
    fn from_serialized_key(data: &[u8], chain: Chain) -> Self {
        let hash = {
            let mut hash = vec![chain.code()];
            hash.extend_from_slice(&hash160(data));
            hash
        };
        Self(Self::base58_encode_with_checksum(&hash))
    }

    fn from_public_key_compressed(key: &PublicKey, chain: Chain) -> Self {
        Self::from_serialized_key(&PublicKeyCompressedSerializer::serialize(key), chain)
    }

    fn from_public_key_uncompressed(key: &PublicKey, chain: Chain) -> Self {
        Self::from_serialized_key(&PublicKeyUncompressedSerializer::serialize(key), chain)
    }

    fn base58_encode_with_checksum(input: &[u8]) -> String {
        let mut input_with_checksum = Vec::with_capacity(input.len() + 32);
        input_with_checksum.extend_from_slice(input);
        input_with_checksum.extend_from_slice(&hash256(input)[..4]);
        Self::base58_encode(&input_with_checksum)
    }

    fn base58_encode(input: &[u8]) -> String {
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
    use lambdaworks_math::{cyclic_group::IsGroup, elliptic_curve::traits::IsEllipticCurve};

    use crate::secp256k1::curve::Secp256k1;

    use super::{Address, Chain};

    #[test]
    fn test_address_1() {
        let public_key = Secp256k1::generator().operate_with_self(5002u64);
        let expected_address = Address("mmTPbXQFxboEtNRkwfh6K51jvdtHLxGeMA".to_string());
        let address = Address::from_public_key_uncompressed(&public_key, Chain::TestNet);
        assert_eq!(address, expected_address);
    }

    #[test]
    fn test_address_2() {
        let public_key = Secp256k1::generator().operate_with_self(33632321603200000u64);
        let expected_address = Address("mopVkxp8UhXqRYbCYJsbeE1h1fiF64jcoH".to_string());
        let address = Address::from_public_key_compressed(&public_key, Chain::TestNet);
        assert_eq!(address, expected_address);
    }

    #[test]
    fn test_address_3() {
        let public_key = Secp256k1::generator().operate_with_self(0x12345deadbeefu64);
        let expected_address = Address("1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1".to_string());
        let address = Address::from_public_key_compressed(&public_key, Chain::MainNet);
        assert_eq!(address, expected_address);
    }

    #[test]
    fn test_base58_encoding_1() {
        let bytes = [
            124, 7, 111, 243, 22, 105, 42, 61, 126, 179, 195, 187, 15, 139, 20, 136, 207, 114, 225,
            175, 205, 146, 158, 41, 48, 112, 50, 153, 122, 131, 138, 61,
        ];
        let expected_string = "9MA8fRQrT4u8Zj8ZRd6MAiiyaxb2Y1CMpvVkHQu5hVM6".to_string();
        let base58_encoded = Address::base58_encode(&bytes);
        assert_eq!(base58_encoded, expected_string);
    }

    #[test]
    fn test_base58_encoding_2() {
        let bytes = [
            239, 246, 158, 242, 177, 189, 147, 166, 110, 213, 33, 154, 221, 79, 181, 30, 17, 168,
            64, 244, 4, 135, 99, 37, 161, 232, 255, 224, 82, 154, 44,
        ];
        let expected_string = "4fE3H2E6XMp4SsxtwinF7w9a34ooUrwWe4WsW1458Pd".to_string();
        let base58_encoded = Address::base58_encode(&bytes);
        assert_eq!(base58_encoded, expected_string);
    }

    #[test]
    fn test_base58_encoding_3() {
        let bytes = [
            199, 32, 127, 238, 25, 125, 39, 198, 24, 174, 166, 33, 64, 111, 107, 245, 239, 111,
            202, 56, 104, 29, 130, 178, 240, 111, 221, 189, 206, 111, 234, 182,
        ];
        let expected_string = "EQJsjkd6JaGwxrjEhfeqPenqHwrBmPQZjJGNSCHBkcF7".to_string();
        let base58_encoded = Address::base58_encode(&bytes);
        assert_eq!(base58_encoded, expected_string);
    }
}
