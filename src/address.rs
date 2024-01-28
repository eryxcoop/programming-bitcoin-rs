use std::fmt::Display;

use crate::{
    hash::{hash160, hash256},
    public_key::PublicKey,
    serializer::{CanSerialize, PublicKeyCompressedSerializer, PublicKeyUncompressedSerializer},
};

#[derive(Clone)]
pub enum Chain {
    TestNet,
    MainNet,
}

pub enum Encoding {
    CompressedBase58,
    UncompressedBase58,
    Bech32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Address(String);

impl Chain {
    fn code(self) -> u8 {
        match self {
            Chain::TestNet => 0x6f,
            Chain::MainNet => 0x00,
        }
    }

    fn hrp(self) -> [u8; 2] {
        match self {
            Chain::TestNet => b"tb".to_owned(),
            Chain::MainNet => b"bc".to_owned(),
        }
    }
}

impl Address {
    pub fn new(public_key: &PublicKey, chain: Chain, encoding: Encoding) -> Self {
        match encoding {
            Encoding::CompressedBase58 => {
                let public_key_bytes = &PublicKeyCompressedSerializer::serialize(public_key);
                Self::from_serialized_public_key_base58_check(public_key_bytes, chain)
            }
            Encoding::UncompressedBase58 => {
                let public_key_bytes = &PublicKeyUncompressedSerializer::serialize(public_key);
                Self::from_serialized_public_key_base58_check(public_key_bytes, chain)
            }
            Encoding::Bech32 => {
                let public_key_bytes = PublicKeyCompressedSerializer::serialize(public_key);
                let bytes = hash160(&public_key_bytes);
                Address(Self::encode_bech32(&bytes, chain))
            }
        }
    }

    fn from_serialized_public_key_base58_check(data: &[u8], chain: Chain) -> Self {
        let hash = {
            let mut hash = vec![chain.code()];
            hash.extend_from_slice(&hash160(data));
            hash
        };
        Self(Self::base58_encode_with_checksum(&hash))
    }

    fn base58_encode_with_checksum(input: &[u8]) -> String {
        let mut input_with_checksum = Vec::with_capacity(input.len() + 32);
        input_with_checksum.extend_from_slice(input);
        input_with_checksum.extend_from_slice(&hash256(input)[..4]);
        Self::base58_encode(&input_with_checksum)
    }

    fn base58_encode(input: &[u8]) -> String {
        const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let input_base = to_base::<58>(input);
        let mut result: Vec<u8> = input_base.iter().map(|b| ALPHABET[*b as usize]).collect();

        for _ in input.iter().take_while(|&&byte| byte == 0) {
            result.push(0x31);
        }
        result.reverse();

        String::from_utf8(result).unwrap()
    }

    fn bech32_polymod(bytes: &[u8]) -> u32 {
        let mut c = 1u32;
        for v_i in bytes.iter() {
            let c0 = (c >> 25) as u8;
            c = ((c & 0x1ffffff) << 5) ^ (*v_i as u32);
            if c0 & 1 == 1 {
                //     k(x) = {29}x^5 + {22}x^4 + {20}x^3 + {21}x^2 + {29}x + {18}
                c ^= 0x3b6a57b2;
            }
            if c0 & 2 == 2 {
                //  {2}k(x) = {19}x^5 +  {5}x^4 +     x^3 +  {3}x^2 + {19}x + {13}
                c ^= 0x26508e6d;
            }
            if c0 & 4 == 4 {
                //  {4}k(x) = {15}x^5 + {10}x^4 +  {2}x^3 +  {6}x^2 + {15}x + {26}
                c ^= 0x1ea119fa;
            }
            if c0 & 8 == 8 {
                //  {8}k(x) = {30}x^5 + {20}x^4 +  {4}x^3 + {12}x^2 + {30}x + {29}
                c ^= 0x3d4233dd;
            }
            if c0 & 16 == 16 {
                // {16}k(x) = {21}x^5 +     x^4 +  {8}x^3 + {24}x^2 + {21}x + {19}
                c ^= 0x2a1462b3;
            };
        }
        c
    }

    fn expand_human_readable_part(bytes: [u8; 2]) -> Vec<u8> {
        let mut result = vec![0u8; 5];
        let c = bytes[0];
        result[0] = c >> 5;
        result[3] = c & 0x1f;

        let c = bytes[1];
        result[1] = c >> 5;
        result[4] = c & 0x1f;

        result[2] = 0;
        result
    }

    fn bech32_checksum(bytes: &[u8], chain: Chain) -> [u8; 6] {
        let mut enc = Self::expand_human_readable_part(chain.hrp()).to_vec();
        enc.extend_from_slice(bytes);
        enc.extend_from_slice(&[0u8; 6]);
        // let m = Self::bech32_polymod(&enc) ^ 0x2bc830a3; // Bech32m
        let m = Self::bech32_polymod(&enc) ^ 1; // Bech32
        let mut result = [0u8; 6];
        for (i, byte) in result.iter_mut().enumerate() {
            *byte = ((m >> (5 * (5 - i))) as u8) & 31;
        }
        result
    }

    fn encode_bech32(bytes: &[u8], chain: Chain) -> String {
        const ALPHABET: &[u8] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l".as_bytes();
        let mut input_base_32 = to_base::<32>(bytes);
        input_base_32.push(0);
        input_base_32.reverse();
        let checksum = Self::bech32_checksum(&input_base_32, chain.clone());

        let mut result = chain.hrp().to_vec();
        result.push(49); // Separator "1"
        for c in input_base_32.iter() {
            result.push(ALPHABET[*c as usize])
        }
        for c in checksum.iter() {
            result.push(ALPHABET[*c as usize])
        }
        String::from_utf8(result).unwrap()
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn to_base<const N: u32>(bytes: &[u8]) -> Vec<u8> {
    let mut number = bytes.to_vec();
    let mut input_base = Vec::new();
    while !number.is_empty() {
        let mut quotient = Vec::new();
        let mut remainder = 0;
        for byte in number.iter() {
            let acc = *byte as u32 + 256 * remainder;
            let digit = acc / N;
            remainder = acc % N;

            if digit > 0 || !quotient.is_empty() {
                quotient.push(digit as u8);
            }
        }
        input_base.push(remainder as u8);
        number = quotient;
    }
    input_base
}

#[cfg(test)]
mod tests {
    use lambdaworks_math::unsigned_integer::element::U256;

    use crate::{address::Encoding, public_key::PublicKey};

    use super::{Address, Chain};

    #[test]
    fn test_address_1() {
        let public_key = PublicKey::from_u256(U256::from_u64(5002u64));
        let expected_address = Address("mmTPbXQFxboEtNRkwfh6K51jvdtHLxGeMA".to_string());
        let address = Address::new(&public_key, Chain::TestNet, Encoding::UncompressedBase58);
        assert_eq!(address, expected_address);
    }

    #[test]
    fn test_address_2() {
        let public_key = PublicKey::from_u256(U256::from_u64(33632321603200000u64));
        let expected_address = Address("mopVkxp8UhXqRYbCYJsbeE1h1fiF64jcoH".to_string());
        let address = Address::new(&public_key, Chain::TestNet, Encoding::CompressedBase58);
        assert_eq!(address, expected_address);
    }

    #[test]
    fn test_address_3() {
        let public_key = PublicKey::from_u256(U256::from_u64(0x12345deadbeefu64));
        let expected_address = Address("1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1".to_string());
        let address = Address::new(&public_key, Chain::MainNet, Encoding::CompressedBase58);
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

    /// https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    #[test]
    fn test_new_address_from_compressed() {
        let private_key_u256 = U256::from_hex_unchecked(
            "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725",
        );
        let expected_address = Address("1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs".to_string());
        let public_key = PublicKey::from_u256(private_key_u256);
        let address = Address::new(&public_key, Chain::MainNet, Encoding::CompressedBase58);

        assert_eq!(address, expected_address);
    }

    #[test]
    fn test_hrp() {
        let expected_for_testnet = b"tb";
        let expected_for_mainnet = b"bc";
        assert_eq!(&Chain::MainNet.hrp(), expected_for_mainnet);
        assert_eq!(&Chain::TestNet.hrp(), expected_for_testnet);
    }

    #[test]
    fn test_expand_hrp() {
        let expected_for_testnet = [3, 3, 0, 20, 2];
        let result_testnet = Address::expand_human_readable_part(Chain::TestNet.hrp());
        assert_eq!(result_testnet, expected_for_testnet);

        let expected_for_mainnet = [3, 3, 0, 2, 3];
        let result_mainnet = Address::expand_human_readable_part(Chain::MainNet.hrp());
        assert_eq!(result_mainnet, expected_for_mainnet);
    }

    #[test]
    fn test_polymod_2() {
        let poly = [];
        let expected_remainder = 1;

        let remainder = Address::bech32_polymod(&poly);
        assert_eq!(remainder, expected_remainder);
    }

    #[test]
    fn test_polymod_3() {
        let poly = [2];
        let expected_remainder = 34; // (1 << 5) | 2

        let remainder = Address::bech32_polymod(&poly);
        assert_eq!(remainder, expected_remainder);
    }
    #[test]
    fn test_polymod_4() {
        let poly = [5, 1];
        let expected_remainder = 1185; // (((1 << 5) | 5) << 5) | 1

        let remainder = Address::bech32_polymod(&poly);
        assert_eq!(remainder, expected_remainder);
    }
    #[test]
    fn test_polymod_5() {
        let poly = [5, 1, 9];
        let expected_remainder = 37929; // (((((1 << 5) | 5) << 5) | 1) << 5) | 9

        let remainder = Address::bech32_polymod(&poly);
        assert_eq!(remainder, expected_remainder);
    }

    #[test]
    fn test_polymod_6() {
        let poly = [29, 22, 20, 21, 29, 18];
        let expected_remainder = 0;

        let remainder = Address::bech32_polymod(&poly);
        assert_eq!(remainder, expected_remainder);
    }

    #[test]
    fn test_polymod_7() {
        let poly = [29, 22, 20, 21, 28, 16]; // k(x) + x + 2
        let expected_remainder = 34;

        let remainder = Address::bech32_polymod(&poly);
        assert_eq!(remainder, expected_remainder);
    }

    #[test]
    fn test_polymod_8() {
        let poly = [29, 22, 20, 20, 24, 19]; // k(x) + x^2 + 5*x + 1
        let expected_remainder = 1185;

        let remainder = Address::bech32_polymod(&poly);
        assert_eq!(remainder, expected_remainder);
    }

    #[test]
    fn test_polymod_9() {
        let poly = [29, 22, 21, 16, 28, 27]; // k(x) + x^3 + 5*x^2 + x + 9
        let expected_remainder = 37929;

        let remainder = Address::bech32_polymod(&poly);
        assert_eq!(remainder, expected_remainder);
    }

    #[test]
    fn test_polymod_10() {
        let poly = [5, 1, 9, 8, 3, 9, 22];
        let expected_remainder = 948480536;

        let remainder = Address::bech32_polymod(&poly);
        assert_eq!(remainder, expected_remainder);
    }

    #[test]
    fn test_bech32_checksum() {
        let bytes = [
            0, 14, 20, 15, 7, 13, 26, 0, 25, 18, 6, 11, 13, 8, 21, 4, 20, 3, 17, 2, 29, 3, 12, 29,
            3, 4, 15, 24, 20, 6, 14, 30, 22,
        ];
        let chain = Chain::MainNet;
        let expected_checksum = [12, 7, 9, 17, 11, 21];
        let checksum = Address::bech32_checksum(&bytes, chain);
        assert_eq!(checksum, expected_checksum);
    }

    #[test]
    fn test_bech32_encoding() {
        let bytes = [
            117, 30, 118, 232, 25, 145, 150, 212, 84, 148, 28, 69, 209, 179, 163, 35, 241, 67, 59,
            214,
        ];
        let chain = Chain::MainNet;
        let expected_string = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string();
        let string = Address::encode_bech32(&bytes, chain);
        assert_eq!(string, expected_string);
    }
}
