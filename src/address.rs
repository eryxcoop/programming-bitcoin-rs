use crate::{
    hash::{hash160, ripemd160},
    serializer::Serializer,
    signature::PublicKey,
};

pub(crate) enum Chain {
    TestNet,
    MainNet,
}

impl Chain {
    fn code(self) -> u8 {
        match self {
            Chain::TestNet => 0x6f,
            Chain::MainNet => 0x00,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Address(String);

impl Address {
    fn from_public_key_compressed(key: &PublicKey, chain: Chain) -> Self {
        let hash = {
            let mut hash = vec![chain.code()];
            hash.extend_from_slice(&hash160(&Serializer::serialize_point_compressed_sec(key)));
            hash
        };
        Self(Serializer::base58_encode_with_checksum(&hash))
    }

    fn from_public_key_uncompressed(key: &PublicKey, chain: Chain) -> Self {
        let hash = {
            let mut hash = vec![chain.code()];
            hash.extend_from_slice(&hash160(&Serializer::serialize_point_uncompressed_sec(key)));
            hash
        };
        Self(Serializer::base58_encode_with_checksum(&hash))
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
}
