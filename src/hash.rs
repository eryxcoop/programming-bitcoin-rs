use sha2::{Digest, Sha256};

pub(crate) fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let e: [u8; 32] = hasher.finalize().into();
    e.into()
}

pub(crate) fn hash256(data: &[u8]) -> Vec<u8> {
    sha256(&sha256(data))
}

#[cfg(test)]
pub mod tests {
    use lambdaworks_math::traits::ByteConversion;

    use crate::{
        hash::{hash256, sha256},
        secp256k1::Secp256k1ScalarFelt,
    };

    #[test]
    fn test_sha256() {
        let z = Secp256k1ScalarFelt::from_bytes_be(&sha256("".as_bytes())).unwrap();
        let z_expected = Secp256k1ScalarFelt::from_hex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap();
        assert_eq!(z, z_expected);
    }

    #[test]
    fn test_hash256() {
        let z = Secp256k1ScalarFelt::from_bytes_be(&hash256("my message".as_bytes())).unwrap();
        let z_expected = Secp256k1ScalarFelt::from_hex_unchecked(
            "231c6f3d980a6b0fb7152f85cee7eb52bf92433d9919b9c5218cb08e79cce78",
        );
        assert_eq!(z, z_expected);
    }
}
