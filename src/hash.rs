use ripemd::{Digest as RipemdDigest, Ripemd160};
use sha2::{Digest as Sha2Digest, Sha256};

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub(crate) fn hash256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

pub(crate) fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub(crate) fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

#[cfg(test)]
pub mod tests {
    use crate::hash::{hash256, sha256};

    use super::ripemd160;

    #[test]
    fn test_sha256() {
        let z = sha256("".as_bytes());

        // z_expected = 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let z_expected = [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ];
        assert_eq!(z, z_expected);
    }

    #[test]
    fn test_hash256() {
        let z = hash256("my message".as_bytes());

        // z_expected = 0x231c6f3d980a6b0fb7152f85cee7eb52bf92433d9919b9c5218cb08e79cce78
        let z_expected = [
            2, 49, 198, 243, 217, 128, 166, 176, 251, 113, 82, 248, 92, 238, 126, 181, 43, 249, 36,
            51, 217, 145, 155, 156, 82, 24, 203, 8, 231, 156, 206, 120,
        ];
        assert_eq!(z, z_expected);
    }

    #[test]
    fn test_ripemd160() {
        let z = ripemd160(&[]);
        let z_expected = [
            156, 17, 133, 165, 197, 233, 252, 84, 97, 40, 8, 151, 126, 232, 245, 72, 178, 37, 141,
            49,
        ];
        assert_eq!(z, z_expected);
    }
}
