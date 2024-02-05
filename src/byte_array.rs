use lambdaworks_math::unsigned_integer::element::U256;

pub struct ByteArrayOfLength32 {
    pub(crate) bytes: [u8; 32],
}

impl ByteArrayOfLength32 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }
}

impl From<&ByteArrayOfLength32> for U256 {
    fn from(private_key: &ByteArrayOfLength32) -> Self {
        let bytes = private_key.bytes;
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let start = i * 8;
            *limb = u64::from_be_bytes([
                bytes[start],
                bytes[start + 1],
                bytes[start + 2],
                bytes[start + 3],
                bytes[start + 4],
                bytes[start + 5],
                bytes[start + 6],
                bytes[start + 7],
            ])
        }
        U256::from_limbs(limbs)
    }
}

impl From<ByteArrayOfLength32> for U256 {
    fn from(private_key: ByteArrayOfLength32) -> Self {
        (&private_key).into()
    }
}
