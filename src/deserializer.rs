pub(crate) struct Deserializer;

#[derive(Debug, PartialEq, Eq)]
pub enum DeserializerError {
    ExpectedMoreBytes,
    ParseTransactionVersionError,
    ParseVarintError,
}

impl Deserializer {
    fn read_bytes<const N: usize>(bytes: &[u8]) -> Result<[u8; N], DeserializerError> {
        bytes
            .get(..N)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(DeserializerError::ExpectedMoreBytes)
    }

    pub fn parse_transaction_version(bytes: &[u8]) -> Result<u32, DeserializerError> {
        let version_bytes = Self::read_bytes::<4>(bytes)
            .map_err(|_| DeserializerError::ParseTransactionVersionError)?;

        Ok(u32::from_le_bytes(version_bytes))
    }

    pub fn parse_varint(bytes: &[u8]) -> Result<u64, DeserializerError> {
        match bytes.get(0) {
            Some(&flag) if flag < 253 => Ok(flag as u64),
            Some(&253) => {
                let int_bytes = Self::read_bytes::<2>(&bytes[1..])?;
                Ok(u16::from_le_bytes(int_bytes) as u64)
            }
            Some(&254) => {
                let int_bytes = Self::read_bytes::<4>(&bytes[1..])?;
                Ok(u32::from_le_bytes(int_bytes) as u64)
            }
            Some(&255) => {
                let int_bytes = Self::read_bytes::<8>(&bytes[1..])?;
                Ok(u64::from_le_bytes(int_bytes))
            }
            _ => Err(DeserializerError::ParseVarintError),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deserializer::DeserializerError;

    use super::Deserializer;

    #[test]
    fn test_parse_transaction_version_ok() {
        let bytes = [1, 0, 0, 0, 255];
        let expected_version = 1u32;
        let version = Deserializer::parse_transaction_version(&bytes).unwrap();
        assert_eq!(version, expected_version);
    }

    #[test]
    fn test_parse_transaction_version_err() {
        let bytes = [1, 0, 0];
        let expected_error = DeserializerError::ParseTransactionVersionError;
        let version = Deserializer::parse_transaction_version(&bytes);
        assert_eq!(version.unwrap_err(), expected_error);
    }

    #[test]
    fn test_parse_varint_1() {
        let bytes = [1];
        let expected_uint = 1u64;
        let uint = Deserializer::parse_varint(&bytes).unwrap();
        assert_eq!(uint, expected_uint);
    }

    #[test]
    fn test_parse_varint_2() {
        let bytes = [1, 1];
        let expected_uint = 1u64;
        let uint = Deserializer::parse_varint(&bytes).unwrap();
        assert_eq!(uint, expected_uint);
    }

    #[test]
    fn test_parse_varint_3() {
        let bytes = [1, 253];
        let expected_uint = 1u64;
        let uint = Deserializer::parse_varint(&bytes).unwrap();
        assert_eq!(uint, expected_uint);
    }

    #[test]
    fn test_parse_varint_4() {
        let bytes = [253, 36, 244, 9];
        let expected_uint = 62500u64;
        let uint = Deserializer::parse_varint(&bytes).unwrap();
        assert_eq!(uint, expected_uint);
    }

    #[test]
    fn test_parse_varint_5() {
        let bytes = [254, 40, 107, 238, 0, 101];
        let expected_uint = 15625000u64;
        let uint = Deserializer::parse_varint(&bytes).unwrap();
        assert_eq!(uint, expected_uint);
    }

    #[test]
    fn test_parse_varint_6() {
        let bytes = [255, 159, 58, 195, 181, 207, 27, 194, 211, 11, 17];
        let expected_uint = 15258789066406312607_u64;
        let uint = Deserializer::parse_varint(&bytes).unwrap();
        assert_eq!(uint, expected_uint);
    }
}
