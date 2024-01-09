use super::{read_bytes, CanSerialize, ParserError};

pub(crate) struct VarIntSerializer;

impl CanSerialize<u64> for VarIntSerializer {
    type Output = Vec<u8>;

    fn serialize(uint: &u64) -> Self::Output {
        let bytes: [u8; 8] = u64::to_le_bytes(*uint);
        if *uint < 253 {
            vec![*uint as u8]
        } else if *uint < 0x10000 {
            vec![253, bytes[0], bytes[1]]
        } else if *uint < 0x100000000 {
            vec![254, bytes[0], bytes[1], bytes[2], bytes[3]]
        } else {
            vec![
                255, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]
        }
    }

    fn parse(bytes: &[u8]) -> Result<(u64, usize), super::ParserError> {
        match bytes.first() {
            Some(&flag) if flag < 253 => Ok((flag as u64, 1)),
            Some(&253) => {
                let int_bytes = read_bytes::<2>(&bytes[1..])?;
                Ok((u16::from_le_bytes(int_bytes) as u64, 3))
            }
            Some(&254) => {
                let int_bytes = read_bytes::<4>(&bytes[1..])?;
                Ok((u32::from_le_bytes(int_bytes) as u64, 5))
            }
            Some(&255) => {
                let int_bytes = read_bytes::<8>(&bytes[1..])?;
                Ok((u64::from_le_bytes(int_bytes), 9))
            }
            _ => Err(ParserError::ParseError),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::serializer::{CanSerialize, VarIntSerializer};
    #[test]
    fn test_serialize_varint_1() {
        let uint = 1u64;
        let expected_bytes = [1];
        let bytes = VarIntSerializer::serialize(&uint);
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_serialize_varint_2() {
        let uint = 62500u64;
        let expected_bytes = [253, 36, 244];
        let bytes = VarIntSerializer::serialize(&uint);
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_serialize_varint_3() {
        let uint = 15625000u64;
        let expected_bytes = [254, 40, 107, 238, 0];
        let bytes = VarIntSerializer::serialize(&uint);
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_serialize_varint_4() {
        let uint = 15258789066406312607_u64;
        let expected_bytes = [255, 159, 58, 195, 181, 207, 27, 194, 211];
        let bytes = VarIntSerializer::serialize(&uint);
        assert_eq!(bytes, expected_bytes);
    }
    #[test]
    fn test_parse_varint_1() {
        let bytes = [1];
        let expected_uint = 1u64;
        let expected_prefix_length = 1;
        let (uint, prefix_length) = VarIntSerializer::parse(&bytes).unwrap();
        assert_eq!(uint, expected_uint);
        assert_eq!(prefix_length, expected_prefix_length);
    }

    #[test]
    fn test_parse_varint_2() {
        let bytes = [1, 1];
        let expected_uint = 1u64;
        let expected_prefix_length = 1;
        let (uint, prefix_length) = VarIntSerializer::parse(&bytes).unwrap();
        assert_eq!(uint, expected_uint);
        assert_eq!(prefix_length, expected_prefix_length);
    }

    #[test]
    fn test_parse_varint_3() {
        let bytes = [1, 253];
        let expected_uint = 1u64;
        let expected_prefix_length = 1;
        let (uint, prefix_length) = VarIntSerializer::parse(&bytes).unwrap();
        assert_eq!(uint, expected_uint);
        assert_eq!(prefix_length, expected_prefix_length);
    }

    #[test]
    fn test_parse_varint_4() {
        let bytes = [253, 36, 244, 9];
        let expected_uint = 62500u64;
        let expected_prefix_length = 3;
        let (uint, prefix_length) = VarIntSerializer::parse(&bytes).unwrap();
        assert_eq!(uint, expected_uint);
        assert_eq!(prefix_length, expected_prefix_length);
    }

    #[test]
    fn test_parse_varint_5() {
        let bytes = [254, 40, 107, 238, 0, 101];
        let expected_uint = 15625000u64;
        let expected_prefix_length = 5;
        let (uint, prefix_length) = VarIntSerializer::parse(&bytes).unwrap();
        assert_eq!(uint, expected_uint);
        assert_eq!(prefix_length, expected_prefix_length);
    }

    #[test]
    fn test_parse_varint_6() {
        let bytes = [255, 159, 58, 195, 181, 207, 27, 194, 211, 11, 17];
        let expected_uint = 15258789066406312607_u64;
        let expected_prefix_length = 9;
        let (uint, prefix_length) = VarIntSerializer::parse(&bytes).unwrap();
        assert_eq!(uint, expected_uint);
        assert_eq!(prefix_length, expected_prefix_length);
    }
}
