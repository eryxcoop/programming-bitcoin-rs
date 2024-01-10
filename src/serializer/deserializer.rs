use crate::transaction::{Input};

use super::{read_bytes, script::ScriptSerializer, CanParse, ParserError};

pub(crate) struct Deserializer;

impl Deserializer {
    pub fn parse_transaction_version(bytes: &[u8]) -> Result<u32, ParserError> {
        let version_bytes = read_bytes::<4>(bytes).map_err(|_| ParserError::ParseError)?;

        Ok(u32::from_le_bytes(version_bytes))
    }

    pub fn parse_input(bytes: &[u8]) -> Result<(Input, usize), ParserError> {
        let mut source_id = read_bytes::<32>(bytes).map_err(|_| ParserError::ParseError)?;
        source_id.reverse();

        let source_index_bytes =
            read_bytes::<4>(&bytes[32..]).map_err(|_| ParserError::ParseError)?;
        let source_index = u32::from_le_bytes(source_index_bytes);
        let (script_sig, script_length) = ScriptSerializer::parse(&bytes[36..])?;
        let sequence_bytes = read_bytes::<4>(&bytes[(36 + script_length)..])?;
        let sequence = u32::from_le_bytes(sequence_bytes);
        let input = Input::new(source_id, source_index, script_sig, sequence);
        Ok((input, 32 + 4 + script_length + 4))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        serializer::deserializer::ParserError,
        transaction::{Command, Input, Script},
    };

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
        let expected_error = ParserError::ParseError;
        let version = Deserializer::parse_transaction_version(&bytes);
        assert_eq!(version.unwrap_err(), expected_error);
    }

    #[test]
    fn test_parse_input_1() {
        let bytes = [
            47, 42, 254, 87, 189, 224, 130, 44, 121, 54, 4, 186, 174, 131, 79, 44, 210, 97, 85,
            191, 28, 13, 55, 72, 2, 18, 193, 7, 231, 92, 208, 17, 1, 0, 0, 0, 0, 255, 255, 255,
            255,
        ];
        let expected_input = Input::new(
            [
                17, 208, 92, 231, 7, 193, 18, 2, 72, 55, 13, 28, 191, 85, 97, 210, 44, 79, 131,
                174, 186, 4, 54, 121, 44, 130, 224, 189, 87, 254, 42, 47,
            ],
            1,
            Script::empty(),
            0xffffffff,
        );
        let (input, length) = Deserializer::parse_input(&bytes).unwrap();
        assert_eq!(input, expected_input);
        assert_eq!(length, bytes.len());
    }

    #[test]
    fn test_parse_input_2() {
        let bytes = [
            21, 61, 176, 32, 45, 226, 126, 121, 68, 199, 253, 101, 30, 193, 208, 250, 177, 241,
            170, 237, 75, 13, 166, 13, 154, 27, 6, 189, 119, 31, 246, 81, 1, 0, 0, 0, 0, 255, 255,
            255, 255,
        ];
        let expected_input = Input::new(
            [
                81, 246, 31, 119, 189, 6, 27, 154, 13, 166, 13, 75, 237, 170, 241, 177, 250, 208,
                193, 30, 101, 253, 199, 68, 121, 126, 226, 45, 32, 176, 61, 21,
            ],
            1,
            Script::empty(),
            0xffffffff,
        );
        let (input, length) = Deserializer::parse_input(&bytes).unwrap();
        assert_eq!(input, expected_input);
        assert_eq!(length, bytes.len());
    }

    #[test]
    fn test_parse_input_3() {
        let bytes = [
            134, 130, 120, 237, 109, 223, 182, 193, 237, 58, 213, 248, 24, 30, 176, 199, 163, 133,
            170, 8, 54, 240, 29, 94, 71, 137, 230, 189, 48, 77, 135, 34, 26, 0, 0, 0, 71, 82, 33,
            2, 38, 38, 233, 85, 234, 110, 166, 217, 136, 80, 201, 148, 249, 16, 123, 3, 107, 19,
            52, 241, 140, 168, 131, 11, 255, 241, 41, 93, 33, 207, 219, 112, 33, 3, 178, 135, 234,
            241, 34, 238, 166, 144, 48, 160, 233, 254, 237, 9, 107, 237, 128, 69, 200, 185, 139,
            236, 69, 62, 31, 250, 199, 251, 219, 212, 187, 113, 82, 174, 255, 255, 255, 255,
        ];

        let expected_input = Input::new(
            [
                34, 135, 77, 48, 189, 230, 137, 71, 94, 29, 240, 54, 8, 170, 133, 163, 199, 176,
                30, 24, 248, 213, 58, 237, 193, 182, 223, 109, 237, 120, 130, 134,
            ],
            26,
            Script::new(vec![
                Command::Operation(82),
                Command::Element(vec![
                    2, 38, 38, 233, 85, 234, 110, 166, 217, 136, 80, 201, 148, 249, 16, 123, 3,
                    107, 19, 52, 241, 140, 168, 131, 11, 255, 241, 41, 93, 33, 207, 219, 112,
                ]),
                Command::Element(vec![
                    3, 178, 135, 234, 241, 34, 238, 166, 144, 48, 160, 233, 254, 237, 9, 107, 237,
                    128, 69, 200, 185, 139, 236, 69, 62, 31, 250, 199, 251, 219, 212, 187, 113,
                ]),
                Command::Operation(82),
                Command::Operation(174),
            ])
            .unwrap(),
            0xffffffff,
        );

        let (input, length) = Deserializer::parse_input(&bytes).unwrap();
        assert_eq!(input, expected_input);
        assert_eq!(length, 112);
    }
}

//
