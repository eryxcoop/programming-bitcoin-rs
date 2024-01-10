use crate::transaction::{Command, Script};

use super::{read_bytes, CanParse, CanSerialize, ParserError, VarIntSerializer};

pub(crate) struct ScriptSerializer;

impl ScriptSerializer {
    fn serialize_command(command: &Command) -> Vec<u8> {
        match command {
            Command::Operation(value) => vec![*value],
            Command::Element(element_bytes) => {
                let length = element_bytes.len();
                if length <= 75 {
                    let mut result = vec![length as u8];
                    result.extend_from_slice(element_bytes);
                    result
                } else if 75 < length && length < 0x100 {
                    let mut result = vec![76, length as u8];
                    result.extend_from_slice(element_bytes);
                    result
                } else if (0x100..0x10000).contains(&length) {
                    let length_as_bytes = &length.to_le_bytes()[..2];
                    let mut result = vec![77];
                    result.extend_from_slice(length_as_bytes);
                    result.extend_from_slice(element_bytes);
                    result
                } else {
                    // Code unreachable given Script's invariants
                    vec![]
                }
            }
        }
    }
}

impl CanSerialize<Script> for ScriptSerializer {
    type Output = Vec<u8>;

    fn serialize(script: &Script) -> Self::Output {
        let serialized_script: Vec<u8> = script
            .commands()
            .iter()
            .flat_map(Self::serialize_command)
            .collect();
        let mut result = VarIntSerializer::serialize(&(serialized_script.len() as u64));
        result.extend_from_slice(&serialized_script);
        result
    }
}

impl CanParse<Script> for ScriptSerializer {
    fn parse(bytecode: &[u8]) -> Result<(Script, usize), super::ParserError> {
        let (length, length_prefix) = VarIntSerializer::parse(bytecode)?;
        let bytecode = &bytecode[length_prefix..];
        let mut count = 0;
        let mut commands = Vec::new();
        while count < length as usize {
            let command = match bytecode.get(count) {
                Some(&value) if value <= 75 => {
                    count += 1;
                    let element_bytes = bytecode
                        .get(count..(count + value as usize))
                        .ok_or(ParserError::ParseError)?;
                    count += value as usize;
                    Command::Element(element_bytes.to_vec())
                }
                Some(&76) => {
                    count += 1;
                    let element_length =
                        *bytecode.get(count).ok_or(ParserError::ParseError)? as usize;
                    count += 1;
                    let element_bytes = bytecode
                        .get(count..(count + element_length))
                        .ok_or(ParserError::ParseError)?;
                    count += element_length;
                    Command::Element(element_bytes.to_vec())
                }
                Some(&77) => {
                    count += 1;
                    let element_length_bytes = read_bytes::<2>(&bytecode[count..])?;
                    let element_length = u16::from_le_bytes(element_length_bytes) as usize;
                    count += 2;
                    let element_bytes = bytecode
                        .get(count..(count + element_length))
                        .ok_or(ParserError::ParseError)?;
                    count += element_length;
                    Command::Element(element_bytes.to_vec())
                }
                Some(&value) => {
                    count += 1;
                    Command::Operation(value)
                }
                None => return Err(ParserError::ParseError),
            };
            commands.push(command);
        }

        let script = Script::new(commands).map_err(|_| ParserError::ParseError)?;
        Ok((script, length_prefix + count))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        serializer::{script::ScriptSerializer, CanParse, CanSerialize},
        transaction::{Command, Script},
    };

    #[test]
    fn test_serialize_script_1() {
        let script = Script::new(vec![
            Command::Element(vec![
                4, 136, 115, 135, 228, 82, 184, 234, 204, 74, 207, 222, 16, 217, 170, 247, 246,
                217, 160, 249, 117, 170, 187, 16, 208, 6, 228, 218, 86, 135, 68, 208, 108, 97, 222,
                109, 149, 35, 28, 216, 144, 38, 226, 134, 223, 59, 106, 228, 168, 148, 163, 55,
                142, 57, 62, 147, 160, 244, 91, 102, 99, 41, 160, 174, 52,
            ]),
            Command::Operation(0xac),
        ])
        .unwrap();
        let expected_bytes = [
            67, 65, 4, 136, 115, 135, 228, 82, 184, 234, 204, 74, 207, 222, 16, 217, 170, 247, 246,
            217, 160, 249, 117, 170, 187, 16, 208, 6, 228, 218, 86, 135, 68, 208, 108, 97, 222,
            109, 149, 35, 28, 216, 144, 38, 226, 134, 223, 59, 106, 228, 168, 148, 163, 55, 142,
            57, 62, 147, 160, 244, 91, 102, 99, 41, 160, 174, 52, 172,
        ];
        let bytes = ScriptSerializer::serialize(&script);
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_serialize_script_2() {
        let script = Script::new(vec![
            Command::Element(vec![
                48, 69, 2, 33, 0, 237, 129, 255, 25, 46, 117, 163, 253, 35, 4, 0, 77, 202, 219,
                116, 111, 165, 226, 76, 80, 49, 204, 252, 242, 19, 32, 176, 39, 116, 87, 201, 143,
                2, 32, 122, 152, 109, 149, 92, 110, 12, 179, 93, 68, 106, 137, 211, 245, 97, 0,
                244, 215, 246, 120, 1, 195, 25, 103, 116, 58, 156, 142, 16, 97, 91, 237, 1,
            ]),
            Command::Element(vec![
                3, 73, 252, 78, 99, 30, 54, 36, 165, 69, 222, 63, 137, 245, 216, 104, 76, 123, 129,
                56, 189, 148, 189, 213, 49, 210, 226, 19, 191, 1, 107, 39, 138,
            ]),
        ])
        .unwrap();
        let expected_bytes = [
            107, 72, 48, 69, 2, 33, 0, 237, 129, 255, 25, 46, 117, 163, 253, 35, 4, 0, 77, 202,
            219, 116, 111, 165, 226, 76, 80, 49, 204, 252, 242, 19, 32, 176, 39, 116, 87, 201, 143,
            2, 32, 122, 152, 109, 149, 92, 110, 12, 179, 93, 68, 106, 137, 211, 245, 97, 0, 244,
            215, 246, 120, 1, 195, 25, 103, 116, 58, 156, 142, 16, 97, 91, 237, 1, 33, 3, 73, 252,
            78, 99, 30, 54, 36, 165, 69, 222, 63, 137, 245, 216, 104, 76, 123, 129, 56, 189, 148,
            189, 213, 49, 210, 226, 19, 191, 1, 107, 39, 138,
        ];
        let bytes = ScriptSerializer::serialize(&script);
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_serialize_script_3() {
        let script = Script::new(vec![
            Command::Element(vec![
                37, 80, 68, 70, 45, 49, 46, 51, 10, 37, 226, 227, 207, 211, 10, 10, 10, 49, 32, 48,
                32, 111, 98, 106, 10, 60, 60, 47, 87, 105, 100, 116, 104, 32, 50, 32, 48, 32, 82,
                47, 72, 101, 105, 103, 104, 116, 32, 51, 32, 48, 32, 82, 47, 84, 121, 112, 101, 32,
                52, 32, 48, 32, 82, 47, 83, 117, 98, 116, 121, 112, 101, 32, 53, 32, 48, 32, 82,
                47, 70, 105, 108, 116, 101, 114, 32, 54, 32, 48, 32, 82, 47, 67, 111, 108, 111,
                114, 83, 112, 97, 99, 101, 32, 55, 32, 48, 32, 82, 47, 76, 101, 110, 103, 116, 104,
                32, 56, 32, 48, 32, 82, 47, 66, 105, 116, 115, 80, 101, 114, 67, 111, 109, 112,
                111, 110, 101, 110, 116, 32, 56, 62, 62, 10, 115, 116, 114, 101, 97, 109, 10, 255,
                216, 255, 254, 0, 36, 83, 72, 65, 45, 49, 32, 105, 115, 32, 100, 101, 97, 100, 33,
                33, 33, 33, 33, 133, 47, 236, 9, 35, 57, 117, 156, 57, 177, 161, 198, 60, 76, 151,
                225, 255, 254, 1, 127, 70, 220, 147, 166, 182, 126, 1, 59, 2, 154, 170, 29, 178,
                86, 11, 69, 202, 103, 214, 136, 199, 248, 75, 140, 76, 121, 31, 224, 43, 61, 246,
                20, 248, 109, 177, 105, 9, 1, 197, 107, 69, 193, 83, 10, 254, 223, 183, 96, 56,
                233, 114, 114, 47, 231, 173, 114, 143, 14, 73, 4, 224, 70, 194, 48, 87, 15, 233,
                212, 19, 152, 171, 225, 46, 245, 188, 148, 43, 227, 53, 66, 164, 128, 45, 152, 181,
                215, 15, 42, 51, 46, 195, 127, 172, 53, 20, 231, 77, 220, 15, 44, 193, 168, 116,
                205, 12, 120, 48, 90, 33, 86, 100, 97, 48, 151, 137, 96, 107, 208, 191, 63, 152,
                205, 168, 4, 70, 41, 161,
            ]),
            Command::Element(vec![
                37, 80, 68, 70, 45, 49, 46, 51, 10, 37, 226, 227, 207, 211, 10, 10, 10, 49, 32, 48,
                32, 111, 98, 106, 10, 60, 60, 47, 87, 105, 100, 116, 104, 32, 50, 32, 48, 32, 82,
                47, 72, 101, 105, 103, 104, 116, 32, 51, 32, 48, 32, 82, 47, 84, 121, 112, 101, 32,
                52, 32, 48, 32, 82, 47, 83, 117, 98, 116, 121, 112, 101, 32, 53, 32, 48, 32, 82,
                47, 70, 105, 108, 116, 101, 114, 32, 54, 32, 48, 32, 82, 47, 67, 111, 108, 111,
                114, 83, 112, 97, 99, 101, 32, 55, 32, 48, 32, 82, 47, 76, 101, 110, 103, 116, 104,
                32, 56, 32, 48, 32, 82, 47, 66, 105, 116, 115, 80, 101, 114, 67, 111, 109, 112,
                111, 110, 101, 110, 116, 32, 56, 62, 62, 10, 115, 116, 114, 101, 97, 109, 10, 255,
                216, 255, 254, 0, 36, 83, 72, 65, 45, 49, 32, 105, 115, 32, 100, 101, 97, 100, 33,
                33, 33, 33, 33, 133, 47, 236, 9, 35, 57, 117, 156, 57, 177, 161, 198, 60, 76, 151,
                225, 255, 254, 1, 115, 70, 220, 145, 102, 182, 126, 17, 143, 2, 154, 182, 33, 178,
                86, 15, 249, 202, 103, 204, 168, 199, 248, 91, 168, 76, 121, 3, 12, 43, 61, 226,
                24, 248, 109, 179, 169, 9, 1, 213, 223, 69, 193, 79, 38, 254, 223, 179, 220, 56,
                233, 106, 194, 47, 231, 189, 114, 143, 14, 69, 188, 224, 70, 210, 60, 87, 15, 235,
                20, 19, 152, 187, 85, 46, 245, 160, 168, 43, 227, 49, 254, 164, 128, 55, 184, 181,
                215, 31, 14, 51, 46, 223, 147, 172, 53, 0, 235, 77, 220, 13, 236, 193, 168, 100,
                121, 12, 120, 44, 118, 33, 86, 96, 221, 48, 151, 145, 208, 107, 208, 175, 63, 152,
                205, 164, 188, 70, 41, 177,
            ]),
            Command::Operation(0x6e),
            Command::Operation(0x87),
            Command::Operation(0x91),
            Command::Operation(0x69),
            Command::Operation(0xa7),
            Command::Operation(0x7c),
            Command::Operation(0xa7),
            Command::Operation(0x87),
        ])
        .unwrap();
        let expected_bytes = [
            253, 142, 2, 77, 64, 1, 37, 80, 68, 70, 45, 49, 46, 51, 10, 37, 226, 227, 207, 211, 10,
            10, 10, 49, 32, 48, 32, 111, 98, 106, 10, 60, 60, 47, 87, 105, 100, 116, 104, 32, 50,
            32, 48, 32, 82, 47, 72, 101, 105, 103, 104, 116, 32, 51, 32, 48, 32, 82, 47, 84, 121,
            112, 101, 32, 52, 32, 48, 32, 82, 47, 83, 117, 98, 116, 121, 112, 101, 32, 53, 32, 48,
            32, 82, 47, 70, 105, 108, 116, 101, 114, 32, 54, 32, 48, 32, 82, 47, 67, 111, 108, 111,
            114, 83, 112, 97, 99, 101, 32, 55, 32, 48, 32, 82, 47, 76, 101, 110, 103, 116, 104, 32,
            56, 32, 48, 32, 82, 47, 66, 105, 116, 115, 80, 101, 114, 67, 111, 109, 112, 111, 110,
            101, 110, 116, 32, 56, 62, 62, 10, 115, 116, 114, 101, 97, 109, 10, 255, 216, 255, 254,
            0, 36, 83, 72, 65, 45, 49, 32, 105, 115, 32, 100, 101, 97, 100, 33, 33, 33, 33, 33,
            133, 47, 236, 9, 35, 57, 117, 156, 57, 177, 161, 198, 60, 76, 151, 225, 255, 254, 1,
            127, 70, 220, 147, 166, 182, 126, 1, 59, 2, 154, 170, 29, 178, 86, 11, 69, 202, 103,
            214, 136, 199, 248, 75, 140, 76, 121, 31, 224, 43, 61, 246, 20, 248, 109, 177, 105, 9,
            1, 197, 107, 69, 193, 83, 10, 254, 223, 183, 96, 56, 233, 114, 114, 47, 231, 173, 114,
            143, 14, 73, 4, 224, 70, 194, 48, 87, 15, 233, 212, 19, 152, 171, 225, 46, 245, 188,
            148, 43, 227, 53, 66, 164, 128, 45, 152, 181, 215, 15, 42, 51, 46, 195, 127, 172, 53,
            20, 231, 77, 220, 15, 44, 193, 168, 116, 205, 12, 120, 48, 90, 33, 86, 100, 97, 48,
            151, 137, 96, 107, 208, 191, 63, 152, 205, 168, 4, 70, 41, 161, 77, 64, 1, 37, 80, 68,
            70, 45, 49, 46, 51, 10, 37, 226, 227, 207, 211, 10, 10, 10, 49, 32, 48, 32, 111, 98,
            106, 10, 60, 60, 47, 87, 105, 100, 116, 104, 32, 50, 32, 48, 32, 82, 47, 72, 101, 105,
            103, 104, 116, 32, 51, 32, 48, 32, 82, 47, 84, 121, 112, 101, 32, 52, 32, 48, 32, 82,
            47, 83, 117, 98, 116, 121, 112, 101, 32, 53, 32, 48, 32, 82, 47, 70, 105, 108, 116,
            101, 114, 32, 54, 32, 48, 32, 82, 47, 67, 111, 108, 111, 114, 83, 112, 97, 99, 101, 32,
            55, 32, 48, 32, 82, 47, 76, 101, 110, 103, 116, 104, 32, 56, 32, 48, 32, 82, 47, 66,
            105, 116, 115, 80, 101, 114, 67, 111, 109, 112, 111, 110, 101, 110, 116, 32, 56, 62,
            62, 10, 115, 116, 114, 101, 97, 109, 10, 255, 216, 255, 254, 0, 36, 83, 72, 65, 45, 49,
            32, 105, 115, 32, 100, 101, 97, 100, 33, 33, 33, 33, 33, 133, 47, 236, 9, 35, 57, 117,
            156, 57, 177, 161, 198, 60, 76, 151, 225, 255, 254, 1, 115, 70, 220, 145, 102, 182,
            126, 17, 143, 2, 154, 182, 33, 178, 86, 15, 249, 202, 103, 204, 168, 199, 248, 91, 168,
            76, 121, 3, 12, 43, 61, 226, 24, 248, 109, 179, 169, 9, 1, 213, 223, 69, 193, 79, 38,
            254, 223, 179, 220, 56, 233, 106, 194, 47, 231, 189, 114, 143, 14, 69, 188, 224, 70,
            210, 60, 87, 15, 235, 20, 19, 152, 187, 85, 46, 245, 160, 168, 43, 227, 49, 254, 164,
            128, 55, 184, 181, 215, 31, 14, 51, 46, 223, 147, 172, 53, 0, 235, 77, 220, 13, 236,
            193, 168, 100, 121, 12, 120, 44, 118, 33, 86, 96, 221, 48, 151, 145, 208, 107, 208,
            175, 63, 152, 205, 164, 188, 70, 41, 177, 110, 135, 145, 105, 167, 124, 167, 135,
        ];
        let bytes = ScriptSerializer::serialize(&script);
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_parse_script_1() {
        let bytes = [
            67, 65, 4, 136, 115, 135, 228, 82, 184, 234, 204, 74, 207, 222, 16, 217, 170, 247, 246,
            217, 160, 249, 117, 170, 187, 16, 208, 6, 228, 218, 86, 135, 68, 208, 108, 97, 222,
            109, 149, 35, 28, 216, 144, 38, 226, 134, 223, 59, 106, 228, 168, 148, 163, 55, 142,
            57, 62, 147, 160, 244, 91, 102, 99, 41, 160, 174, 52, 172,
        ];
        let expected_script = Script::new(vec![
            Command::Element(vec![
                4, 136, 115, 135, 228, 82, 184, 234, 204, 74, 207, 222, 16, 217, 170, 247, 246,
                217, 160, 249, 117, 170, 187, 16, 208, 6, 228, 218, 86, 135, 68, 208, 108, 97, 222,
                109, 149, 35, 28, 216, 144, 38, 226, 134, 223, 59, 106, 228, 168, 148, 163, 55,
                142, 57, 62, 147, 160, 244, 91, 102, 99, 41, 160, 174, 52,
            ]),
            Command::Operation(0xac),
        ])
        .unwrap();
        let (script, length) = ScriptSerializer::parse(&bytes).unwrap();
        assert_eq!(script, expected_script);
        assert_eq!(length, 68)
    }

    #[test]
    fn test_parse_script_2() {
        let bytes = [
            107, 72, 48, 69, 2, 33, 0, 237, 129, 255, 25, 46, 117, 163, 253, 35, 4, 0, 77, 202,
            219, 116, 111, 165, 226, 76, 80, 49, 204, 252, 242, 19, 32, 176, 39, 116, 87, 201, 143,
            2, 32, 122, 152, 109, 149, 92, 110, 12, 179, 93, 68, 106, 137, 211, 245, 97, 0, 244,
            215, 246, 120, 1, 195, 25, 103, 116, 58, 156, 142, 16, 97, 91, 237, 1, 33, 3, 73, 252,
            78, 99, 30, 54, 36, 165, 69, 222, 63, 137, 245, 216, 104, 76, 123, 129, 56, 189, 148,
            189, 213, 49, 210, 226, 19, 191, 1, 107, 39, 138,
        ];
        let expected_script = Script::new(vec![
            Command::Element(vec![
                48, 69, 2, 33, 0, 237, 129, 255, 25, 46, 117, 163, 253, 35, 4, 0, 77, 202, 219,
                116, 111, 165, 226, 76, 80, 49, 204, 252, 242, 19, 32, 176, 39, 116, 87, 201, 143,
                2, 32, 122, 152, 109, 149, 92, 110, 12, 179, 93, 68, 106, 137, 211, 245, 97, 0,
                244, 215, 246, 120, 1, 195, 25, 103, 116, 58, 156, 142, 16, 97, 91, 237, 1,
            ]),
            Command::Element(vec![
                3, 73, 252, 78, 99, 30, 54, 36, 165, 69, 222, 63, 137, 245, 216, 104, 76, 123, 129,
                56, 189, 148, 189, 213, 49, 210, 226, 19, 191, 1, 107, 39, 138,
            ]),
        ])
        .unwrap();
        let (script, length) = ScriptSerializer::parse(&bytes).unwrap();
        assert_eq!(script, expected_script);
        assert_eq!(length, 108)
    }

    #[test]
    fn test_parse_script_3() {
        let bytes = [
            253, 142, 2, 77, 64, 1, 37, 80, 68, 70, 45, 49, 46, 51, 10, 37, 226, 227, 207, 211, 10,
            10, 10, 49, 32, 48, 32, 111, 98, 106, 10, 60, 60, 47, 87, 105, 100, 116, 104, 32, 50,
            32, 48, 32, 82, 47, 72, 101, 105, 103, 104, 116, 32, 51, 32, 48, 32, 82, 47, 84, 121,
            112, 101, 32, 52, 32, 48, 32, 82, 47, 83, 117, 98, 116, 121, 112, 101, 32, 53, 32, 48,
            32, 82, 47, 70, 105, 108, 116, 101, 114, 32, 54, 32, 48, 32, 82, 47, 67, 111, 108, 111,
            114, 83, 112, 97, 99, 101, 32, 55, 32, 48, 32, 82, 47, 76, 101, 110, 103, 116, 104, 32,
            56, 32, 48, 32, 82, 47, 66, 105, 116, 115, 80, 101, 114, 67, 111, 109, 112, 111, 110,
            101, 110, 116, 32, 56, 62, 62, 10, 115, 116, 114, 101, 97, 109, 10, 255, 216, 255, 254,
            0, 36, 83, 72, 65, 45, 49, 32, 105, 115, 32, 100, 101, 97, 100, 33, 33, 33, 33, 33,
            133, 47, 236, 9, 35, 57, 117, 156, 57, 177, 161, 198, 60, 76, 151, 225, 255, 254, 1,
            127, 70, 220, 147, 166, 182, 126, 1, 59, 2, 154, 170, 29, 178, 86, 11, 69, 202, 103,
            214, 136, 199, 248, 75, 140, 76, 121, 31, 224, 43, 61, 246, 20, 248, 109, 177, 105, 9,
            1, 197, 107, 69, 193, 83, 10, 254, 223, 183, 96, 56, 233, 114, 114, 47, 231, 173, 114,
            143, 14, 73, 4, 224, 70, 194, 48, 87, 15, 233, 212, 19, 152, 171, 225, 46, 245, 188,
            148, 43, 227, 53, 66, 164, 128, 45, 152, 181, 215, 15, 42, 51, 46, 195, 127, 172, 53,
            20, 231, 77, 220, 15, 44, 193, 168, 116, 205, 12, 120, 48, 90, 33, 86, 100, 97, 48,
            151, 137, 96, 107, 208, 191, 63, 152, 205, 168, 4, 70, 41, 161, 77, 64, 1, 37, 80, 68,
            70, 45, 49, 46, 51, 10, 37, 226, 227, 207, 211, 10, 10, 10, 49, 32, 48, 32, 111, 98,
            106, 10, 60, 60, 47, 87, 105, 100, 116, 104, 32, 50, 32, 48, 32, 82, 47, 72, 101, 105,
            103, 104, 116, 32, 51, 32, 48, 32, 82, 47, 84, 121, 112, 101, 32, 52, 32, 48, 32, 82,
            47, 83, 117, 98, 116, 121, 112, 101, 32, 53, 32, 48, 32, 82, 47, 70, 105, 108, 116,
            101, 114, 32, 54, 32, 48, 32, 82, 47, 67, 111, 108, 111, 114, 83, 112, 97, 99, 101, 32,
            55, 32, 48, 32, 82, 47, 76, 101, 110, 103, 116, 104, 32, 56, 32, 48, 32, 82, 47, 66,
            105, 116, 115, 80, 101, 114, 67, 111, 109, 112, 111, 110, 101, 110, 116, 32, 56, 62,
            62, 10, 115, 116, 114, 101, 97, 109, 10, 255, 216, 255, 254, 0, 36, 83, 72, 65, 45, 49,
            32, 105, 115, 32, 100, 101, 97, 100, 33, 33, 33, 33, 33, 133, 47, 236, 9, 35, 57, 117,
            156, 57, 177, 161, 198, 60, 76, 151, 225, 255, 254, 1, 115, 70, 220, 145, 102, 182,
            126, 17, 143, 2, 154, 182, 33, 178, 86, 15, 249, 202, 103, 204, 168, 199, 248, 91, 168,
            76, 121, 3, 12, 43, 61, 226, 24, 248, 109, 179, 169, 9, 1, 213, 223, 69, 193, 79, 38,
            254, 223, 179, 220, 56, 233, 106, 194, 47, 231, 189, 114, 143, 14, 69, 188, 224, 70,
            210, 60, 87, 15, 235, 20, 19, 152, 187, 85, 46, 245, 160, 168, 43, 227, 49, 254, 164,
            128, 55, 184, 181, 215, 31, 14, 51, 46, 223, 147, 172, 53, 0, 235, 77, 220, 13, 236,
            193, 168, 100, 121, 12, 120, 44, 118, 33, 86, 96, 221, 48, 151, 145, 208, 107, 208,
            175, 63, 152, 205, 164, 188, 70, 41, 177, 110, 135, 145, 105, 167, 124, 167, 135,
        ];
        let expected_script = Script::new(vec![
            Command::Element(vec![
                37, 80, 68, 70, 45, 49, 46, 51, 10, 37, 226, 227, 207, 211, 10, 10, 10, 49, 32, 48,
                32, 111, 98, 106, 10, 60, 60, 47, 87, 105, 100, 116, 104, 32, 50, 32, 48, 32, 82,
                47, 72, 101, 105, 103, 104, 116, 32, 51, 32, 48, 32, 82, 47, 84, 121, 112, 101, 32,
                52, 32, 48, 32, 82, 47, 83, 117, 98, 116, 121, 112, 101, 32, 53, 32, 48, 32, 82,
                47, 70, 105, 108, 116, 101, 114, 32, 54, 32, 48, 32, 82, 47, 67, 111, 108, 111,
                114, 83, 112, 97, 99, 101, 32, 55, 32, 48, 32, 82, 47, 76, 101, 110, 103, 116, 104,
                32, 56, 32, 48, 32, 82, 47, 66, 105, 116, 115, 80, 101, 114, 67, 111, 109, 112,
                111, 110, 101, 110, 116, 32, 56, 62, 62, 10, 115, 116, 114, 101, 97, 109, 10, 255,
                216, 255, 254, 0, 36, 83, 72, 65, 45, 49, 32, 105, 115, 32, 100, 101, 97, 100, 33,
                33, 33, 33, 33, 133, 47, 236, 9, 35, 57, 117, 156, 57, 177, 161, 198, 60, 76, 151,
                225, 255, 254, 1, 127, 70, 220, 147, 166, 182, 126, 1, 59, 2, 154, 170, 29, 178,
                86, 11, 69, 202, 103, 214, 136, 199, 248, 75, 140, 76, 121, 31, 224, 43, 61, 246,
                20, 248, 109, 177, 105, 9, 1, 197, 107, 69, 193, 83, 10, 254, 223, 183, 96, 56,
                233, 114, 114, 47, 231, 173, 114, 143, 14, 73, 4, 224, 70, 194, 48, 87, 15, 233,
                212, 19, 152, 171, 225, 46, 245, 188, 148, 43, 227, 53, 66, 164, 128, 45, 152, 181,
                215, 15, 42, 51, 46, 195, 127, 172, 53, 20, 231, 77, 220, 15, 44, 193, 168, 116,
                205, 12, 120, 48, 90, 33, 86, 100, 97, 48, 151, 137, 96, 107, 208, 191, 63, 152,
                205, 168, 4, 70, 41, 161,
            ]),
            Command::Element(vec![
                37, 80, 68, 70, 45, 49, 46, 51, 10, 37, 226, 227, 207, 211, 10, 10, 10, 49, 32, 48,
                32, 111, 98, 106, 10, 60, 60, 47, 87, 105, 100, 116, 104, 32, 50, 32, 48, 32, 82,
                47, 72, 101, 105, 103, 104, 116, 32, 51, 32, 48, 32, 82, 47, 84, 121, 112, 101, 32,
                52, 32, 48, 32, 82, 47, 83, 117, 98, 116, 121, 112, 101, 32, 53, 32, 48, 32, 82,
                47, 70, 105, 108, 116, 101, 114, 32, 54, 32, 48, 32, 82, 47, 67, 111, 108, 111,
                114, 83, 112, 97, 99, 101, 32, 55, 32, 48, 32, 82, 47, 76, 101, 110, 103, 116, 104,
                32, 56, 32, 48, 32, 82, 47, 66, 105, 116, 115, 80, 101, 114, 67, 111, 109, 112,
                111, 110, 101, 110, 116, 32, 56, 62, 62, 10, 115, 116, 114, 101, 97, 109, 10, 255,
                216, 255, 254, 0, 36, 83, 72, 65, 45, 49, 32, 105, 115, 32, 100, 101, 97, 100, 33,
                33, 33, 33, 33, 133, 47, 236, 9, 35, 57, 117, 156, 57, 177, 161, 198, 60, 76, 151,
                225, 255, 254, 1, 115, 70, 220, 145, 102, 182, 126, 17, 143, 2, 154, 182, 33, 178,
                86, 15, 249, 202, 103, 204, 168, 199, 248, 91, 168, 76, 121, 3, 12, 43, 61, 226,
                24, 248, 109, 179, 169, 9, 1, 213, 223, 69, 193, 79, 38, 254, 223, 179, 220, 56,
                233, 106, 194, 47, 231, 189, 114, 143, 14, 69, 188, 224, 70, 210, 60, 87, 15, 235,
                20, 19, 152, 187, 85, 46, 245, 160, 168, 43, 227, 49, 254, 164, 128, 55, 184, 181,
                215, 31, 14, 51, 46, 223, 147, 172, 53, 0, 235, 77, 220, 13, 236, 193, 168, 100,
                121, 12, 120, 44, 118, 33, 86, 96, 221, 48, 151, 145, 208, 107, 208, 175, 63, 152,
                205, 164, 188, 70, 41, 177,
            ]),
            Command::Operation(0x6e),
            Command::Operation(0x87),
            Command::Operation(0x91),
            Command::Operation(0x69),
            Command::Operation(0xa7),
            Command::Operation(0x7c),
            Command::Operation(0xa7),
            Command::Operation(0x87),
        ])
        .unwrap();
        let (script, length) = ScriptSerializer::parse(&bytes).unwrap();
        assert_eq!(script, expected_script);
        assert_eq!(length, 657)
    }
}
