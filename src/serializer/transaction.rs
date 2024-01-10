use std::string::ParseError;

use crate::{
    serializer::VarIntSerializer,
    transaction::{Input, Output, Transaction},
};

use super::{read_bytes, CanParse, CanSerialize, ParserError, ScriptSerializer};

pub(crate) struct TransactionSerializer;

impl TransactionSerializer {
    fn parse_input(bytes: &[u8]) -> Result<(Input, usize), ParserError> {
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

    fn parse_output(bytes: &[u8]) -> Result<(Output, usize), ParserError> {
        let amount_bytes = read_bytes::<8>(&bytes).map_err(|_| ParserError::ParseError)?;
        let amount = u64::from_le_bytes(amount_bytes);
        let (script_pubkey, script_length) = ScriptSerializer::parse(&bytes[8..])?;
        Ok((Output::new(amount, script_pubkey), 8 + script_length))
    }
}

impl CanParse<Transaction> for TransactionSerializer {
    fn parse(bytes: &[u8]) -> Result<(Transaction, usize), ParserError> {
        let mut offset = 0;
        let version_bytes = read_bytes::<4>(bytes).map_err(|_| ParserError::ParseError)?;
        let version = u32::from_le_bytes(version_bytes);
        offset += 4;

        let (number_inputs, num_inputs_length) = VarIntSerializer::parse(&bytes[offset..])?;
        offset += num_inputs_length;
        let mut inputs = Vec::new();
        for _ in 0..number_inputs {
            let (input, input_length) = Self::parse_input(&bytes[offset..])?;
            inputs.push(input);
            offset += input_length;
        }

        let (number_outputs, num_outputs_length) = VarIntSerializer::parse(&bytes[offset..])?;
        offset += num_inputs_length;
        let mut outputs = Vec::new();
        for _ in 0..number_outputs {
            let (output, output_length) = Self::parse_output(&bytes[offset..])?;
            outputs.push(output);
            offset += output_length;
        }

        let locktime_bytes =
            read_bytes::<4>(&bytes[offset..]).map_err(|_| ParserError::ParseError)?;
        let locktime = u32::from_le_bytes(locktime_bytes);
        offset += 4;

        let transaction = Transaction::new(version, inputs, outputs, locktime);
        Ok((transaction, offset))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        serializer::CanParse,
        transaction::{Command, Input, Output, Script, Transaction},
    };

    use super::TransactionSerializer;

    #[test]
    fn test_parse_transaction_1() {
        let bytes = [
            1, 0, 0, 0, 4, 86, 145, 153, 96, 172, 105, 23, 99, 104, 141, 61, 59, 206, 169, 173,
            110, 202, 248, 117, 223, 83, 57, 225, 72, 161, 252, 97, 198, 237, 122, 6, 158, 1, 0, 0,
            0, 106, 71, 48, 68, 2, 32, 69, 133, 188, 222, 248, 94, 107, 28, 106, 245, 194, 102,
            157, 72, 48, 255, 134, 228, 45, 210, 5, 192, 224, 137, 188, 42, 130, 22, 87, 233, 81,
            192, 2, 32, 16, 36, 161, 3, 102, 7, 127, 135, 214, 188, 225, 247, 16, 10, 216, 207,
            168, 160, 100, 179, 157, 78, 143, 228, 234, 19, 167, 183, 26, 168, 24, 15, 1, 33, 2,
            240, 218, 87, 232, 94, 236, 41, 52, 168, 42, 88, 94, 163, 55, 206, 47, 73, 152, 181,
            10, 230, 153, 221, 121, 245, 136, 14, 37, 61, 175, 175, 183, 254, 255, 255, 255, 235,
            143, 81, 244, 3, 141, 193, 126, 99, 19, 207, 131, 29, 79, 2, 40, 28, 42, 70, 139, 222,
            15, 175, 211, 127, 27, 248, 130, 114, 158, 127, 211, 0, 0, 0, 0, 106, 71, 48, 68, 2,
            32, 120, 153, 83, 26, 82, 213, 154, 109, 226, 0, 23, 153, 40, 202, 144, 2, 84, 163,
            107, 141, 255, 139, 183, 95, 95, 93, 113, 177, 205, 194, 97, 37, 2, 32, 8, 180, 34,
            105, 11, 132, 97, 203, 82, 195, 204, 48, 51, 11, 35, 213, 116, 53, 24, 114, 183, 195,
            97, 233, 170, 227, 100, 144, 113, 193, 167, 22, 1, 33, 3, 93, 92, 147, 217, 172, 150,
            136, 31, 25, 186, 31, 104, 111, 21, 240, 9, 222, 215, 198, 46, 254, 133, 168, 114, 230,
            161, 155, 67, 193, 90, 41, 55, 254, 255, 255, 255, 86, 123, 244, 5, 149, 17, 157, 27,
            184, 163, 3, 124, 53, 110, 253, 86, 23, 11, 100, 203, 204, 22, 15, 176, 40, 250, 16,
            112, 75, 69, 215, 117, 0, 0, 0, 0, 106, 71, 48, 68, 2, 32, 76, 124, 120, 24, 66, 76,
            127, 121, 17, 218, 108, 221, 197, 150, 85, 167, 10, 241, 203, 94, 175, 23, 198, 157,
            173, 191, 199, 79, 250, 11, 102, 47, 2, 32, 117, 153, 224, 139, 200, 2, 54, 147, 173,
            78, 149, 39, 220, 66, 195, 66, 16, 247, 167, 209, 209, 221, 252, 132, 146, 182, 84,
            161, 30, 118, 32, 160, 1, 33, 2, 21, 139, 70, 251, 223, 246, 93, 1, 114, 183, 152, 154,
            236, 136, 80, 170, 13, 174, 73, 171, 251, 132, 200, 26, 230, 229, 178, 81, 165, 138,
            206, 92, 254, 255, 255, 255, 214, 58, 94, 108, 22, 230, 32, 248, 111, 55, 89, 37, 178,
            28, 171, 175, 115, 108, 119, 159, 136, 253, 4, 220, 173, 81, 210, 102, 144, 247, 243,
            69, 1, 0, 0, 0, 106, 71, 48, 68, 2, 32, 6, 51, 234, 13, 51, 20, 190, 160, 217, 91, 60,
            216, 218, 219, 46, 247, 158, 168, 51, 31, 254, 30, 97, 247, 98, 192, 246, 218, 234, 15,
            171, 222, 2, 32, 41, 242, 59, 62, 156, 48, 240, 128, 68, 97, 80, 178, 56, 82, 2, 135,
            81, 99, 93, 206, 226, 190, 102, 156, 42, 22, 134, 164, 181, 237, 243, 4, 1, 33, 3, 255,
            214, 244, 166, 126, 148, 171, 163, 83, 160, 8, 130, 229, 99, 255, 39, 34, 235, 76, 255,
            10, 214, 0, 110, 134, 238, 32, 223, 231, 82, 13, 85, 254, 255, 255, 255, 2, 81, 67, 15,
            0, 0, 0, 0, 0, 25, 118, 169, 20, 171, 12, 11, 46, 152, 177, 171, 109, 191, 103, 212,
            117, 11, 10, 86, 36, 73, 72, 168, 121, 136, 172, 0, 90, 98, 2, 0, 0, 0, 0, 25, 118,
            169, 20, 60, 130, 215, 223, 54, 78, 182, 199, 91, 232, 200, 13, 242, 179, 237, 168,
            219, 87, 57, 112, 136, 172, 70, 67, 6, 0,
        ];
        let input1 = Input::new(
            [
                158, 6, 122, 237, 198, 97, 252, 161, 72, 225, 57, 83, 223, 117, 248, 202, 110, 173,
                169, 206, 59, 61, 141, 104, 99, 23, 105, 172, 96, 153, 145, 86,
            ],
            1,
            Script::new(vec![
                Command::Element(vec![
                    48, 68, 2, 32, 69, 133, 188, 222, 248, 94, 107, 28, 106, 245, 194, 102, 157,
                    72, 48, 255, 134, 228, 45, 210, 5, 192, 224, 137, 188, 42, 130, 22, 87, 233,
                    81, 192, 2, 32, 16, 36, 161, 3, 102, 7, 127, 135, 214, 188, 225, 247, 16, 10,
                    216, 207, 168, 160, 100, 179, 157, 78, 143, 228, 234, 19, 167, 183, 26, 168,
                    24, 15, 1,
                ]),
                Command::Element(vec![
                    2, 240, 218, 87, 232, 94, 236, 41, 52, 168, 42, 88, 94, 163, 55, 206, 47, 73,
                    152, 181, 10, 230, 153, 221, 121, 245, 136, 14, 37, 61, 175, 175, 183,
                ]),
            ])
            .unwrap(),
            4294967294,
        );
        let input2 = Input::new(
            [
                211, 127, 158, 114, 130, 248, 27, 127, 211, 175, 15, 222, 139, 70, 42, 28, 40, 2,
                79, 29, 131, 207, 19, 99, 126, 193, 141, 3, 244, 81, 143, 235,
            ],
            0,
            Script::new(vec![
                Command::Element(vec![
                    48, 68, 2, 32, 120, 153, 83, 26, 82, 213, 154, 109, 226, 0, 23, 153, 40, 202,
                    144, 2, 84, 163, 107, 141, 255, 139, 183, 95, 95, 93, 113, 177, 205, 194, 97,
                    37, 2, 32, 8, 180, 34, 105, 11, 132, 97, 203, 82, 195, 204, 48, 51, 11, 35,
                    213, 116, 53, 24, 114, 183, 195, 97, 233, 170, 227, 100, 144, 113, 193, 167,
                    22, 1,
                ]),
                Command::Element(vec![
                    3, 93, 92, 147, 217, 172, 150, 136, 31, 25, 186, 31, 104, 111, 21, 240, 9, 222,
                    215, 198, 46, 254, 133, 168, 114, 230, 161, 155, 67, 193, 90, 41, 55,
                ]),
            ])
            .unwrap(),
            4294967294,
        );
        let input3 = Input::new(
            [
                117, 215, 69, 75, 112, 16, 250, 40, 176, 15, 22, 204, 203, 100, 11, 23, 86, 253,
                110, 53, 124, 3, 163, 184, 27, 157, 17, 149, 5, 244, 123, 86,
            ],
            0,
            Script::new(vec![
                Command::Element(vec![
                    48, 68, 2, 32, 76, 124, 120, 24, 66, 76, 127, 121, 17, 218, 108, 221, 197, 150,
                    85, 167, 10, 241, 203, 94, 175, 23, 198, 157, 173, 191, 199, 79, 250, 11, 102,
                    47, 2, 32, 117, 153, 224, 139, 200, 2, 54, 147, 173, 78, 149, 39, 220, 66, 195,
                    66, 16, 247, 167, 209, 209, 221, 252, 132, 146, 182, 84, 161, 30, 118, 32, 160,
                    1,
                ]),
                Command::Element(vec![
                    2, 21, 139, 70, 251, 223, 246, 93, 1, 114, 183, 152, 154, 236, 136, 80, 170,
                    13, 174, 73, 171, 251, 132, 200, 26, 230, 229, 178, 81, 165, 138, 206, 92,
                ]),
            ])
            .unwrap(),
            4294967294,
        );
        let input4 = Input::new(
            [
                69, 243, 247, 144, 102, 210, 81, 173, 220, 4, 253, 136, 159, 119, 108, 115, 175,
                171, 28, 178, 37, 89, 55, 111, 248, 32, 230, 22, 108, 94, 58, 214,
            ],
            1,
            Script::new(vec![
                Command::Element(vec![
                    48, 68, 2, 32, 6, 51, 234, 13, 51, 20, 190, 160, 217, 91, 60, 216, 218, 219,
                    46, 247, 158, 168, 51, 31, 254, 30, 97, 247, 98, 192, 246, 218, 234, 15, 171,
                    222, 2, 32, 41, 242, 59, 62, 156, 48, 240, 128, 68, 97, 80, 178, 56, 82, 2,
                    135, 81, 99, 93, 206, 226, 190, 102, 156, 42, 22, 134, 164, 181, 237, 243, 4,
                    1,
                ]),
                Command::Element(vec![
                    3, 255, 214, 244, 166, 126, 148, 171, 163, 83, 160, 8, 130, 229, 99, 255, 39,
                    34, 235, 76, 255, 10, 214, 0, 110, 134, 238, 32, 223, 231, 82, 13, 85,
                ]),
            ])
            .unwrap(),
            4294967294,
        );
        let output1 = Output::new(
            1000273,
            Script::new(vec![
                Command::Operation(118),
                Command::Operation(169),
                Command::Element(vec![
                    171, 12, 11, 46, 152, 177, 171, 109, 191, 103, 212, 117, 11, 10, 86, 36, 73,
                    72, 168, 121,
                ]),
                Command::Operation(136),
                Command::Operation(172),
            ])
            .unwrap(),
        );
        let output2 = Output::new(
            40000000,
            Script::new(vec![
                Command::Operation(118),
                Command::Operation(169),
                Command::Element(vec![
                    60, 130, 215, 223, 54, 78, 182, 199, 91, 232, 200, 13, 242, 179, 237, 168, 219,
                    87, 57, 112,
                ]),
                Command::Operation(136),
                Command::Operation(172),
            ])
            .unwrap(),
        );

        let expected_transaction = Transaction::new(
            1,
            vec![input1, input2, input3, input4],
            vec![output1, output2],
            410438,
        );
        let (transaction, _) = TransactionSerializer::parse(&bytes).unwrap();
        assert_eq!(transaction, expected_transaction);
    }
}
