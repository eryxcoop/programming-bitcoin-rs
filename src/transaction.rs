use crate::{
    serializer::{CanSerialize, PublicKeyCompressedSerializer, PublicKeyUncompressedSerializer},
    PublicKey,
};

pub(crate) type TransactionId = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Command {
    Operation(u8),
    Element(Vec<u8>),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Script {
    commands: Vec<Command>,
}

#[derive(Debug)]
pub enum ScriptError {
    InvalidCommandsError,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Transaction {
    pub(crate) version: u32,
    pub(crate) inputs: Vec<Input>,
    pub(crate) outputs: Vec<Output>,
    pub(crate) locktime: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Input {
    pub(crate) source_id: TransactionId,
    pub(crate) source_index: u32,
    pub(crate) script_sig: Script,
    pub(crate) sequence: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Output {
    pub(crate) amount: u64,
    pub(crate) script_pubkey: Script,
}

impl Script {
    pub fn new(commands: Vec<Command>) -> Result<Self, ScriptError> {
        if commands.iter().all(|command| match command {
            Command::Operation(value) => *value > 77,
            Command::Element(value) => value.len() < 0x10000,
        }) {
            Ok(Self { commands })
        } else {
            Err(ScriptError::InvalidCommandsError)
        }
    }

    pub fn p2pk(public_key: &PublicKey, compressed: bool) -> Self {
        let mut commands = Vec::new();
        let serialized_public_key = if compressed {
            PublicKeyCompressedSerializer::serialize(public_key).to_vec()
        } else {
            PublicKeyUncompressedSerializer::serialize(public_key).to_vec()
        };
        commands.push(Command::Element(serialized_public_key));
        commands.push(Command::Operation(0xac));
        Self { commands }
    }

    pub fn empty() -> Self {
        Self { commands: vec![] }
    }

    pub fn commands(&self) -> &[Command] {
        &self.commands
    }
}

impl Input {
    pub fn new(source_id: [u8; 32], source_index: u32, script_sig: Script, sequence: u32) -> Self {
        Self {
            source_id,
            source_index,
            script_sig,
            sequence,
        }
    }
}

impl Output {
    pub fn new(amount: u64, script_pubkey: Script) -> Self {
        Self {
            amount,
            script_pubkey,
        }
    }
}

impl Transaction {
    pub fn new(version: u32, inputs: Vec<Input>, outputs: Vec<Output>, locktime: u32) -> Self {
        Self {
            version,
            inputs,
            outputs,
            locktime,
        }
    }
}

#[cfg(test)]
mod test {
    use lambdaworks_math::elliptic_curve::traits::IsEllipticCurve;

    use crate::{
        secp256k1::{curve::Secp256k1, fields::BaseFelt},
        PublicKey,
    };

    use super::{Command, Script};

    #[test]
    fn test_script_constructor_1() {
        let empty_script = Script::empty();
        assert_eq!(empty_script.commands, vec![])
    }

    #[test]
    fn test_script_constructor_2() {
        let commands = vec![Command::Operation(1)];
        let _ = Script::new(commands).unwrap_err();
    }

    #[test]
    fn test_script_constructor_3() {
        let commands = vec![Command::Operation(77), Command::Operation(78)];
        let _ = Script::new(commands).unwrap_err();
    }

    #[test]
    fn test_script_constructor_4() {
        let commands = vec![Command::Operation(78)];
        let _ = Script::new(commands).unwrap();
    }

    #[test]
    fn test_script_constructor_5() {
        let commands = vec![
            Command::Operation(80),
            Command::Element(vec![0u8]),
            Command::Operation(107),
        ];
        let _ = Script::new(commands).unwrap();
    }

    #[test]
    fn test_script_constructor_6() {
        let commands = vec![
            Command::Operation(80),
            Command::Element(vec![0u8; 0x0ffff]),
            Command::Operation(107),
        ];
        let _ = Script::new(commands).unwrap();
    }

    #[test]
    fn test_script_constructor_7() {
        let commands = vec![
            Command::Operation(80),
            Command::Element(vec![0u8; 0x10000]),
            Command::Operation(107),
        ];
        let _ = Script::new(commands).unwrap_err();
    }

    #[test]
    fn test_p2pk() {
        let x = BaseFelt::from_hex_unchecked(
            "a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd",
        );
        let y = BaseFelt::from_hex_unchecked(
            "5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235",
        );
        let point = Secp256k1::create_point_from_affine(x, y).unwrap();
        let public_key = PublicKey::new(point);
        let expected_script = Script::new(vec![
            Command::Element(vec![
                3, 163, 75, 153, 242, 44, 121, 12, 78, 54, 178, 179, 194, 195, 90, 54, 219, 6, 34,
                110, 65, 198, 146, 252, 130, 184, 181, 106, 193, 197, 64, 197, 189,
            ]),
            Command::Operation(0xac),
        ])
        .unwrap();

        let script = Script::p2pk(&public_key, true);
        assert_eq!(script, expected_script);
    }
}
