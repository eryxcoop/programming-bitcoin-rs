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

impl Script {
    pub fn new(commands: Vec<Command>) -> Result<Self, ScriptError> {
        if commands.iter().fold(true, |acc, command| {
            acc && match command {
                Command::Operation(value) => *value > 77,
                Command::Element(value) => value.len() < 0x10000,
            }
        }) {
            Ok(Self { commands })
        } else {
            Err(ScriptError::InvalidCommandsError)
        }
    }

    pub fn empty() -> Self {
        Self { commands: vec![] }
    }

    pub fn commands(&self) -> &[Command] {
        &self.commands
    }
}

pub(crate) struct Transaction {
    version: u32,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    locktime: u32,
}

pub(crate) struct Input {
    source_id: TransactionId,
    source_index: usize,
    script_sig: Script,
    sequence: usize,
}

pub(crate) struct Output {
    amount: u64,
    script_pubkey: Script,
}

#[cfg(test)]
mod test {
    use crate::transaction::ScriptError;

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
}
