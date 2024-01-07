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

impl Script {
    pub fn new(commands: Vec<Command>) -> Self {
        Self { commands }
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
