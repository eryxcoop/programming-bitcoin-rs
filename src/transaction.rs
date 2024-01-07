pub(crate) type TransactionId = [u8; 32];

pub(crate) type Script = Vec<u8>;

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
