mod public_key;
mod script;
mod signature;
mod transaction;
mod u256;
mod u64;

pub(crate) use self::script::ScriptSerializer;
pub(crate) use self::u256::U256BigEndianSerializer;
pub(crate) use self::u256::U256DERSerializer;
pub(crate) use self::u64::VarIntSerializer;

pub(crate) use self::public_key::PublicKeyCompressedSerializer;
pub(crate) use self::public_key::PublicKeyUncompressedSerializer;

#[derive(Debug, PartialEq, Eq)]
pub enum SerializerError {}

#[derive(Debug, PartialEq, Eq)]
pub enum ParserError {
    ParseError,
}

pub(crate) fn read_bytes<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ParserError> {
    bytes
        .get(..N)
        .and_then(|slice| {
            let array: Result<[u8; N], _> = slice.try_into();
            array.ok()
        })
        .ok_or(ParserError::ParseError)
}

pub(crate) trait CanSerialize<T> {
    type Output: AsRef<[u8]>;
    fn serialize(object: &T) -> Self::Output;
}

pub(crate) trait CanParse<T> {
    fn parse(object: &[u8]) -> Result<(T, usize), ParserError>;
}
