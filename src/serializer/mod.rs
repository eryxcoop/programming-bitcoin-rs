pub mod deserializer;
pub mod serializer;
mod u64;
mod u256;

pub(crate) use self::u64::VarIntSerializer;
pub(crate) use self::u256::U256Serializer;

#[derive(Debug, PartialEq, Eq)]
pub enum SerializerError {}

#[derive(Debug, PartialEq, Eq)]
pub enum ParserError { ParseError }

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
    fn serialize(object: &T) -> Result<Self::Output, SerializerError>;
    fn parse(object: &[u8]) -> Result<(T, usize), ParserError>;
}
