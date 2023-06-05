#[derive(Debug)]
pub enum Error {
    IndexOutOfBounds(String),
    UnsupportedBytesCount(String),
}
