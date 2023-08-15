use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;

#[derive(Debug)]
pub enum Error {
    // recoverable/parsing errors

    IndexOutOfBoundsSimple,
    /// 1st arg is the offset the error occur, 2nd is the length
    IndexOutOfBounds(usize, usize),
    Leb128EncodeSigned,
    Leb128EncodeUnsigned,
    Leb128MaxBytes,
    AssignAtOffset(usize),
    EnumValueNotFound,
    ParseOpcodeFailed(usize),
    ComputationFailed,

    // fatal errors

    AssignExternalChip,
    UnknownAssignTypeUsed,
    UnsupportedValue(String),
    UnsupportedTypeValue(String),
    InvalidArgumentValue(String),

    Leb128Overflow(String),
    Leb128AlignOverflow(String),
    Leb128ThresholdOverflow(String),
    Leb128InvalidArgumentValue(String),
}

pub fn error_index_out_of_bounds(start_offset: usize, len: usize) -> Error {
    Error::IndexOutOfBounds(start_offset, len)
}

pub fn error_index_out_of_bounds_wb(wb: &WasmBytecode, offset: usize) -> Error {
    Error::IndexOutOfBounds(offset, wb.bytes.len())
}

pub fn validate_wb_offset(wb: &WasmBytecode, offset: usize) -> Result<(), Error> {
    if offset >= wb.bytes.len() { return Err(error_index_out_of_bounds_wb(wb, offset)) }
    Ok(())
}

pub fn validate_offset(wb: &WasmBytecode, offset: usize) -> Result<(), Error> {
    if offset >= wb.bytes.len() { return Err(error_index_out_of_bounds_wb(wb, offset)) }
    Ok(())
}

pub fn remap_error_to_assign_at_offset<E>(offset: usize) -> impl FnOnce(E) -> Error {
    move |_| Error::AssignAtOffset(offset)
}

pub fn remap_error<E>(to: Error) -> impl FnOnce(E) -> Error { |_| to }