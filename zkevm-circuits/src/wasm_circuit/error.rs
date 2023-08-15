use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;

type Offset = usize;

#[derive(Debug, Clone)]
pub enum Error {
    IndexOutOfBoundsSimple,
    IndexOutOfBounds(Offset),
    Leb128EncodeSigned,
    Leb128EncodeUnsigned,
    Leb128MaxBytes,
    AssignAtOffset(Offset),
    EnumValueNotFound,
    ParseOpcodeFailed(Offset),
    ComputationFailed,

    FatalAssignExternalChip,
    FatalUnknownAssignTypeUsed,
    FatalUnsupportedValue(String),
    FatalUnsupportedTypeValue(String),
    FatalInvalidArgumentValue(String),

    FatalLeb128Overflow(String),
    FatalLeb128AlignOverflow(String),
    FatalLeb128ThresholdOverflow(String),
    FatalLeb128InvalidArgumentValue(String),

    FatalRecoverableButNotProcessed(String),

    FatalUnknown(String),
}
pub fn is_recoverable_error(e: &Error) -> bool {
    match e {
        Error::IndexOutOfBoundsSimple => {}
        Error::IndexOutOfBounds(_) => {}
        Error::Leb128EncodeSigned => {}
        Error::Leb128EncodeUnsigned => {}
        Error::Leb128MaxBytes => {}
        Error::AssignAtOffset(_) => {}
        Error::EnumValueNotFound => {}
        Error::ParseOpcodeFailed(_) => {}
        Error::ComputationFailed => {}

        _ => {}
    }
    false
}
pub fn is_fatal_error(e: &Error) -> bool {
    match e {
        Error::FatalAssignExternalChip |
        Error::FatalUnknownAssignTypeUsed |
        Error::FatalUnsupportedValue(_) |
        Error::FatalUnsupportedTypeValue(_) |
        Error::FatalInvalidArgumentValue(_) |
        Error::FatalLeb128Overflow(_) |
        Error::FatalLeb128AlignOverflow(_) |
        Error::FatalLeb128ThresholdOverflow(_) |
        Error::FatalLeb128InvalidArgumentValue(_) |
        Error::FatalRecoverableButNotProcessed(_) |
        Error::FatalUnknown(_) => { return true }

        _ => {}
    }
    false
}

pub fn error_index_out_of_bounds(offset: usize) -> Error {
    Error::IndexOutOfBounds(offset)
}

pub fn error_index_out_of_bounds_wb(offset: usize) -> Error {
    Error::IndexOutOfBounds(offset)
}

pub fn validate_wb_offset(wb: &WasmBytecode, offset: usize) -> Result<(), Error> {
    if offset >= wb.bytes.len() { return Err(error_index_out_of_bounds_wb(offset)) }
    Ok(())
}

pub fn remap_error_to_assign_at_offset<E>(offset: usize) -> impl FnOnce(E) -> Error {
    move |_| Error::AssignAtOffset(offset)
}

pub fn remap_error<E>(to: Error) -> impl FnOnce(E) -> Error { |_| to }