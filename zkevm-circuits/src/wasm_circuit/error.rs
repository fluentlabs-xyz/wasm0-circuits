use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;

type Offset = usize;

#[derive(Debug, Clone)]
pub enum Error {
    IndexOutOfBoundsAt(Offset),
    AssignAt(Offset),
    InvalidByteValueAt(Offset),
    ParseOpcodeFailedAt(Offset),
    InvalidEnumValueAt(Offset),
    ComputeValueAt(Offset),

    InvalidEnumValue,
    IndexOutOfBoundsSimple,
    Leb128Encode,
    Leb128EncodeSigned,
    Leb128EncodeUnsigned,
    Leb128MaxBytes,
    ComputationFailed,

    FatalAssignExternalChip,
    FatalUnknownAssignTypeUsed(String),
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
    return match e {
        Error::IndexOutOfBoundsAt(_) |
        Error::AssignAt(_) |
        Error::ParseOpcodeFailedAt(_) |
        Error::InvalidByteValueAt(_) |
        Error::InvalidEnumValueAt(_) |
        Error::ComputeValueAt(_) |
        Error::IndexOutOfBoundsSimple |
        Error::Leb128EncodeSigned |
        Error::Leb128EncodeUnsigned |
        Error::Leb128MaxBytes |
        Error::InvalidEnumValue |
        Error::ComputationFailed => { true }

        _ => false
    }
}
pub fn is_fatal_error(e: &Error) -> bool {
    return match e {
        Error::FatalAssignExternalChip |
        Error::FatalUnknownAssignTypeUsed(_) |
        Error::FatalUnsupportedValue(_) |
        Error::FatalUnsupportedTypeValue(_) |
        Error::FatalInvalidArgumentValue(_) |
        Error::FatalLeb128Overflow(_) |
        Error::FatalLeb128AlignOverflow(_) |
        Error::FatalLeb128ThresholdOverflow(_) |
        Error::FatalLeb128InvalidArgumentValue(_) |
        Error::FatalRecoverableButNotProcessed(_) |
        Error::FatalUnknown(_) => { true }

        _ => false
    }
}

pub fn error_index_out_of_bounds(offset: usize) -> Error {
    Error::IndexOutOfBoundsAt(offset)
}

pub fn error_index_out_of_bounds_wb(offset: usize) -> Error {
    Error::IndexOutOfBoundsAt(offset)
}

pub fn validate_wb_offset(wb: &WasmBytecode, offset: usize) -> Result<(), Error> {
    if offset >= wb.bytes.len() { return Err(error_index_out_of_bounds_wb(offset)) }
    Ok(())
}

pub fn remap_error_to_index_out_of_bounds_at<E>(offset: usize) -> impl FnOnce(E) -> Error {
    move |_| Error::IndexOutOfBoundsAt(offset)
}
pub fn remap_error_to_assign_at<E>(offset: usize) -> impl FnOnce(E) -> Error {
    move |_| Error::AssignAt(offset)
}
pub fn remap_error_to_invalid_byte_value_at<E>(offset: usize) -> impl FnOnce(E) -> Error {
    move |_| Error::InvalidByteValueAt(offset)
}
pub fn remap_error_to_parse_opcode_failed_at<E>(offset: usize) -> impl FnOnce(E) -> Error {
    move |_| Error::ParseOpcodeFailedAt(offset)
}
pub fn remap_error_to_invalid_enum_value_at<E>(offset: usize) -> impl FnOnce(E) -> Error {
    move |_| Error::InvalidEnumValueAt(offset)
}
pub fn remap_error_to_compute_value_at<E>(offset: usize) -> impl FnOnce(E) -> Error {
    move |_| Error::ComputeValueAt(offset)
}

pub fn remap_error<E>(to: Error) -> impl FnOnce(E) -> Error { |_| to }