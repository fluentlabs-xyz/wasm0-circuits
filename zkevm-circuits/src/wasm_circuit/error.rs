use crate::wasm_circuit::{bytecode::bytecode::WasmBytecode, types::AssignOffsetType};
use strum_macros::EnumIter;

#[derive(Debug, Clone, EnumIter, PartialEq)]
pub enum Error {
    IndexOutOfBoundsAt(AssignOffsetType),
    AssignAt(AssignOffsetType),
    InvalidByteValueAt(AssignOffsetType),
    ParseOpcodeFailedAt(AssignOffsetType),
    InvalidEnumValueAt(AssignOffsetType),
    ComputeValueAt(AssignOffsetType),

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
        Error::IndexOutOfBoundsAt(_)
        | Error::AssignAt(_)
        | Error::ParseOpcodeFailedAt(_)
        | Error::InvalidByteValueAt(_)
        | Error::InvalidEnumValueAt(_)
        | Error::ComputeValueAt(_)
        | Error::IndexOutOfBoundsSimple
        | Error::Leb128Encode
        | Error::Leb128EncodeSigned
        | Error::Leb128EncodeUnsigned
        | Error::Leb128MaxBytes
        | Error::InvalidEnumValue
        | Error::ComputationFailed => true,

        _ => false,
    };
}
pub fn is_fatal_error(e: &Error) -> bool {
    return match e {
        Error::FatalAssignExternalChip
        | Error::FatalUnknownAssignTypeUsed(_)
        | Error::FatalUnsupportedValue(_)
        | Error::FatalUnsupportedTypeValue(_)
        | Error::FatalInvalidArgumentValue(_)
        | Error::FatalLeb128Overflow(_)
        | Error::FatalLeb128AlignOverflow(_)
        | Error::FatalLeb128ThresholdOverflow(_)
        | Error::FatalLeb128InvalidArgumentValue(_)
        | Error::FatalRecoverableButNotProcessed(_)
        | Error::FatalUnknown(_) => true,

        _ => false,
    };
}

pub fn error_index_out_of_bounds(assign_offset: usize) -> Error {
    Error::IndexOutOfBoundsAt(assign_offset)
}

pub fn validate_wb_offset(wb: &WasmBytecode, assign_offset: usize) -> Result<(), Error> {
    if assign_offset >= wb.bytes.len() {
        return Err(error_index_out_of_bounds(assign_offset));
    }
    Ok(())
}

pub fn remap_error_to_index_out_of_bounds_at<E>(assign_offset: usize) -> impl FnOnce(E) -> Error {
    move |_| Error::IndexOutOfBoundsAt(assign_offset)
}
pub fn remap_error_to_assign_at<E>(assign_offset: usize) -> impl FnOnce(E) -> Error {
    move |_| Error::AssignAt(assign_offset)
}
pub fn remap_error_to_invalid_byte_value_at<E>(assign_offset: usize) -> impl FnOnce(E) -> Error {
    move |_| Error::InvalidByteValueAt(assign_offset)
}
pub fn remap_error_to_parse_opcode_failed_at<E>(assign_offset: usize) -> impl FnOnce(E) -> Error {
    move |_| Error::ParseOpcodeFailedAt(assign_offset)
}
pub fn remap_error_to_invalid_enum_value_at<E>(assign_offset: usize) -> impl FnOnce(E) -> Error {
    move |_| Error::InvalidEnumValueAt(assign_offset)
}
pub fn remap_error_to_compute_value_at<E>(assign_offset: usize) -> impl FnOnce(E) -> Error {
    move |_| Error::ComputeValueAt(assign_offset)
}

pub fn remap_error<E>(to: Error) -> impl FnOnce(E) -> Error {
    |_| to
}
