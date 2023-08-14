use std::io;
use halo2_proofs::plonk;
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;

#[derive(Debug)]
pub enum Error {
    /// 1st arg is the offset the error occur
    IndexOutOfBoundsSimple,
    /// 1st arg is the offset the error occur, 2nd - length (or max offset + 1)
    IndexOutOfBounds(usize, usize),
    Leb128EncodeSigned,
    Leb128EncodeUnsigned,
    Leb128MaxBytes,
    AssignAtOffset(usize),
}

pub fn error_index_out_of_bounds_simple() -> Error {
    Error::IndexOutOfBoundsSimple
}

pub fn error_index_out_of_bounds(start_offset: usize, len: usize) -> Error {
    Error::IndexOutOfBounds(start_offset, len)
}

pub fn error_index_out_of_bounds_wb(wb: &WasmBytecode, offset: usize) -> Error {
    Error::IndexOutOfBounds(offset, wb.bytes.len())
}

pub fn check_wb_for_offset(wb: &WasmBytecode, offset: usize) -> Result<(), Error> {
    if offset >= wb.bytes.len() { return Err(error_index_out_of_bounds_wb(wb, offset)) }
    Ok(())
}

pub fn remap_plonk_error(offset: usize) -> impl FnOnce(plonk::Error) -> Error {
    move |_: plonk::Error| Error::AssignAtOffset(offset)
}

pub fn remap_io_error(to: Error) -> impl FnOnce(io::Error) -> Error {
    |_: io::Error| to
}