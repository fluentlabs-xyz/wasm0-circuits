use std::convert::Into;
use std::iter::{IntoIterator, Iterator};
use itertools::Itertools;
use strum_macros::EnumIter;
use crate::wasm_circuit::consts::WasmSectionId::DataCount;

pub static WASM_VERSION_PREFIX_BASE_INDEX: usize = 4;
pub static WASM_VERSION_PREFIX_LENGTH: usize = 4;
pub static WASM_SECTIONS_START_INDEX: usize = WASM_VERSION_PREFIX_BASE_INDEX + WASM_VERSION_PREFIX_LENGTH;
pub static WASM_PREAMBLE_MAGIC_PREFIX: &'static str = "\0asm";
pub static WASM_BLOCK_END: i32 = 0xB;
pub static WASM_BLOCKTYPE_DELIMITER: i32 = 0x40;

#[derive(Copy, Clone, Debug)]
pub enum WasmSectionId {
    Custom = 0,
    Type,
    Import,
    Function,
    Table,
    Memory,
    Global,
    Export,
    Start,
    Element,
    Code,
    Data,
    DataCount,
}
pub const WASM_SECTION_ID_MAX: usize = DataCount as usize;

/// https://webassembly.github.io/spec/core/binary/types.html#number-types
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum NumType {
    I32 = 0x7F,
    I64 = 0x7E,
    F32 = 0x7D,
    F64 = 0x7C,
}

// TODO make it differ from custom section id (which is 0 too)
pub const SECTION_ID_DEFAULT: i32 = 0;

// https://webassembly.github.io/spec/core/binary/types.html#limits
#[derive(Copy, Clone, Debug)]
pub enum LimitsType {
    MinOnly = 0x0,
    MinMax = 0x1,
}

/// https://webassembly.github.io/spec/core/binary/modules.html#data-section
#[derive(Copy, Clone, Debug)]
pub enum MemSegmentType {
    ActiveZero = 0x0,
    Passive = 0x1,
    ActiveVariadic = 0x2,
}

#[derive(Copy, Clone, Debug, EnumIter, PartialEq, Eq, PartialOrd, Ord)]
pub enum NumericInstruction {
    I32Const = 0x41,
    I64Const = 0x42,
    F32Const = 0x43,
    F64Const = 0x44,

    I32Eqz = 0x45,
    I32Eq = 0x46,
    I32Ne = 0x47,
    I32LtS = 0x48,
    I32LtU = 0x49,
    I32GtS = 0x4a,
    I32GtU = 0x4b,
    I32LeS = 0x4c,
    I32LeU = 0x4d,
    I32GeS = 0x4e,
    I32GeU = 0x4f,

    I64Eqz = 0x50,
    I64Eq = 0x51,
    I64Ne = 0x52,
    I64LtS = 0x53,
    I64LtU = 0x54,
    I64GtS = 0x55,
    I64GtU = 0x56,
    I64LeS = 0x57,
    I64LeU = 0x58,
    I64GeS = 0x59,
    I64GeU = 0x5a,

    F32Eq = 0x5b,
    F32Ne = 0x5c,
    F32Lt = 0x5d,
    F32Gt = 0x5e,
    F32Le = 0x5f,
    F32Ge = 0x60,

    F64Eq = 0x61,
    F64Ne = 0x62,
    F64Lt = 0x63,
    F64Gt = 0x64,
    F64Le = 0x65,
    F64Ge = 0x66,

    I32Clz = 0x67,
    I32Ctz = 0x68,
    I32Popcnt = 0x69,
    I32Add = 0x6a,
    I32Sub = 0x6b,
    I32Mul = 0x6c,
    I32DivS = 0x6d,
    I32DivU = 0x6e,
    I32RemS = 0x6f,
    I32RemU = 0x70,
    I32And = 0x71,
    I32Or = 0x72,
    I32Xor = 0x73,
    I32Shl = 0x74,
    I32ShrS = 0x75,
    I32ShrU = 0x76,
    I32Rotl = 0x77,
    I32Rotr = 0x78,

    I64Clz = 0x79,
    I64Ctz = 0x7a,
    I64Popcnt = 0x7b,
    I64Add = 0x7c,
    I64Sub = 0x7d,
    I64Mul = 0x7e,
    I64DivS = 0x7f,
    I64DivU = 0x80,
    I64RemS = 0x81,
    I64RemU = 0x82,
    I64And = 0x83,
    I64Or = 0x84,
    I64Xor = 0x85,
    I64Shl = 0x86,
    I64ShrS = 0x87,
    I64ShrU = 0x88,
    I64Rotl = 0x89,
    I64Rotr = 0x8a,

    F32Abs = 0x8b,
    F32Neg = 0x8c,
    F32Ceil = 0x8d,
    F32Floor = 0x8e,
    F32Trunc = 0x8f,
    F32Nearest = 0x90,
    F32Sqrt = 0x91,
    F32Add = 0x92,
    F32Sub = 0x93,
    F32Mul = 0x94,
    F32Div = 0x95,
    F32Min = 0x96,
    F32Max = 0x97,
    F32Copysign = 0x98,

    F64Abs = 0x99,
    F64Neg = 0x9a,
    F64Ceil = 0x9b,
    F64Floor = 0x9c,
    F64Trunc = 0x9d,
    F64Nearest = 0x9e,
    F64Sqrt = 0x9f,
    F64Add = 0xa0,
    F64Sub = 0xa1,
    F64Mul = 0xa2,
    F64Div = 0xa3,
    F64Min = 0xa4,
    F64Max = 0xa5,
    F64Copysign = 0xa6,
    I32WrapI64 = 0xa7,
    I32TruncSF32 = 0xa8,
    I32TruncUF32 = 0xa9,
    I32TruncSF64 = 0xaa,
    I32TruncUF64 = 0xab,
    I64ExtendSI32 = 0xac,
    I64ExtendUI32 = 0xad,
    I64TruncSF32 = 0xae,
    I64TruncUF32 = 0xaf,
    I64TruncSF64 = 0xb0,
    I64TruncUF64 = 0xb1,
    F32ConvertSI32 = 0xb2,
    F32ConvertUI32 = 0xb3,
    F32ConvertSI64 = 0xb4,
    F32ConvertUI64 = 0xb5,
    F32DemoteF64 = 0xb6,
    F64ConvertSI32 = 0xb7,
    F64ConvertUI32 = 0xb8,
    F64ConvertSI64 = 0xb9,
    F64ConvertUI64 = 0xba,
    F64PromoteF32 = 0xbb,
    I32ReinterpretF32 = 0xbc,
    I64ReinterpretF64 = 0xbd,
    F32ReinterpretI32 = 0xbe,
    F64ReinterpretI64 = 0xbf,

    I32extend8S = 0xc0,
    I32extend16S = 0xc1,
    I64extend8S = 0xc2,
    I64extend16S = 0xc3,
    I64extend32S = 0xc4,
}
pub const NUMERIC_INSTRUCTIONS_WITHOUT_PARAMS: &[NumericInstruction] = &[
    NumericInstruction::I32Add,
    NumericInstruction::I64Add,
];
pub const NUMERIC_INSTRUCTIONS_WITH_LEB_PARAM: &[NumericInstruction] = &[
    NumericInstruction::I32Const,
    NumericInstruction::I64Const,
];

#[derive(Copy, Clone, Debug, EnumIter, PartialEq, Eq, PartialOrd, Ord)]
pub enum VariableInstruction {
    LocalGet = 0x20,
    LocalSet = 0x21,
    LocalTee = 0x22,
    GlobalGet = 0x23,
    GlobalSet = 0x24,
}
pub static VARIABLE_INSTRUCTIONS_WITH_LEB_PARAM: &[VariableInstruction] = &[
    VariableInstruction::LocalGet,
    VariableInstruction::LocalSet,
    VariableInstruction::LocalTee,
    VariableInstruction::GlobalGet,
    VariableInstruction::GlobalSet,
];

#[derive(Copy, Clone, Debug, EnumIter, PartialEq, Eq, PartialOrd, Ord)]
pub enum ControlInstruction {
    Unreachable = 0x00,
    Nop = 0x01,
    Block = 0x02,
    Loop = 0x03,
    If = 0x04,
    Else = 0x05,
    Br = 0x0C,
    BrIf = 0x0D,
    BrTable = 0x0E,
    Return = 0x0F,
    Call = 0x10,
    CallIndirect = 0x11,
}
pub static CONTROL_INSTRUCTIONS_WITHOUT_PARAMS: &[ControlInstruction] = &[
    ControlInstruction::Unreachable,
];
pub static CONTROL_INSTRUCTIONS_WITH_LEB_PARAM: &[ControlInstruction] = &[
    ControlInstruction::Br,
    ControlInstruction::BrIf,
];
pub static CONTROL_INSTRUCTIONS_BLOCK: &[ControlInstruction] = &[
    ControlInstruction::Block,
    ControlInstruction::Loop,
];

impl TryFrom<i32> for NumericInstruction {
    type Error = ();

    fn try_from(v: i32) -> Result<Self, Self::Error> {
        for instr in NUMERIC_INSTRUCTIONS_WITH_LEB_PARAM {
            if v == *instr as i32 { return Ok(*instr); }
        }
        for instr in NUMERIC_INSTRUCTIONS_WITHOUT_PARAMS {
            if v == *instr as i32 { return Ok(*instr); }
        }
        Err(())
    }
}

impl TryFrom<i32> for VariableInstruction {
    type Error = ();

    fn try_from(v: i32) -> Result<Self, Self::Error> {
        for instr in VARIABLE_INSTRUCTIONS_WITH_LEB_PARAM {
            if v == *instr as i32 { return Ok(*instr); }
        }
        Err(())
    }
}

impl TryFrom<i32> for ControlInstruction {
    type Error = ();

    fn try_from(v: i32) -> Result<Self, Self::Error> {
        for instr in CONTROL_INSTRUCTIONS_WITH_LEB_PARAM {
            if v == *instr as i32 { return Ok(*instr); }
        }
        for instr in CONTROL_INSTRUCTIONS_WITHOUT_PARAMS {
            if v == *instr as i32 { return Ok(*instr); }
        }
        for instr in CONTROL_INSTRUCTIONS_BLOCK {
            if v == *instr as i32 { return Ok(*instr); }
        }
        Err(())
    }
}

impl From<NumericInstruction> for usize {
    fn from(t: NumericInstruction) -> Self {
        t as usize
    }
}

impl From<VariableInstruction> for usize {
    fn from(t: VariableInstruction) -> Self {
        t as usize
    }
}

impl From<ControlInstruction> for usize {
    fn from(t: ControlInstruction) -> Self {
        t as usize
    }
}
