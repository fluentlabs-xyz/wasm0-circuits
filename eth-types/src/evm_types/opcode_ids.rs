//! Doc this
use core::fmt::Debug;

use itertools::Itertools;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{de, Deserialize, Serialize};
use std::str::FromStr;
use std::{fmt, matches};
use strum_macros::EnumIter;

use crate::{error::Error, evm_types::GasCost};

/// Opcode enum. One-to-one corresponding to an `u8` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Hash, EnumIter)]
pub enum OpcodeId {
    CALLDATALOAD,
    CALLDATASIZE,
    CALLDATACOPY,
    CODESIZE,
    CODECOPY,
    PC,
    MSIZE,
    RETURN,
    REVERT,

    /// Invalid opcode
    INVALID(u8),

    SHA3,
    ADDRESS,
    BALANCE,
    ORIGIN,
    CALLER,
    CALLVALUE,
    GASPRICE,
    EXTCODESIZE,
    EXTCODECOPY,
    EXTCODEHASH,
    RETURNDATASIZE,
    RETURNDATACOPY,
    BLOCKHASH,
    COINBASE,
    TIMESTAMP,
    NUMBER,
    DIFFICULTY,
    GASLIMIT,
    CHAINID,
    SELFBALANCE,
    BASEFEE,
    SLOAD,
    SSTORE,
    GAS,

    LOG0,
    LOG1,
    LOG2,
    LOG3,
    LOG4,

    CREATE,
    CREATE2,
    CALL,
    CALLCODE,
    DELEGATECALL,
    STATICCALL,
    SELFDESTRUCT,

    // WebAssembly opcode family
    Unreachable,
    Nop,
    Block,
    Loop,
    If,
    Else,
    End,
    Br,
    BrIf,
    BrTable,
    Return,
    Call,
    CallIndirect,
    Drop,
    Select,
    GetLocal,
    SetLocal,
    TeeLocal,
    GetGlobal,
    SetGlobal,
    I32Load,
    I64Load,
    F32Load,
    F64Load,
    I32Load8S,
    I32Load8U,
    I32Load16S,
    I32Load16U,
    I64Load8S,
    I64Load8U,
    I64Load16S,
    I64Load16U,
    I64Load32S,
    I64Load32U,
    I32Store,
    I64Store,
    F32Store,
    F64Store,
    I32Store8,
    I32Store16,
    I64Store8,
    I64Store16,
    I64Store32,
    CurrentMemory,
    GrowMemory,
    I32Const,
    I64Const,
    F32Const,
    F64Const,
    I32Eqz,
    I32Eq,
    I32Ne,
    I32LtS,
    I32LtU,
    I32GtS,
    I32GtU,
    I32LeS,
    I32LeU,
    I32GeS,
    I32GeU,
    I64Eqz,
    I64Eq,
    I64Ne,
    I64LtS,
    I64LtU,
    I64GtS,
    I64GtU,
    I64LeS,
    I64LeU,
    I64GeS,
    I64GeU,
    F32Eq,
    F32Ne,
    F32Lt,
    F32Gt,
    F32Le,
    F32Ge,
    F64Eq,
    F64Ne,
    F64Lt,
    F64Gt,
    F64Le,
    F64Ge,
    I32Clz,
    I32Ctz,
    I32Popcnt,
    I32Add,
    I32Sub,
    I32Mul,
    I32DivS,
    I32DivU,
    I32RemS,
    I32RemU,
    I32And,
    I32Or,
    I32Xor,
    I32Shl,
    I32ShrS,
    I32ShrU,
    I32Rotl,
    I32Rotr,
    I64Clz,
    I64Ctz,
    I64Popcnt,
    I64Add,
    I64Sub,
    I64Mul,
    I64DivS,
    I64DivU,
    I64RemS,
    I64RemU,
    I64And,
    I64Or,
    I64Xor,
    I64Shl,
    I64ShrS,
    I64ShrU,
    I64Rotl,
    I64Rotr,
    F32Abs,
    F32Neg,
    F32Ceil,
    F32Floor,
    F32Trunc,
    F32Nearest,
    F32Sqrt,
    F32Add,
    F32Sub,
    F32Mul,
    F32Div,
    F32Min,
    F32Max,
    F32Copysign,
    F64Abs,
    F64Neg,
    F64Ceil,
    F64Floor,
    F64Trunc,
    F64Nearest,
    F64Sqrt,
    F64Add,
    F64Sub,
    F64Mul,
    F64Div,
    F64Min,
    F64Max,
    F64Copysign,
    I32WrapI64,
    I32TruncSF32,
    I32TruncUF32,
    I32TruncSF64,
    I32TruncUF64,
    I64ExtendSI32,
    I64ExtendUI32,
    I64TruncSF32,
    I64TruncUF32,
    I64TruncSF64,
    I64TruncUF64,
    F32ConvertSI32,
    F32ConvertUI32,
    F32ConvertSI64,
    F32ConvertUI64,
    F32DemoteF64,
    F64ConvertSI32,
    F64ConvertUI32,
    F64ConvertSI64,
    F64ConvertUI64,
    F64PromoteF32,
    I32ReinterpretF32,
    I64ReinterpretF64,
    F32ReinterpretI32,
    F64ReinterpretI64,

    // TODO: "remove these opcodes in the future they don't work"
    STOP,
    ADD,
    MUL,
    SUB,
    DIV,
    SDIV,
    MOD,
    SMOD,
    ADDMOD,
    MULMOD,
    EXP,
    SIGNEXTEND,
    LT,
    GT,
    SLT,
    SGT,
    EQ,
    ISZERO,
    AND,
    OR,
    XOR,
    NOT,
    BYTE,
    SHL,
    SHR,
    SAR,
    POP,
    MLOAD,
    MSTORE,
    MSTORE8,
    JUMP,
    JUMPI,
    JUMPDEST,
    PUSH1,
    PUSH2,
    PUSH3,
    PUSH4,
    PUSH5,
    PUSH6,
    PUSH7,
    PUSH8,
    PUSH9,
    PUSH10,
    PUSH11,
    PUSH12,
    PUSH13,
    PUSH14,
    PUSH15,
    PUSH16,
    PUSH17,
    PUSH18,
    PUSH19,
    PUSH20,
    PUSH21,
    PUSH22,
    PUSH23,
    PUSH24,
    PUSH25,
    PUSH26,
    PUSH27,
    PUSH28,
    PUSH29,
    PUSH30,
    PUSH31,
    PUSH32,
    DUP1,
    DUP2,
    DUP3,
    DUP4,
    DUP5,
    DUP6,
    DUP7,
    DUP8,
    DUP9,
    DUP10,
    DUP11,
    DUP12,
    DUP13,
    DUP14,
    DUP15,
    DUP16,
    SWAP1,
    SWAP2,
    SWAP3,
    SWAP4,
    SWAP5,
    SWAP6,
    SWAP7,
    SWAP8,
    SWAP9,
    SWAP10,
    SWAP11,
    SWAP12,
    SWAP13,
    SWAP14,
    SWAP15,
    SWAP16,
}

impl OpcodeId {
    /// Returns `true` if the `OpcodeId` is a `PUSHn`.
    pub fn is_push(&self) -> bool {
        match self {
            OpcodeId::I32Const | OpcodeId::I64Const => true,
            _ => {
                self.as_u8() >= Self::PUSH1.as_u8() && self.as_u8() <= Self::PUSH32.as_u8()
            },
        }
    }

    pub fn is_evm_call(&self) -> bool {
        match self {
            OpcodeId::STOP | OpcodeId::RETURN | OpcodeId::SHA3 | OpcodeId::ADDRESS | OpcodeId::BALANCE |
            OpcodeId::ORIGIN | OpcodeId::CALLER | OpcodeId::CALLVALUE | OpcodeId::CALLDATALOAD |
            OpcodeId::CALLDATASIZE | OpcodeId::CALLDATACOPY | OpcodeId::CODESIZE | OpcodeId::CODECOPY |
            OpcodeId::GASPRICE | OpcodeId::EXTCODESIZE | OpcodeId::EXTCODECOPY | OpcodeId::EXTCODEHASH |
            OpcodeId::RETURNDATASIZE | OpcodeId::RETURNDATACOPY | OpcodeId::BLOCKHASH | OpcodeId::COINBASE |
            OpcodeId::TIMESTAMP | OpcodeId::NUMBER | OpcodeId::DIFFICULTY | OpcodeId::GASLIMIT |
            OpcodeId::CHAINID | OpcodeId::BASEFEE | OpcodeId::SLOAD | OpcodeId::SSTORE | OpcodeId::LOG0 |
            OpcodeId::LOG1 | OpcodeId::LOG2 | OpcodeId::LOG3 | OpcodeId::LOG4 | OpcodeId::CREATE |
            OpcodeId::CALL | OpcodeId::CALLCODE | OpcodeId::DELEGATECALL | OpcodeId::CREATE2 |
            OpcodeId::STATICCALL | OpcodeId::REVERT | OpcodeId::SELFBALANCE => {
                true
            },
            _ => false
        }
    }

    /// Returns `true` if the `OpcodeId` is a `DUPn`.
    pub fn is_dup(&self) -> bool {
        false
    }

    /// Returns `true` if the `OpcodeId` is a `SWAPn`.
    pub fn is_swap(&self) -> bool {
        false
    }

    /// Returns `true` if the `OpcodeId` is a `LOGn`.
    pub fn is_log(&self) -> bool {
        self.as_u8() >= Self::LOG0.as_u8() && self.as_u8() <= Self::LOG4.as_u8()
    }

    /// Returns `true` if the `OpcodeId` is a CALL-like.
    pub fn is_call(&self) -> bool {
        matches!(
            self,
            OpcodeId::CREATE
                | OpcodeId::CALL
                | OpcodeId::CALLCODE
                | OpcodeId::DELEGATECALL
                | OpcodeId::STATICCALL
        )
    }

    /// Returns `true` if the `OpcodeId` is a CREATE-like.
    pub fn is_create(&self) -> bool {
        matches!(self, OpcodeId::CREATE | Self::CREATE2)
    }

    /// Returns `true` if the `OpcodeId` is a `CALL` or `CREATE` related .
    pub fn is_call_or_create(&self) -> bool {
        self.is_call() || self.is_create()
    }
}

impl OpcodeId {
    /// Returns the `OpcodeId` as a `u8`.
    pub const fn as_u8(&self) -> u8 {
        match self {
            OpcodeId::INVALID(b) => *b,
            // WebAssembly opcode family
            OpcodeId::Unreachable => 0x00,
            OpcodeId::Nop => 0x01,
            OpcodeId::Block => 0x02,
            OpcodeId::Loop => 0x03,
            OpcodeId::If => 0x04,
            OpcodeId::Else => 0x05,
            OpcodeId::End => 0x0b,
            OpcodeId::Br => 0x0c,
            OpcodeId::BrIf => 0x0d,
            OpcodeId::BrTable => 0x0e,
            OpcodeId::Return => 0x0f,
            OpcodeId::Call => 0x10,
            OpcodeId::CallIndirect => 0x11,
            OpcodeId::Drop => 0x1a,
            OpcodeId::Select => 0x1b,
            OpcodeId::GetLocal => 0x20,
            OpcodeId::SetLocal => 0x21,
            OpcodeId::TeeLocal => 0x22,
            OpcodeId::GetGlobal => 0x23,
            OpcodeId::SetGlobal => 0x24,
            OpcodeId::I32Load => 0x28,
            OpcodeId::I64Load => 0x29,
            OpcodeId::F32Load => 0x2a,
            OpcodeId::F64Load => 0x2b,
            OpcodeId::I32Load8S => 0x2c,
            OpcodeId::I32Load8U => 0x2d,
            OpcodeId::I32Load16S => 0x2e,
            OpcodeId::I32Load16U => 0x2f,
            OpcodeId::I64Load8S => 0x30,
            OpcodeId::I64Load8U => 0x31,
            OpcodeId::I64Load16S => 0x32,
            OpcodeId::I64Load16U => 0x33,
            OpcodeId::I64Load32S => 0x34,
            OpcodeId::I64Load32U => 0x35,
            OpcodeId::I32Store => 0x36,
            OpcodeId::I64Store => 0x37,
            OpcodeId::F32Store => 0x38,
            OpcodeId::F64Store => 0x39,
            OpcodeId::I32Store8 => 0x3a,
            OpcodeId::I32Store16 => 0x3b,
            OpcodeId::I64Store8 => 0x3c,
            OpcodeId::I64Store16 => 0x3d,
            OpcodeId::I64Store32 => 0x3e,
            OpcodeId::CurrentMemory => 0x3f,
            OpcodeId::GrowMemory => 0x40,
            OpcodeId::I32Const => 0x41,
            OpcodeId::I64Const => 0x42,
            OpcodeId::F32Const => 0x43,
            OpcodeId::F64Const => 0x44,
            OpcodeId::I32Eqz => 0x45,
            OpcodeId::I32Eq => 0x46,
            OpcodeId::I32Ne => 0x47,
            OpcodeId::I32LtS => 0x48,
            OpcodeId::I32LtU => 0x49,
            OpcodeId::I32GtS => 0x4a,
            OpcodeId::I32GtU => 0x4b,
            OpcodeId::I32LeS => 0x4c,
            OpcodeId::I32LeU => 0x4d,
            OpcodeId::I32GeS => 0x4e,
            OpcodeId::I32GeU => 0x4f,
            OpcodeId::I64Eqz => 0x50,
            OpcodeId::I64Eq => 0x51,
            OpcodeId::I64Ne => 0x52,
            OpcodeId::I64LtS => 0x53,
            OpcodeId::I64LtU => 0x54,
            OpcodeId::I64GtS => 0x55,
            OpcodeId::I64GtU => 0x56,
            OpcodeId::I64LeS => 0x57,
            OpcodeId::I64LeU => 0x58,
            OpcodeId::I64GeS => 0x59,
            OpcodeId::I64GeU => 0x5a,
            OpcodeId::F32Eq => 0x5b,
            OpcodeId::F32Ne => 0x5c,
            OpcodeId::F32Lt => 0x5d,
            OpcodeId::F32Gt => 0x5e,
            OpcodeId::F32Le => 0x5f,
            OpcodeId::F32Ge => 0x60,
            OpcodeId::F64Eq => 0x61,
            OpcodeId::F64Ne => 0x62,
            OpcodeId::F64Lt => 0x63,
            OpcodeId::F64Gt => 0x64,
            OpcodeId::F64Le => 0x65,
            OpcodeId::F64Ge => 0x66,
            OpcodeId::I32Clz => 0x67,
            OpcodeId::I32Ctz => 0x68,
            OpcodeId::I32Popcnt => 0x69,
            OpcodeId::I32Add => 0x6a,
            OpcodeId::I32Sub => 0x6b,
            OpcodeId::I32Mul => 0x6c,
            OpcodeId::I32DivS => 0x6d,
            OpcodeId::I32DivU => 0x6e,
            OpcodeId::I32RemS => 0x6f,
            OpcodeId::I32RemU => 0x70,
            OpcodeId::I32And => 0x71,
            OpcodeId::I32Or => 0x72,
            OpcodeId::I32Xor => 0x73,
            OpcodeId::I32Shl => 0x74,
            OpcodeId::I32ShrS => 0x75,
            OpcodeId::I32ShrU => 0x76,
            OpcodeId::I32Rotl => 0x77,
            OpcodeId::I32Rotr => 0x78,
            OpcodeId::I64Clz => 0x79,
            OpcodeId::I64Ctz => 0x7a,
            OpcodeId::I64Popcnt => 0x7b,
            OpcodeId::I64Add => 0x7c,
            OpcodeId::I64Sub => 0x7d,
            OpcodeId::I64Mul => 0x7e,
            OpcodeId::I64DivS => 0x7f,
            OpcodeId::I64DivU => 0x80,
            OpcodeId::I64RemS => 0x81,
            OpcodeId::I64RemU => 0x82,
            OpcodeId::I64And => 0x83,
            OpcodeId::I64Or => 0x84,
            OpcodeId::I64Xor => 0x85,
            OpcodeId::I64Shl => 0x86,
            OpcodeId::I64ShrS => 0x87,
            OpcodeId::I64ShrU => 0x88,
            OpcodeId::I64Rotl => 0x89,
            OpcodeId::I64Rotr => 0x8a,
            OpcodeId::F32Abs => 0x8b,
            OpcodeId::F32Neg => 0x8c,
            OpcodeId::F32Ceil => 0x8d,
            OpcodeId::F32Floor => 0x8e,
            OpcodeId::F32Trunc => 0x8f,
            OpcodeId::F32Nearest => 0x90,
            OpcodeId::F32Sqrt => 0x91,
            OpcodeId::F32Add => 0x92,
            OpcodeId::F32Sub => 0x93,
            OpcodeId::F32Mul => 0x94,
            OpcodeId::F32Div => 0x95,
            OpcodeId::F32Min => 0x96,
            OpcodeId::F32Max => 0x97,
            OpcodeId::F32Copysign => 0x98,
            OpcodeId::F64Abs => 0x99,
            OpcodeId::F64Neg => 0x9a,
            OpcodeId::F64Ceil => 0x9b,
            OpcodeId::F64Floor => 0x9c,
            OpcodeId::F64Trunc => 0x9d,
            OpcodeId::F64Nearest => 0x9e,
            OpcodeId::F64Sqrt => 0x9f,
            OpcodeId::F64Add => 0xa0,
            OpcodeId::F64Sub => 0xa1,
            OpcodeId::F64Mul => 0xa2,
            OpcodeId::F64Div => 0xa3,
            OpcodeId::F64Min => 0xa4,
            OpcodeId::F64Max => 0xa5,
            OpcodeId::F64Copysign => 0xa6,
            OpcodeId::I32WrapI64 => 0xa7,
            OpcodeId::I32TruncSF32 => 0xa8,
            OpcodeId::I32TruncUF32 => 0xa9,
            OpcodeId::I32TruncSF64 => 0xaa,
            OpcodeId::I32TruncUF64 => 0xab,
            OpcodeId::I64ExtendSI32 => 0xac,
            OpcodeId::I64ExtendUI32 => 0xad,
            OpcodeId::I64TruncSF32 => 0xae,
            OpcodeId::I64TruncUF32 => 0xaf,
            OpcodeId::I64TruncSF64 => 0xb0,
            OpcodeId::I64TruncUF64 => 0xb1,
            OpcodeId::F32ConvertSI32 => 0xb2,
            OpcodeId::F32ConvertUI32 => 0xb3,
            OpcodeId::F32ConvertSI64 => 0xb4,
            OpcodeId::F32ConvertUI64 => 0xb5,
            OpcodeId::F32DemoteF64 => 0xb6,
            OpcodeId::F64ConvertSI32 => 0xb7,
            OpcodeId::F64ConvertUI32 => 0xb8,
            OpcodeId::F64ConvertSI64 => 0xb9,
            OpcodeId::F64ConvertUI64 => 0xba,
            OpcodeId::F64PromoteF32 => 0xbb,
            OpcodeId::I32ReinterpretF32 => 0xbc,
            OpcodeId::I64ReinterpretF64 => 0xbd,
            OpcodeId::F32ReinterpretI32 => 0xbe,
            OpcodeId::F64ReinterpretI64 => 0xbf,
            // EVM opcode family
            OpcodeId::CALLDATALOAD => 0xc1,
            OpcodeId::CALLDATASIZE => 0xc2,
            OpcodeId::CALLDATACOPY => 0xc3,
            OpcodeId::CODESIZE => 0xc4,
            OpcodeId::CODECOPY => 0xc5,
            OpcodeId::PC => 0xc6,
            OpcodeId::MSIZE => 0xc7,
            OpcodeId::RETURN => 0xc9,
            OpcodeId::REVERT => 0xca,
            OpcodeId::SHA3 => 0xcb,
            OpcodeId::ADDRESS => 0xcc,
            OpcodeId::BALANCE => 0xcd,
            OpcodeId::ORIGIN => 0xce,
            OpcodeId::CALLER => 0xcf,
            OpcodeId::CALLVALUE => 0xd0,
            OpcodeId::GASPRICE => 0xd1,
            OpcodeId::EXTCODESIZE => 0xd2,
            OpcodeId::EXTCODECOPY => 0xd3,
            OpcodeId::EXTCODEHASH => 0xd4,
            OpcodeId::RETURNDATASIZE => 0xd5,
            OpcodeId::RETURNDATACOPY => 0xd6,
            OpcodeId::BLOCKHASH => 0xd7,
            OpcodeId::COINBASE => 0xd8,
            OpcodeId::TIMESTAMP => 0xd9,
            OpcodeId::NUMBER => 0xda,
            OpcodeId::DIFFICULTY => 0xdb,
            OpcodeId::GASLIMIT => 0xdc,
            OpcodeId::CHAINID => 0xde,
            OpcodeId::SELFBALANCE => 0xdf,
            OpcodeId::BASEFEE => 0xe0,
            OpcodeId::SLOAD => 0xe1,
            OpcodeId::SSTORE => 0xe2,
            OpcodeId::GAS => 0xe3,
            OpcodeId::LOG0 => 0xe4,
            OpcodeId::LOG1 => 0xe5,
            OpcodeId::LOG2 => 0xe6,
            OpcodeId::LOG3 => 0xe7,
            OpcodeId::LOG4 => 0xe8,
            OpcodeId::CREATE => 0xe9,
            OpcodeId::CREATE2 => 0xe0,
            OpcodeId::CALL => 0xea,
            OpcodeId::CALLCODE => 0xeb,
            OpcodeId::DELEGATECALL => 0xec,
            OpcodeId::STATICCALL => 0xed,
            OpcodeId::SELFDESTRUCT => 0xef,
            _ => 0x00,
        }
    }

    /// Returns the `OpcodeId` as a `u64`.
    pub const fn as_u64(&self) -> u64 {
        self.as_u8() as u64
    }

    /// Returns the constant gas cost of `OpcodeId`
    pub const fn constant_gas_cost(&self) -> GasCost {
        match self {
            OpcodeId::SHA3 => GasCost::SHA3,
            OpcodeId::ADDRESS => GasCost::QUICK,
            OpcodeId::BALANCE => GasCost::WARM_ACCESS,
            OpcodeId::ORIGIN => GasCost::QUICK,
            OpcodeId::CALLER => GasCost::QUICK,
            OpcodeId::CALLVALUE => GasCost::QUICK,
            OpcodeId::CALLDATALOAD => GasCost::FASTEST,
            OpcodeId::CALLDATASIZE => GasCost::QUICK,
            OpcodeId::CALLDATACOPY => GasCost::FASTEST,
            OpcodeId::CODESIZE => GasCost::QUICK,
            OpcodeId::CODECOPY => GasCost::FASTEST,
            OpcodeId::GASPRICE => GasCost::QUICK,
            OpcodeId::EXTCODESIZE => GasCost::WARM_ACCESS,
            OpcodeId::EXTCODECOPY => GasCost::WARM_ACCESS,
            OpcodeId::RETURNDATASIZE => GasCost::QUICK,
            OpcodeId::RETURNDATACOPY => GasCost::FASTEST,
            OpcodeId::EXTCODEHASH => GasCost::WARM_ACCESS,
            OpcodeId::BLOCKHASH => GasCost::EXT,
            OpcodeId::COINBASE => GasCost::QUICK,
            OpcodeId::TIMESTAMP => GasCost::QUICK,
            OpcodeId::NUMBER => GasCost::QUICK,
            OpcodeId::DIFFICULTY => GasCost::QUICK,
            OpcodeId::GASLIMIT => GasCost::QUICK,
            OpcodeId::CHAINID => GasCost::QUICK,
            OpcodeId::SELFBALANCE => GasCost::FAST,
            OpcodeId::BASEFEE => GasCost::QUICK,
            OpcodeId::SLOAD => GasCost::ZERO,
            OpcodeId::SSTORE => GasCost::ZERO,
            OpcodeId::PC => GasCost::QUICK,
            OpcodeId::MSIZE => GasCost::QUICK,
            OpcodeId::GAS => GasCost::QUICK,
            OpcodeId::LOG0 => GasCost::ZERO,
            OpcodeId::LOG1 => GasCost::ZERO,
            OpcodeId::LOG2 => GasCost::ZERO,
            OpcodeId::LOG3 => GasCost::ZERO,
            OpcodeId::LOG4 => GasCost::ZERO,
            OpcodeId::CREATE => GasCost::CREATE,
            OpcodeId::CALL => GasCost::WARM_ACCESS,
            OpcodeId::CALLCODE => GasCost::WARM_ACCESS,
            OpcodeId::RETURN => GasCost::ZERO,
            OpcodeId::DELEGATECALL => GasCost::WARM_ACCESS,
            OpcodeId::CREATE2 => GasCost::CREATE,
            OpcodeId::STATICCALL => GasCost::WARM_ACCESS,
            OpcodeId::REVERT => GasCost::ZERO,
            OpcodeId::INVALID(_) => GasCost::ZERO,
            OpcodeId::SELFDESTRUCT => GasCost::SELFDESTRUCT,
            // use zero gas for remaining
            _ => GasCost::ZERO,
        }
    }

    /// Returns invalid stack pointers of `OpcodeId`
    pub fn invalid_stack_ptrs(&self) -> Vec<u32> {
        let (min_stack_ptr, max_stack_ptr): (u32, u32) = match self {
            // `min_stack_pointer` 0 means stack overflow never happen, for example, `OpcodeId::ADD`
            // can only encounter underflow error, but never encounter overflow error.
            // `max_stack_pointer` means max stack poniter for op code normally run. for example,
            // `OpcodeId::ADD` 's max stack pointer is 1022, when actual sp > 1022, will
            // encounter underflow error.

            OpcodeId::I32Add => (0, 1022),
            OpcodeId::I64Add => (0, 1022),
            OpcodeId::I32Const => (1, 1024),
            OpcodeId::I64Const => (1, 1024),

            OpcodeId::SHA3 => (0, 1022),
            OpcodeId::ADDRESS => (1, 1024),
            OpcodeId::BALANCE => (0, 1023),
            OpcodeId::ORIGIN => (1, 1024),
            OpcodeId::CALLER => (1, 1024),
            OpcodeId::CALLVALUE => (1, 1024),
            OpcodeId::CALLDATALOAD => (0, 1023),
            OpcodeId::CALLDATASIZE => (1, 1024),
            OpcodeId::CALLDATACOPY => (0, 1021),
            OpcodeId::CODESIZE => (1, 1024),
            OpcodeId::CODECOPY => (0, 1021),
            OpcodeId::GASPRICE => (1, 1024),
            OpcodeId::EXTCODESIZE => (0, 1023),
            OpcodeId::EXTCODECOPY => (0, 1020),
            OpcodeId::RETURNDATASIZE => (1, 1024),
            OpcodeId::RETURNDATACOPY => (0, 1021),
            OpcodeId::EXTCODEHASH => (1, 1024),
            OpcodeId::BLOCKHASH => (0, 1023),
            OpcodeId::COINBASE => (1, 1024),
            OpcodeId::TIMESTAMP => (1, 1024),
            OpcodeId::NUMBER => (1, 1024),
            OpcodeId::DIFFICULTY => (1, 1024),
            OpcodeId::GASLIMIT => (1, 1024),
            OpcodeId::CHAINID => (1, 1024),
            OpcodeId::SELFBALANCE => (1, 1024),
            OpcodeId::BASEFEE => (1, 1024),
            OpcodeId::SLOAD => (0, 1023),
            OpcodeId::SSTORE => (0, 1022),
            OpcodeId::PC => (1, 1024),
            OpcodeId::MSIZE => (1, 1024),
            OpcodeId::GAS => (1, 1024),
            OpcodeId::LOG0 => (0, 1022),
            OpcodeId::LOG1 => (0, 1021),
            OpcodeId::LOG2 => (0, 1020),
            OpcodeId::LOG3 => (0, 1019),
            OpcodeId::LOG4 => (0, 1018),
            OpcodeId::CREATE => (0, 1021),
            OpcodeId::CALL => (0, 1017),
            OpcodeId::CALLCODE => (0, 1017),
            OpcodeId::RETURN => (0, 1022),
            OpcodeId::DELEGATECALL => (0, 1018),
            OpcodeId::CREATE2 => (0, 1020),
            OpcodeId::STATICCALL => (0, 1018),
            OpcodeId::REVERT => (0, 1022),
            OpcodeId::SELFDESTRUCT => (0, 1023),
            _ => (0, 0),
        };

        debug_assert!(max_stack_ptr <= 1024);

        (0..min_stack_ptr)
            // Range (1025..=1024) is valid and it should be converted to an empty vector.
            .chain(max_stack_ptr.checked_add(1).unwrap()..=1024)
            .collect()
    }

    /// Returns `true` if the `OpcodeId` has memory access
    pub const fn has_memory_access(&self) -> bool {
        matches!(
            self,
            OpcodeId::MLOAD
                | OpcodeId::MSTORE
                | OpcodeId::MSTORE8
                | OpcodeId::CALLDATACOPY
                | OpcodeId::RETURNDATACOPY
                | OpcodeId::CODECOPY
                | OpcodeId::EXTCODECOPY
        )
    }

    /// Returns PUSHn opcode from parameter n.
    pub fn push_n(n: u8) -> Result<Self, Error> {
        if (1..=32).contains(&n) {
            Ok(OpcodeId::from(OpcodeId::PUSH1.as_u8() + n - 1))
        } else {
            Err(Error::InvalidOpConversion)
        }
    }

    /// If operation has postfix returns it, otherwise None.
    pub fn postfix(&self) -> Option<u8> {
        match self {
            OpcodeId::I32Const => Some(4),
            OpcodeId::I64Const => Some(8),
            _ => {
                if self.is_push() {
                    Some(self.as_u8() - OpcodeId::PUSH1.as_u8() + 1)
                } else if self.is_dup() {
                    Some(self.as_u8() - OpcodeId::DUP1.as_u8() + 1)
                } else if self.is_swap() {
                    Some(self.as_u8() - OpcodeId::SWAP1.as_u8() + 1)
                } else if self.is_log() {
                    Some(self.as_u8() - OpcodeId::LOG0.as_u8())
                } else {
                    None
                }
            }
        }
    }

    /// Returns number of bytes used by immediate data. This is > 0 only for
    /// push opcodes.
    pub fn data_len(&self) -> usize {
        match self {
            OpcodeId::I32Const => 4,
            OpcodeId::I64Const => 8,
            _ => {
                if self.is_push() {
                    (self.as_u8() - OpcodeId::PUSH1.as_u8() + 1) as usize
                } else {
                    0
                }
            },
        }
    }

    /// Returns the all valid opcodes.
    pub fn valid_opcodes() -> Vec<Self> {
        (u8::MIN..=u8::MAX).fold(vec![], |mut acc, val| {
            if !matches!(val.into(), Self::INVALID(_)) {
                acc.push(val.into());
            }
            acc
        })
    }

    /// Returns the all invalid opcodes.
    pub fn invalid_opcodes() -> Vec<Self> {
        (u8::MIN..=u8::MAX).fold(vec![], |mut acc, val| {
            if matches!(val.into(), Self::INVALID(_)) {
                acc.push(Self::INVALID(val));
            }
            acc
        })
    }
}

impl From<u8> for OpcodeId {
    fn from(value: u8) -> Self {
        match value {
            0x00 => OpcodeId::Unreachable,
            0x01 => OpcodeId::Nop,
            0x02 => OpcodeId::Block,
            0x03 => OpcodeId::Loop,
            0x04 => OpcodeId::If,
            0x05 => OpcodeId::Else,
            0x0b => OpcodeId::End,
            0x0c => OpcodeId::Br,
            0x0d => OpcodeId::BrIf,
            0x0e => OpcodeId::BrTable,
            0x0f => OpcodeId::Return,
            0x10 => OpcodeId::Call,
            0x11 => OpcodeId::CallIndirect,
            0x1a => OpcodeId::Drop,
            0x1b => OpcodeId::Select,
            0x20 => OpcodeId::GetLocal,
            0x21 => OpcodeId::SetLocal,
            0x22 => OpcodeId::TeeLocal,
            0x23 => OpcodeId::GetGlobal,
            0x24 => OpcodeId::SetGlobal,
            0x28 => OpcodeId::I32Load,
            0x29 => OpcodeId::I64Load,
            0x2a => OpcodeId::F32Load,
            0x2b => OpcodeId::F64Load,
            0x2c => OpcodeId::I32Load8S,
            0x2d => OpcodeId::I32Load8U,
            0x2e => OpcodeId::I32Load16S,
            0x2f => OpcodeId::I32Load16U,
            0x30 => OpcodeId::I64Load8S,
            0x31 => OpcodeId::I64Load8U,
            0x32 => OpcodeId::I64Load16S,
            0x33 => OpcodeId::I64Load16U,
            0x34 => OpcodeId::I64Load32S,
            0x35 => OpcodeId::I64Load32U,
            0x36 => OpcodeId::I32Store,
            0x37 => OpcodeId::I64Store,
            0x38 => OpcodeId::F32Store,
            0x39 => OpcodeId::F64Store,
            0x3a => OpcodeId::I32Store8,
            0x3b => OpcodeId::I32Store16,
            0x3c => OpcodeId::I64Store8,
            0x3d => OpcodeId::I64Store16,
            0x3e => OpcodeId::I64Store32,
            0x3f => OpcodeId::CurrentMemory,
            0x40 => OpcodeId::GrowMemory,
            0x41 => OpcodeId::I32Const,
            0x42 => OpcodeId::I64Const,
            0x43 => OpcodeId::F32Const,
            0x44 => OpcodeId::F64Const,
            0x45 => OpcodeId::I32Eqz,
            0x46 => OpcodeId::I32Eq,
            0x47 => OpcodeId::I32Ne,
            0x48 => OpcodeId::I32LtS,
            0x49 => OpcodeId::I32LtU,
            0x4a => OpcodeId::I32GtS,
            0x4b => OpcodeId::I32GtU,
            0x4c => OpcodeId::I32LeS,
            0x4d => OpcodeId::I32LeU,
            0x4e => OpcodeId::I32GeS,
            0x4f => OpcodeId::I32GeU,
            0x50 => OpcodeId::I64Eqz,
            0x51 => OpcodeId::I64Eq,
            0x52 => OpcodeId::I64Ne,
            0x53 => OpcodeId::I64LtS,
            0x54 => OpcodeId::I64LtU,
            0x55 => OpcodeId::I64GtS,
            0x56 => OpcodeId::I64GtU,
            0x57 => OpcodeId::I64LeS,
            0x58 => OpcodeId::I64LeU,
            0x59 => OpcodeId::I64GeS,
            0x5a => OpcodeId::I64GeU,
            0x5b => OpcodeId::F32Eq,
            0x5c => OpcodeId::F32Ne,
            0x5d => OpcodeId::F32Lt,
            0x5e => OpcodeId::F32Gt,
            0x5f => OpcodeId::F32Le,
            0x60 => OpcodeId::F32Ge,
            0x61 => OpcodeId::F64Eq,
            0x62 => OpcodeId::F64Ne,
            0x63 => OpcodeId::F64Lt,
            0x64 => OpcodeId::F64Gt,
            0x65 => OpcodeId::F64Le,
            0x66 => OpcodeId::F64Ge,
            0x67 => OpcodeId::I32Clz,
            0x68 => OpcodeId::I32Ctz,
            0x69 => OpcodeId::I32Popcnt,
            0x6a => OpcodeId::I32Add,
            0x6b => OpcodeId::I32Sub,
            0x6c => OpcodeId::I32Mul,
            0x6d => OpcodeId::I32DivS,
            0x6e => OpcodeId::I32DivU,
            0x6f => OpcodeId::I32RemS,
            0x70 => OpcodeId::I32RemU,
            0x71 => OpcodeId::I32And,
            0x72 => OpcodeId::I32Or,
            0x73 => OpcodeId::I32Xor,
            0x74 => OpcodeId::I32Shl,
            0x75 => OpcodeId::I32ShrS,
            0x76 => OpcodeId::I32ShrU,
            0x77 => OpcodeId::I32Rotl,
            0x78 => OpcodeId::I32Rotr,
            0x79 => OpcodeId::I64Clz,
            0x7a => OpcodeId::I64Ctz,
            0x7b => OpcodeId::I64Popcnt,
            0x7c => OpcodeId::I64Add,
            0x7d => OpcodeId::I64Sub,
            0x7e => OpcodeId::I64Mul,
            0x7f => OpcodeId::I64DivS,
            0x80 => OpcodeId::I64DivU,
            0x81 => OpcodeId::I64RemS,
            0x82 => OpcodeId::I64RemU,
            0x83 => OpcodeId::I64And,
            0x84 => OpcodeId::I64Or,
            0x85 => OpcodeId::I64Xor,
            0x86 => OpcodeId::I64Shl,
            0x87 => OpcodeId::I64ShrS,
            0x88 => OpcodeId::I64ShrU,
            0x89 => OpcodeId::I64Rotl,
            0x8a => OpcodeId::I64Rotr,
            0x8b => OpcodeId::F32Abs,
            0x8c => OpcodeId::F32Neg,
            0x8d => OpcodeId::F32Ceil,
            0x8e => OpcodeId::F32Floor,
            0x8f => OpcodeId::F32Trunc,
            0x90 => OpcodeId::F32Nearest,
            0x91 => OpcodeId::F32Sqrt,
            0x92 => OpcodeId::F32Add,
            0x93 => OpcodeId::F32Sub,
            0x94 => OpcodeId::F32Mul,
            0x95 => OpcodeId::F32Div,
            0x96 => OpcodeId::F32Min,
            0x97 => OpcodeId::F32Max,
            0x98 => OpcodeId::F32Copysign,
            0x99 => OpcodeId::F64Abs,
            0x9a => OpcodeId::F64Neg,
            0x9b => OpcodeId::F64Ceil,
            0x9c => OpcodeId::F64Floor,
            0x9d => OpcodeId::F64Trunc,
            0x9e => OpcodeId::F64Nearest,
            0x9f => OpcodeId::F64Sqrt,
            0xa0 => OpcodeId::F64Add,
            0xa1 => OpcodeId::F64Sub,
            0xa2 => OpcodeId::F64Mul,
            0xa3 => OpcodeId::F64Div,
            0xa4 => OpcodeId::F64Min,
            0xa5 => OpcodeId::F64Max,
            0xa6 => OpcodeId::F64Copysign,
            0xa7 => OpcodeId::I32WrapI64,
            0xa8 => OpcodeId::I32TruncSF32,
            0xa9 => OpcodeId::I32TruncUF32,
            0xaa => OpcodeId::I32TruncSF64,
            0xab => OpcodeId::I32TruncUF64,
            0xac => OpcodeId::I64ExtendSI32,
            0xad => OpcodeId::I64ExtendUI32,
            0xae => OpcodeId::I64TruncSF32,
            0xaf => OpcodeId::I64TruncUF32,
            0xb0 => OpcodeId::I64TruncSF64,
            0xb1 => OpcodeId::I64TruncUF64,
            0xb2 => OpcodeId::F32ConvertSI32,
            0xb3 => OpcodeId::F32ConvertUI32,
            0xb4 => OpcodeId::F32ConvertSI64,
            0xb5 => OpcodeId::F32ConvertUI64,
            0xb6 => OpcodeId::F32DemoteF64,
            0xb7 => OpcodeId::F64ConvertSI32,
            0xb8 => OpcodeId::F64ConvertUI32,
            0xb9 => OpcodeId::F64ConvertSI64,
            0xba => OpcodeId::F64ConvertUI64,
            0xbb => OpcodeId::F64PromoteF32,
            0xbc => OpcodeId::I32ReinterpretF32,
            0xbd => OpcodeId::I64ReinterpretF64,
            0xbe => OpcodeId::F32ReinterpretI32,
            0xbf => OpcodeId::F64ReinterpretI64,
            // EVM opcode family
            0xc1 => OpcodeId::CALLDATALOAD,
            0xc2 => OpcodeId::CALLDATASIZE,
            0xc3 => OpcodeId::CALLDATACOPY,
            0xc4 => OpcodeId::CODESIZE,
            0xc5 => OpcodeId::CODECOPY,
            0xc6 => OpcodeId::PC,
            0xc7 => OpcodeId::MSIZE,
            0xc9 => OpcodeId::RETURN,
            0xca => OpcodeId::REVERT,
            0xcb => OpcodeId::SHA3,
            0xcc => OpcodeId::ADDRESS,
            0xcd => OpcodeId::BALANCE,
            0xce => OpcodeId::ORIGIN,
            0xcf => OpcodeId::CALLER,
            0xd0 => OpcodeId::CALLVALUE,
            0xd1 => OpcodeId::GASPRICE,
            0xd2 => OpcodeId::EXTCODESIZE,
            0xd3 => OpcodeId::EXTCODECOPY,
            0xd4 => OpcodeId::EXTCODEHASH,
            0xd5 => OpcodeId::RETURNDATASIZE,
            0xd6 => OpcodeId::RETURNDATACOPY,
            0xd7 => OpcodeId::BLOCKHASH,
            0xd8 => OpcodeId::COINBASE,
            0xd9 => OpcodeId::TIMESTAMP,
            0xda => OpcodeId::NUMBER,
            0xdb => OpcodeId::DIFFICULTY,
            0xdc => OpcodeId::GASLIMIT,
            0xde => OpcodeId::CHAINID,
            0xdf => OpcodeId::SELFBALANCE,
            0xe0 => OpcodeId::BASEFEE,
            0xe1 => OpcodeId::SLOAD,
            0xe2 => OpcodeId::SSTORE,
            0xe3 => OpcodeId::GAS,
            0xe4 => OpcodeId::LOG0,
            0xe5 => OpcodeId::LOG1,
            0xe6 => OpcodeId::LOG2,
            0xe7 => OpcodeId::LOG3,
            0xe8 => OpcodeId::LOG4,
            0xe9 => OpcodeId::CREATE,
            0xea => OpcodeId::CREATE2,
            0xeb => OpcodeId::CALL,
            0xec => OpcodeId::CALLCODE,
            0xed => OpcodeId::DELEGATECALL,
            0xee => OpcodeId::STATICCALL,
            0xef => OpcodeId::SELFDESTRUCT,
            // invalid opcode
            _ => OpcodeId::INVALID(value)
        }
    }
}

impl FromStr for OpcodeId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let items = s.split(" ").collect_vec();
        Ok(match items[0] {
            // WASM opcode family
            "unreachable" => OpcodeId::Unreachable,
            "nop" => OpcodeId::Nop,
            // TODO temporal? need a fix?
            "gas" => OpcodeId::GAS,
            "block" => OpcodeId::Block,
            "loop" => OpcodeId::Loop,
            "if" => OpcodeId::If,
            "else" => OpcodeId::Else,
            "end" => OpcodeId::End,
            "br" => OpcodeId::Br,
            "br_if" => OpcodeId::BrIf,
            "br_table" => OpcodeId::BrTable,
            "return" => OpcodeId::Return,
            "call" => OpcodeId::Call,
            "call_indirect" => OpcodeId::CallIndirect,
            "drop" => OpcodeId::Drop,
            "select" => OpcodeId::Select,
            "get_local" => OpcodeId::GetLocal,
            "set_local" => OpcodeId::SetLocal,
            "tee_local" => OpcodeId::TeeLocal,
            "get_global" => OpcodeId::GetGlobal,
            "set_global" => OpcodeId::SetGlobal,
            "i32_load" => OpcodeId::I32Load,
            "i64_load" => OpcodeId::I64Load,
            "f32_load" => OpcodeId::F32Load,
            "f64_load" => OpcodeId::F64Load,
            "i32_load8_s" => OpcodeId::I32Load8S,
            "i32_load8_u" => OpcodeId::I32Load8U,
            "i32_load16_s" => OpcodeId::I32Load16S,
            "i32_load16_u" => OpcodeId::I32Load16U,
            "i64_load8_s" => OpcodeId::I64Load8S,
            "i64_load8_u" => OpcodeId::I64Load8U,
            "i64_load16_s" => OpcodeId::I64Load16S,
            "i64_load16_u" => OpcodeId::I64Load16U,
            "i64_load32_s" => OpcodeId::I64Load32S,
            "i64_load32_u" => OpcodeId::I64Load32U,
            "i32_store" => OpcodeId::I32Store,
            "i64_store" => OpcodeId::I64Store,
            "f32_store" => OpcodeId::F32Store,
            "f64_store" => OpcodeId::F64Store,
            "i32_store8" => OpcodeId::I32Store8,
            "i32_store16" => OpcodeId::I32Store16,
            "i64_store8" => OpcodeId::I64Store8,
            "i64_store16" => OpcodeId::I64Store16,
            "i64_store32" => OpcodeId::I64Store32,
            "current_memory" => OpcodeId::CurrentMemory,
            "grow_memory" => OpcodeId::GrowMemory,
            "i32_const" => OpcodeId::I32Const,
            "i64_const" => OpcodeId::I64Const,
            "f32_const" => OpcodeId::F32Const,
            "f64_const" => OpcodeId::F64Const,
            "i32_eqz" => OpcodeId::I32Eqz,
            "i32_eq" => OpcodeId::I32Eq,
            "i32_ne" => OpcodeId::I32Ne,
            "i32_lt_s" => OpcodeId::I32LtS,
            "i32_lt_u" => OpcodeId::I32LtU,
            "i32_gt_s" => OpcodeId::I32GtS,
            "i32_gt_u" => OpcodeId::I32GtU,
            "i32_le_s" => OpcodeId::I32LeS,
            "i32_le_u" => OpcodeId::I32LeU,
            "i32_ge_s" => OpcodeId::I32GeS,
            "i32_ge_u" => OpcodeId::I32GeU,
            "i64_eqz" => OpcodeId::I64Eqz,
            "i64_eq" => OpcodeId::I64Eq,
            "i64_ne" => OpcodeId::I64Ne,
            "i64_lt_s" => OpcodeId::I64LtS,
            "i64_lt_u" => OpcodeId::I64LtU,
            "i64_gt_s" => OpcodeId::I64GtS,
            "i64_gt_u" => OpcodeId::I64GtU,
            "i64_le_s" => OpcodeId::I64LeS,
            "i64_le_u" => OpcodeId::I64LeU,
            "i64_ge_s" => OpcodeId::I64GeS,
            "i64_ge_u" => OpcodeId::I64GeU,
            "f32_eq" => OpcodeId::F32Eq,
            "f32_ne" => OpcodeId::F32Ne,
            "f32_lt" => OpcodeId::F32Lt,
            "f32_gt" => OpcodeId::F32Gt,
            "f32_le" => OpcodeId::F32Le,
            "f32_ge" => OpcodeId::F32Ge,
            "f64_eq" => OpcodeId::F64Eq,
            "f64_ne" => OpcodeId::F64Ne,
            "f64_lt" => OpcodeId::F64Lt,
            "f64_gt" => OpcodeId::F64Gt,
            "f64_le" => OpcodeId::F64Le,
            "f64_ge" => OpcodeId::F64Ge,
            "i32_clz" => OpcodeId::I32Clz,
            "i32_ctz" => OpcodeId::I32Ctz,
            "i32_popcnt" => OpcodeId::I32Popcnt,
            "i32_add" => OpcodeId::I32Add,
            "i32_sub" => OpcodeId::I32Sub,
            "i32_mul" => OpcodeId::I32Mul,
            "i32_div_s" => OpcodeId::I32DivS,
            "i32_div_u" => OpcodeId::I32DivU,
            "i32_rem_s" => OpcodeId::I32RemS,
            "i32_rem_u" => OpcodeId::I32RemU,
            "i32_and" => OpcodeId::I32And,
            "i32_or" => OpcodeId::I32Or,
            "i32_xor" => OpcodeId::I32Xor,
            "i32_shl" => OpcodeId::I32Shl,
            "i32_shr_s" => OpcodeId::I32ShrS,
            "i32_shr_u" => OpcodeId::I32ShrU,
            "i32_rotl" => OpcodeId::I32Rotl,
            "i32_rotr" => OpcodeId::I32Rotr,
            "i64_clz" => OpcodeId::I64Clz,
            "i64_ctz" => OpcodeId::I64Ctz,
            "i64_popcnt" => OpcodeId::I64Popcnt,
            "i64_add" => OpcodeId::I64Add,
            "i64_sub" => OpcodeId::I64Sub,
            "i64_mul" => OpcodeId::I64Mul,
            "i64_div_s" => OpcodeId::I64DivS,
            "i64_div_u" => OpcodeId::I64DivU,
            "i64_rem_s" => OpcodeId::I64RemS,
            "i64_rem_u" => OpcodeId::I64RemU,
            "i64_and" => OpcodeId::I64And,
            "i64_or" => OpcodeId::I64Or,
            "i64_xor" => OpcodeId::I64Xor,
            "i64_shl" => OpcodeId::I64Shl,
            "i64_shr_s" => OpcodeId::I64ShrS,
            "i64_shr_u" => OpcodeId::I64ShrU,
            "i64_rotl" => OpcodeId::I64Rotl,
            "i64_rotr" => OpcodeId::I64Rotr,
            "f32_abs" => OpcodeId::F32Abs,
            "f32_neg" => OpcodeId::F32Neg,
            "f32_ceil" => OpcodeId::F32Ceil,
            "f32_floor" => OpcodeId::F32Floor,
            "f32_trunc" => OpcodeId::F32Trunc,
            "f32_nearest" => OpcodeId::F32Nearest,
            "f32_sqrt" => OpcodeId::F32Sqrt,
            "f32_add" => OpcodeId::F32Add,
            "f32_sub" => OpcodeId::F32Sub,
            "f32_mul" => OpcodeId::F32Mul,
            "f32_div" => OpcodeId::F32Div,
            "f32_min" => OpcodeId::F32Min,
            "f32_max" => OpcodeId::F32Max,
            "f32_copysign" => OpcodeId::F32Copysign,
            "f64_abs" => OpcodeId::F64Abs,
            "f64_neg" => OpcodeId::F64Neg,
            "f64_ceil" => OpcodeId::F64Ceil,
            "f64_floor" => OpcodeId::F64Floor,
            "f64_trunc" => OpcodeId::F64Trunc,
            "f64_nearest" => OpcodeId::F64Nearest,
            "f64_sqrt" => OpcodeId::F64Sqrt,
            "f64_add" => OpcodeId::F64Add,
            "f64_sub" => OpcodeId::F64Sub,
            "f64_mul" => OpcodeId::F64Mul,
            "f64_div" => OpcodeId::F64Div,
            "f64_min" => OpcodeId::F64Min,
            "f64_max" => OpcodeId::F64Max,
            "f64_copysign" => OpcodeId::F64Copysign,
            "i32_wrap_i64" => OpcodeId::I32WrapI64,
            "i32_trunc_s_f32" => OpcodeId::I32TruncSF32,
            "i32_trunc_u_f32" => OpcodeId::I32TruncUF32,
            "i32_trunc_s_f64" => OpcodeId::I32TruncSF64,
            "i32_trunc_u_f64" => OpcodeId::I32TruncUF64,
            "i64_extend_s_i32" => OpcodeId::I64ExtendSI32,
            "i64_extend_u_i32" => OpcodeId::I64ExtendUI32,
            "i64_trunc_s_f32" => OpcodeId::I64TruncSF32,
            "i64_trunc_u_f32" => OpcodeId::I64TruncUF32,
            "i64_trunc_s_f64" => OpcodeId::I64TruncSF64,
            "i64_trunc_u_f64" => OpcodeId::I64TruncUF64,
            "f32_convert_s_i32" => OpcodeId::F32ConvertSI32,
            "f32_convert_u_i32" => OpcodeId::F32ConvertUI32,
            "f32_convert_s_i64" => OpcodeId::F32ConvertSI64,
            "f32_convert_u_i64" => OpcodeId::F32ConvertUI64,
            "f32_demote_f64" => OpcodeId::F32DemoteF64,
            "f64_convert_s_i32" => OpcodeId::F64ConvertSI32,
            "f64_convert_u_i32" => OpcodeId::F64ConvertUI32,
            "f64_convert_s_i64" => OpcodeId::F64ConvertSI64,
            "f64_convert_u_i64" => OpcodeId::F64ConvertUI64,
            "f64_promote_f32" => OpcodeId::F64PromoteF32,
            "i32_reinterpret_f32" => OpcodeId::I32ReinterpretF32,
            "i64_reinterpret_f64" => OpcodeId::I64ReinterpretF64,
            "f32_reinterpret_i32" => OpcodeId::F32ReinterpretI32,
            "f64_reinterpret_i64" => OpcodeId::F64ReinterpretI64,
            // special WASM opcodes
            "evm_stop" => OpcodeId::STOP,
            "evm_return" => OpcodeId::RETURN,
            "evm_keccak256" => OpcodeId::SHA3,
            "evm_address" => OpcodeId::ADDRESS,
            "evm_balance" => OpcodeId::BALANCE,
            "evm_selfbalance" => OpcodeId::SELFBALANCE,
            "evm_origin" => OpcodeId::ORIGIN,
            "evm_caller" => OpcodeId::CALLER,
            "evm_callvalue" => OpcodeId::CALLVALUE,
            "evm_calldataload" => OpcodeId::CALLDATALOAD,
            "evm_calldatasize" => OpcodeId::CALLDATASIZE,
            "evm_calldatacopy" => OpcodeId::CALLDATACOPY,
            "evm_codesize" => OpcodeId::CODESIZE,
            "evm_codecopy" => OpcodeId::CODECOPY,
            "evm_gasprice" => OpcodeId::GASPRICE,
            "evm_extcodesize" => OpcodeId::EXTCODESIZE,
            "evm_extcodecopy" => OpcodeId::EXTCODECOPY,
            "evm_extcodehash" => OpcodeId::EXTCODEHASH,
            "evm_returndatasize" => OpcodeId::RETURNDATASIZE,
            "evm_returndatacopy" => OpcodeId::RETURNDATACOPY,
            "evm_blockhash" => OpcodeId::BLOCKHASH,
            "evm_coinbase" => OpcodeId::COINBASE,
            "evm_timestamp" => OpcodeId::TIMESTAMP,
            "evm_number" => OpcodeId::NUMBER,
            "evm_difficulty" => OpcodeId::DIFFICULTY,
            "evm_gaslimit" => OpcodeId::GASLIMIT,
            "evm_chainid" => OpcodeId::CHAINID,
            "evm_basefee" => OpcodeId::BASEFEE,
            "evm_sload" => OpcodeId::SLOAD,
            "evm_sstore" => OpcodeId::SSTORE,
            "evm_log0" => OpcodeId::LOG0,
            "evm_log1" => OpcodeId::LOG1,
            "evm_log2" => OpcodeId::LOG2,
            "evm_log3" => OpcodeId::LOG3,
            "evm_log4" => OpcodeId::LOG4,
            "evm_create" => OpcodeId::CREATE,
            "evm_call" => OpcodeId::CALL,
            "evm_callcode" => OpcodeId::CALLCODE,
            "evm_delegatecall" => OpcodeId::DELEGATECALL,
            "evm_create2" => OpcodeId::CREATE2,
            "evm_staticcall" => OpcodeId::STATICCALL,
            "evm_revert" => OpcodeId::REVERT,
            "evm_selfdestruct" => OpcodeId::SELFDESTRUCT,
            // default parse
            _ => {
                // Parse an invalid opcode value as reported by geth
                lazy_static! {
                    static ref RE: Regex = Regex::new("opcode 0x([[:xdigit:]]{1,2}) not defined")
                        .expect("invalid regex");
                }
                if let Some(cap) = RE.captures(s) {
                    if let Some(byte_hex) = cap.get(1).map(|m| m.as_str()) {
                        return Ok(OpcodeId::INVALID(
                            u8::from_str_radix(byte_hex, 16).expect("invalid hex byte from regex"),
                        ));
                    }
                }
                return Err(Error::OpcodeParsing(s.to_string()));
            }
        })
    }
}

impl<'de> Deserialize<'de> for OpcodeId {
    fn deserialize<D>(deserializer: D) -> Result<OpcodeId, D::Error>
        where
            D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        OpcodeId::from_str(&s).map_err(de::Error::custom)
    }
}

impl fmt::Display for OpcodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(test)]
mod opcode_ids_tests {
    use super::*;

    #[test]
    fn push_n() {
        assert!(matches!(OpcodeId::push_n(1), Ok(OpcodeId::PUSH1)));
        assert!(matches!(OpcodeId::push_n(10), Ok(OpcodeId::PUSH10)));
        assert!(matches!(
            OpcodeId::push_n(100),
            Err(Error::InvalidOpConversion)
        ));
        assert!(matches!(
            OpcodeId::push_n(0),
            Err(Error::InvalidOpConversion)
        ));
    }

    #[test]
    fn postfix() {
        assert_eq!(OpcodeId::PUSH1.postfix(), Some(1));
        assert_eq!(OpcodeId::PUSH10.postfix(), Some(10));
        assert_eq!(OpcodeId::LOG2.postfix(), Some(2));
        assert_eq!(OpcodeId::CALLCODE.postfix(), None);
    }

    #[test]
    fn data_len() {
        assert_eq!(OpcodeId::PUSH1.data_len(), 1);
        assert_eq!(OpcodeId::PUSH10.data_len(), 10);
        assert_eq!(OpcodeId::LOG2.data_len(), 0);
        assert_eq!(OpcodeId::CALLCODE.data_len(), 0);
    }
}
