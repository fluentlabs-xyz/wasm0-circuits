//! Ethereum and Evm types used to deserialize responses from web3 / geth.

#![cfg_attr(docsrs, feature(doc_cfg))]
// Temporary until we have more of the crate implemented.
#![allow(dead_code)]
// We want to have UPPERCASE idents sometimes.
#![allow(non_snake_case)]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
// #![deny(missing_docs)]
//#![deny(unsafe_code)] Allowed now until we find a
// better way to handle downcasting from Operation into it's variants.
#![allow(clippy::upper_case_acronyms)] // Too pedantic

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

pub use ethers_core::abi::ethereum_types::{BigEndianHash, U512};
use ethers_core::types;
pub use ethers_core::types::{
    Address,
    Block, Bytes, H160, H256, H64, Signature, transaction::{eip2930::AccessList, response::Transaction}, U256, U64,
};
use halo2_proofs::{
    arithmetic::{Field as Halo2Field, FieldExt},
    halo2curves::{
        bn256::{Fq, Fr},
        group::ff::PrimeField,
    },
};
use serde::{de, Deserialize, Serialize};

pub use bytecode::Bytecode;
pub use error::Error;
pub use uint_types::{DebugU256, DebugU64};

use crate::evm_types::{memory::Memory, stack::Stack, storage::Storage};
use crate::evm_types::{Gas, GasCost, OpcodeId, ProgramCounter};
use crate::GethExecStepFamily::{Evm, Unknown, WebAssembly};

#[macro_use]
pub mod macros;
#[macro_use]
pub mod error;
#[macro_use]
pub mod bytecode;
pub mod evm_types;
pub mod geth_types;
pub mod sign_types;

/// Trait used to reduce verbosity with the declaration of the [`FieldExt`]
/// trait and its repr.
pub trait Field: FieldExt + Halo2Field + PrimeField<Repr=[u8; 32]> {}

// Impl custom `Field` trait for BN256 Fr to be used and consistent with the
// rest of the workspace.
impl Field for Fr {}

// Impl custom `Field` trait for BN256 Frq to be used and consistent with the
// rest of the workspace.
impl Field for Fq {}

/// Trait used to define types that can be converted to a 256 bit scalar value.
pub trait ToScalar<F> {
    /// Convert the type to a scalar value.
    fn to_scalar(&self) -> Option<F>;
}

/// Trait used to convert a type to a [`Word`].
pub trait ToWord {
    /// Convert the type to a [`Word`].
    fn to_word(&self) -> Word;
}

/// Trait used to convert a type to a [`Word`].
pub trait ToStackWord {
    /// Convert the type to a [`Word`].
    fn to_stack_word(&self) -> StackWord;
}

/// Trait used to convert a type to a [`Word`].
pub trait ToU256 {
    /// Convert the type to a [`Word`].
    fn to_u256(&self) -> U256;
}

/// Trait used to convert a type to a [`Address`].
pub trait ToAddress {
    /// Convert the type to a [`Address`].
    fn to_address(&self) -> Address;
}

/// Trait uset do convert a scalar value to a 32 byte array in big endian.
pub trait ToBigEndian {
    /// Convert the value to a 32 byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32];
}

/// Trait used to convert a scalar value to a 32 byte array in little endian.
pub trait ToLittleEndian {
    /// Convert the value to a 32 byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32];
}

pub const N_BYTES_ADDRESS: usize = 20;
pub const N_BYTES_WORD: usize = 32;

/// Trait used to convert a scalar value to a 32 byte array in little endian.
pub trait ToWordBytes {
    /// Convert the value to a 32 byte array in little endian.
    fn to_word_bytes(&self) -> [u8; N_BYTES_WORD];
}

// We use our own declaration of another U256 in order to implement a custom
// deserializer that can parse U256 when returned by structLogs fields in geth
// debug_trace* methods, which don't contain the `0x` prefix.
#[allow(clippy::all)]
mod uint_types {
    uint::construct_uint! {
        /// 256-bit unsigned integer.
        pub struct DebugU256(4);
    }
    uint::construct_uint! {
        /// 64-bit unsigned integer.
        pub struct DebugU64(4);
    }
}

impl<'de> Deserialize<'de> for DebugU256 {
    fn deserialize<D>(deserializer: D) -> Result<DebugU256, D::Error>
        where
            D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        DebugU256::from_str(&s).map_err(de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for DebugU64 {
    fn deserialize<D>(deserializer: D) -> Result<DebugU64, D::Error>
        where
            D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        DebugU64::from_str(&s).map_err(de::Error::custom)
    }
}

impl<F: Field> ToScalar<F> for DebugU256 {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        F::from_repr(bytes).into()
    }
}

impl<F: Field> ToScalar<F> for DebugU64 {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        F::from_repr(bytes).into()
    }
}

impl ToBigEndian for DebugU256 {
    /// Encode the value as byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes);
        bytes
    }
}

impl ToBigEndian for DebugU64 {
    /// Encode the value as byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes[24..32]);
        bytes
    }
}

impl ToWord for DebugU256 {
    fn to_word(&self) -> Word {
        Word::from(self.to_be_bytes())
    }
}

impl ToWord for DebugU64 {
    fn to_word(&self) -> Word {
        Word::from(self.to_be_bytes())
    }
}

impl ToStackWord for DebugU64 {
    fn to_stack_word(&self) -> StackWord {
        let mut bytes: Vec<u8> = vec![0; 32];
        self.to_big_endian(bytes.as_mut_slice());
        let bytes = &bytes.as_slice()[24..];
        StackWord::from_big_endian(bytes)
    }
}

impl ToU256 for DebugU256 {
    fn to_u256(&self) -> U256 {
        U256::from(self.to_be_bytes())
    }
}

impl ToU256 for DebugU64 {
    fn to_u256(&self) -> U256 {
        U256::from(self.to_be_bytes())
    }
}

impl ToWord for U256 {
    fn to_word(&self) -> Word {
        U256::from(self)
    }
}

/// WASM stack word size (64 bits)
pub type StackWord = U64;

/// Ethereum Word (256 bits).
pub type Word = U256;

impl ToU256 for U256 {
    fn to_u256(&self) -> U256 {
        self.clone()
    }
}

impl ToU256 for U64 {
    fn to_u256(&self) -> U256 {
        U256::from(self.as_u64())
    }
}

impl ToBigEndian for U256 {
    /// Encode the value as byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes);
        bytes
    }
}

impl ToBigEndian for U64 {
    /// Encode the value as byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes[24..32]);
        bytes
    }
}

impl ToLittleEndian for U256 {
    /// Encode the value as byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        bytes
    }
}

impl ToWordBytes for U256 {
    /// Encode the value as byte array in little endian.
    fn to_word_bytes(&self) -> [u8; N_BYTES_WORD] {
        let mut bytes = [0u8; N_BYTES_WORD];
        self.to_little_endian(&mut bytes);
        bytes
    }
}

impl ToLittleEndian for U64 {
    /// Encode the value as byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes[0..8]);
        bytes
    }
}

impl<F: Field> ToScalar<F> for U256 {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        F::from_repr(bytes).into()
    }
}

impl<F: Field> ToScalar<F> for U64 {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes[0..8]);
        F::from_repr(bytes).into()
    }
}

impl ToAddress for U256 {
    fn to_address(&self) -> Address {
        Address::from_slice(&self.to_be_bytes()[12..])
    }
}

impl ToAddress for U64 {
    fn to_address(&self) -> Address {
        Address::from_slice(&self.to_be_bytes()[12..])
    }
}

/// Ethereum Hash (256 bits).
pub type Hash = types::H256;

impl ToWord for Hash {
    fn to_word(&self) -> Word {
        Word::from(self.as_bytes())
    }
}

impl ToU256 for Address {
    fn to_u256(&self) -> U256 {
        U256::from(self.as_bytes())
    }
}

impl ToU256 for Hash {
    fn to_u256(&self) -> U256 {
        U256::from(self.as_bytes())
    }
}

impl ToU256 for usize {
    fn to_u256(&self) -> U256 {
        U256::from(*self)
    }
}

impl ToU256 for bool {
    fn to_u256(&self) -> U256 {
        U256::from(*self as u64)
    }
}

impl ToWord for Address {
    fn to_word(&self) -> Word {
        let mut bytes = [0u8; 32];
        bytes[32 - Self::len_bytes()..].copy_from_slice(self.as_bytes());
        Word::from(bytes)
    }
}

impl ToStackWord for Address {
    fn to_stack_word(&self) -> StackWord {
        let mut bytes = [0u8; 8];
        bytes[8 - Self::len_bytes()..].copy_from_slice(self.as_bytes());
        StackWord::from(bytes)
    }
}

impl ToWord for bool {
    fn to_word(&self) -> Word {
        if *self {
            Word::one()
        } else {
            Word::zero()
        }
    }
}

impl ToWord for u64 {
    fn to_word(&self) -> Word {
        Word::from(*self)
    }
}

impl ToWord for usize {
    fn to_word(&self) -> Word {
        u64::try_from(*self)
            .expect("usize bigger than u64")
            .to_word()
    }
}

impl<F: Field> ToScalar<F> for Address {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        bytes[32 - Self::len_bytes()..].copy_from_slice(self.as_bytes());
        bytes.reverse();
        F::from_repr(bytes).into()
    }
}

impl<F: Field> ToScalar<F> for bool {
    fn to_scalar(&self) -> Option<F> {
        self.to_word().to_scalar()
    }
}

impl<F: Field> ToScalar<F> for u64 {
    fn to_scalar(&self) -> Option<F> {
        Some(F::from(*self))
    }
}

impl<F: Field> ToScalar<F> for usize {
    fn to_scalar(&self) -> Option<F> {
        u64::try_from(*self).ok().map(F::from)
    }
}

/// Struct used to define the storage proof
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
pub struct StorageProof {
    /// Storage key
    pub key: U256,
    /// Storage Value
    pub value: U256,
    /// Storage proof: rlp-encoded trie nodes from root to value.
    pub proof: Vec<Bytes>,
}

/// Struct used to define the result of `eth_getProof` call
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EIP1186ProofResponse {
    /// Account address
    pub address: Address,
    /// The balance of the account
    pub balance: U256,
    /// The hash of the code of the account
    pub code_hash: H256,
    /// The nonce of the account
    pub nonce: U256,
    /// SHA3 of the StorageRoot
    pub storage_hash: H256,
    /// Array of rlp-serialized MerkleTree-Nodes
    pub account_proof: Vec<Bytes>,
    /// Array of storage-entries as requested
    pub storage_proof: Vec<StorageProof>,
}

#[derive(Deserialize)]
#[doc(hidden)]
struct GethExecStepInternal {
    pc: ProgramCounter,
    op: String,
    #[serde(default)]
    #[serde(rename = "opcodeFamily")]
    op_family: Option<String>,
    #[serde(default)]
    params: Option<Vec<u64>>,
    gas: Gas,
    #[serde(default)]
    refund: Gas,
    #[serde(rename = "gasCost")]
    gas_cost: GasCost,
    depth: u16,
    error: Option<String>,
    // stack is in hex 0x prefixed
    stack: Vec<DebugU64>,
    // memory is in chunks of 32 bytes, in hex
    #[serde(rename = "memoryChanges")]
    #[serde(default)]
    memory_changes: HashMap<u32, String>,
    // storage is hex -> hex
    #[serde(default)]
    storage: HashMap<DebugU256, DebugU256>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Debug)]
#[doc(hidden)]
pub enum GethExecStepFamily {
    Unknown,
    WebAssembly,
    Evm,
}

impl GethExecStepFamily {
    fn from_string(value: &String) -> Self {
        if value.eq(&String::from("WASM")) {
            WebAssembly
        } else if value.eq(&String::from("EVM")) {
            Evm
        } else {
            Unknown
        }
    }
}

/// The execution step type returned by geth RPC debug_trace* methods.
/// Corresponds to `StructLogRes` in `go-ethereum/internal/ethapi/api.go`.
#[derive(Serialize, Clone, Eq, PartialEq)]
#[doc(hidden)]
pub struct GethExecStep
{
    pub pc: ProgramCounter,
    pub op_family: Option<GethExecStepFamily>,
    pub params: Vec<u64>,
    pub op: OpcodeId,
    pub gas: Gas,
    pub gas_cost: GasCost,
    pub refund: Gas,
    pub depth: u16,
    pub error: Option<String>,
    // stack is in hex 0x prefixed
    pub stack: Stack<StackWord>,
    // memory is in chunks of 32 bytes, in hex
    pub memory: Vec<Memory>,
    pub global_memory: Memory,
    // storage is hex -> hex
    pub storage: Storage,
}

// Wrapper over u8 that provides formats the byte in hex for [`fmt::Debug`].
pub(crate) struct DebugByte(pub(crate) u8);

impl fmt::Debug for DebugByte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{:02x}", self.0))
    }
}

// Wrapper over Word reference that provides formats the word in hex for
// [`fmt::Debug`].
pub(crate) struct DebugStackWord<'a>(pub(crate) &'a StackWord);

impl<'a> fmt::Debug for DebugStackWord<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("0x{:x}", self.0))
    }
}

// Wrapper over Word reference that provides formats the word in hex for
// [`fmt::Debug`].
pub(crate) struct DebugWord<'a>(pub(crate) &'a Word);

impl<'a> fmt::Debug for DebugWord<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("0x{:x}", self.0))
    }
}

impl fmt::Debug for GethExecStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Step")
            .field("pc", &format_args!("0x{:04x}", self.pc.0))
            .field("op", &self.op)
            .field("gas", &format_args!("{}", self.gas.0))
            .field("gas_cost", &format_args!("{}", self.gas_cost.0))
            .field("depth", &self.depth)
            .field("error", &self.error)
            // .field("stack", &self.stack)
            // .field("memory", &self.memory)
            .field("storage", &self.storage)
            .finish()
    }
}

impl<'de> Deserialize<'de> for GethExecStep {
    fn deserialize<D>(deserializer: D) -> Result<GethExecStep, D::Error>
        where
            D: serde::Deserializer<'de>,
    {
        let s = GethExecStepInternal::deserialize(deserializer)?;
        let memory: Vec<Memory> = s.memory_changes.iter().map(|(offset, mem)| {
            let mem = if mem.starts_with("0x") {
                mem[2..].to_string()
            } else {
                mem.clone()
            };
            Memory::from_bytes_with_offset(hex::decode(mem).unwrap(), *offset)
        }).collect();
        Ok(Self {
            pc: s.pc,
            op_family: s.op_family.map(|f| GethExecStepFamily::from_string(&f)),
            params: s.params.unwrap_or(Vec::new()),
            op: OpcodeId::from_str(s.op.as_str()).unwrap(),
            gas: s.gas,
            refund: s.refund,
            gas_cost: s.gas_cost,
            depth: s.depth,
            error: s.error,
            stack: Stack(s.stack.iter().map(|dw| dw.to_stack_word()).collect::<Vec<_>>()),
            memory,
            global_memory: Memory::new(),
            storage: Storage(
                s.storage
                    .iter()
                    .map(|(k, v)| (k.to_word(), v.to_word()))
                    .collect(),
            ),
        })
    }
}

/// Helper type built to deal with the weird `result` field added between
/// `GethExecutionTrace`s in `debug_traceBlockByHash` and
/// `debug_traceBlockByNumber` Geth JSON-RPC calls.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[doc(hidden)]
pub struct ResultGethExecTraces(pub Vec<ResultGethExecTrace>);

/// Helper type built to deal with the weird `result` field added between
/// `GethExecutionTrace`s in `debug_traceBlockByHash` and
/// `debug_traceBlockByNumber` Geth JSON-RPC calls.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[doc(hidden)]
pub struct ResultGethExecTrace {
    pub result: GethExecTrace,
}

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct GethExecTraceGlobal {
    pub pc: ProgramCounter,
    pub index: u32,
    pub op: String,
    pub value: u64,
}

/// The execution trace type returned by geth RPC debug_trace* methods.
/// Corresponds to `ExecutionResult` in `go-ethereum/internal/ethapi/api.go`.
/// The deserialization truncates the memory of each step in `struct_logs` to
/// the memory size before the expansion, so that it corresponds to the memory
/// before the step is executed.
#[derive(Serialize, Clone, Debug, Eq, PartialEq)]
pub struct GethExecTrace {
    /// Used gas
    pub gas: Gas,
    /// Internal error message
    pub internal_error: String,
    /// True when the transaction has failed.
    pub failed: bool,
    /// Global memory
    pub global_memory: Memory,
    /// Return value of execution which is a hex encoded byte array
    #[serde(rename = "returnValue")]
    pub return_value: String,
    /// Vector of geth execution steps of the trace.
    #[serde(rename = "structLogs")]
    pub struct_logs: Vec<GethExecStep>,
    /// Globals.
    #[serde(rename = "globals")]
    pub globals: Vec<GethExecTraceGlobal>,
}

#[derive(Deserialize)]
#[doc(hidden)]
pub struct GethExecTraceInternal {
    /// Used gas
    pub gas: Gas,
    /// Internal error message
    #[serde(rename = "internalError")]
    #[serde(default)]
    pub internal_error: String,
    /// True when the transaction has failed.
    pub failed: bool,
    /// Global memory
    #[serde(rename = "globalMemory")]
    #[serde(default)]
    pub global_memory: HashMap<u32, String>,
    /// Return value of execution which is a hex encoded byte array
    #[serde(rename = "returnValue")]
    pub return_value: String,
    /// Vector of geth execution steps of the trace.
    #[serde(rename = "structLogs")]
    pub struct_logs: Vec<GethExecStep>,
    /// Globals.
    #[serde(rename = "globals")]
    pub globals: Vec<GethExecTraceGlobal>,
}

impl<'de> Deserialize<'de> for GethExecTrace {
    fn deserialize<D>(deserializer: D) -> Result<GethExecTrace, D::Error>
        where
            D: serde::Deserializer<'de>,
    {
        let mut s = GethExecTraceInternal::deserialize(deserializer)?;
        let mut global_memory = Memory::from_bytes_with_offset(vec![], 0);
        s.global_memory.iter().for_each(|(offset, mem)| {
            let mem = if mem.starts_with("0x") {
                mem[2..].to_string()
            } else {
                mem.clone()
            };
            let mem = Memory(hex::decode(mem).unwrap(), *offset);
            global_memory.extends_with(&mem);
        });
        let init_memory = global_memory.clone();
        // TODO: "create dump of each global memory state and copy to the state (temp solution)"
        for mut step in s.struct_logs.iter_mut() {
            step.memory.iter().for_each(|v| {
                global_memory.extends_with(v);
            });
            step.global_memory = global_memory.clone();
        }
        Ok(Self {
            gas: s.gas,
            internal_error: s.internal_error,
            failed: s.failed,
            global_memory: init_memory,
            return_value: s.return_value,
            struct_logs: s.struct_logs,
            globals: s.globals,
        })
    }
}

#[macro_export]
/// Create an [`Address`] from a hex string.  Panics on invalid input.
macro_rules! address {
    ($addr_hex:expr) => {{
        use std::str::FromStr;
        $crate::Address::from_str(&$addr_hex).expect("invalid hex Address")
    }};
}

#[macro_export]
/// Create a [`Word`] from a hex string.  Panics on invalid input.
macro_rules! word {
    ($word_hex:expr) => {
        $crate::Word::from_str_radix(&$word_hex, 16).expect("invalid hex Word")
    };
}

#[macro_export]
/// Create a [`Word`] from a hex string.  Panics on invalid input.
macro_rules! stack_word {
    ($word_hex:expr) => {
        $crate::StackWord::from_str_radix(&$word_hex, 16).expect("invalid hex StackWord")
    };
}

#[macro_export]
/// Create a [`Word`] to [`Word`] HashMap from pairs of hex strings.  Panics on
/// invalid input.
macro_rules! word_map {
    () => {
        std::collections::HashMap::new()
    };
    ($($key_hex:expr => $value_hex:expr),*) => {
        {
            std::collections::HashMap::from_iter([(
                    $(word!($key_hex), word!($value_hex)),*
            )])
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::evm_types::{memory::Memory, stack::Stack};
    use crate::evm_types::opcode_ids::OpcodeId;

    use super::*;

    #[test]
    fn deserialize_geth_exec_trace2() {
        let trace_json = r#"
  {
    "gas": 26809,
    "failed": false,
    "returnValue": "",
    "structLogs": [
      {
        "pc": 0,
        "op": "PUSH1",
        "gas": 22705,
        "gasCost": 3,
        "refund": 0,
        "depth": 1,
        "stack": []
      },
      {
        "pc": 163,
        "op": "SLOAD",
        "gas": 5217,
        "gasCost": 2100,
        "refund": 0,
        "depth": 1,
        "stack": [
          "0x1003e2d2",
          "0x2a",
          "0x0"
        ],
        "storage": {
          "0000000000000000000000000000000000000000000000000000000000000000": "000000000000000000000000000000000000000000000000000000000000006f"
        },
        "memory": [
          "0000000000000000000000000000000000000000000000000000000000000000",
          "0000000000000000000000000000000000000000000000000000000000000000",
          "0000000000000000000000000000000000000000000000000000000000000080"
        ]
      },
      {
        "pc": 189,
        "op": "KECCAK256",
        "gas": 178805,
        "gasCost": 42,
        "refund": 0,
        "depth": 1,
        "stack": [
            "0x3635c9adc5dea00000",
            "0x40",
            "0x0"
        ],
        "memory": [
            "000000000000000000000000b8f67472dcc25589672a61905f7fd63f09e5d470",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000000000000000000000000000000000a0",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000000000000000003635c9adc5dea00000",
            "00000000000000000000000000000000000000000000003635c9adc5dea00000"
        ]
      }
    ]
  }
        "#;
        let trace: GethExecTrace =
            serde_json::from_str(trace_json).expect("json-deserialize GethExecTrace");
        assert_eq!(
            trace,
            GethExecTrace {
                gas: Gas(26809),
                internal_error: "".to_owned(),
                failed: false,
                return_value: "".to_owned(),
                global_memory: Memory::new(),
                struct_logs: vec![
                    GethExecStep {
                        pc: ProgramCounter(0),
                        op_family: None,
                        params: vec![],
                        op: OpcodeId::PUSH1,
                        gas: Gas(22705),
                        refund: Gas(0),
                        gas_cost: GasCost(3),
                        depth: 1,
                        error: None,
                        stack: Stack::<StackWord>::new(),
                        storage: Storage(word_map!()),
                        memory: vec![],
                        global_memory: Memory::new(),
                    },
                    GethExecStep {
                        pc: ProgramCounter(163),
                        op_family: None,
                        params: vec![],
                        op: OpcodeId::SLOAD,
                        gas: Gas(5217),
                        refund: Gas(0),
                        gas_cost: GasCost(2100),
                        depth: 1,
                        error: None,
                        stack: Stack(vec![stack_word!("0x1003e2d2"), stack_word!("0x2a"), stack_word!("0x0")]),
                        storage: Storage(word_map!("0x0" => "0x6f")),
                        memory: vec![Memory::from(vec![word!("0x0"), word!("0x0"), word!("0x080")])],
                        global_memory: Memory::new(),
                    },
                    GethExecStep {
                        pc: ProgramCounter(189),
                        op_family: None,
                        params: vec![],
                        op: OpcodeId::SHA3,
                        gas: Gas(178805),
                        refund: Gas(0),
                        gas_cost: GasCost(42),
                        depth: 1,
                        error: None,
                        stack: Stack(vec![
                            stack_word!("0x3635c9adc5dea00000"),
                            stack_word!("0x40"),
                            stack_word!("0x0"),
                        ]),
                        storage: Storage(word_map!()),
                        memory: vec![Memory::from(vec![
                            word!(
                                "000000000000000000000000b8f67472dcc25589672a61905f7fd63f09e5d470"
                            ),
                            word!(
                                "0000000000000000000000000000000000000000000000000000000000000000"
                            ),
                            word!(
                                "00000000000000000000000000000000000000000000000000000000000000a0"
                            ),
                            word!(
                                "0000000000000000000000000000000000000000000000000000000000000000"
                            ),
                            word!(
                                "00000000000000000000000000000000000000000000003635c9adc5dea00000"
                            ),
                            word!(
                                "00000000000000000000000000000000000000000000003635c9adc5dea00000"
                            ),
                        ])],
                        global_memory: Memory::new(),
                    },
                ],
            }
        );
    }

    #[test]
    fn deserialize_geth_exec_wasm_trace() {
        let trace_json = r#"
{
    "gas": 92024,
    "failed": false,
    "returnValue": "0061736d01000000010b0260027f7f0060017f017f02130103656e760b5f65766d5f72657475726e0000030201010405017001010105030100110619037f01418080c0000b7f00418c80c0000b7f00419080c0000b072c04066d656d6f72790200046d61696e00010a5f5f646174615f656e6403010b5f5f686561705f6261736503020a0f010d00418080c000410c100041000b0b150100418080c0000b0c48656c6c6f2c20576f726c64",
    "structLogs":
    [
        {
            "pc": 0,
            "opcodeFamily": "WASM",
            "params":
            [
                1048576
            ],
            "op": "i32_const",
            "gas": 9942176,
            "gasCost": 1,
            "depth": 1,
            "stack":
            [
                "0x0"
            ]
        },
        {
            "pc": 1,
            "opcodeFamily": "WASM",
            "params":
            [
                171
            ],
            "op": "i32_const",
            "gas": 9942175,
            "gasCost": 1,
            "depth": 1,
            "stack":
            [
                "0x0",
                "0x100000"
            ]
        },
        {
            "pc": 18446744073709551615,
            "opcodeFamily": "EVM",
            "params":
            [],
            "op": "evm_return",
            "gas": 9942176,
            "gasCost": 0,
            "depth": 1,
            "stack":
            [
                "0xab",
                "0x100000"
            ]
        }
    ]
}
        "#;
        let trace: GethExecTrace =
            serde_json::from_str(trace_json).expect("json-deserialize GethExecTrace");
        assert_eq!(trace.struct_logs[0].op_family, Some(WebAssembly));
        let params = &trace.struct_logs[0].params;
        assert_eq!(params.clone()[0], 1048576);
        assert_eq!(trace.struct_logs[1].op_family, Some(WebAssembly));
        let params = &trace.struct_logs[1].params;
        assert_eq!(params.clone()[0], 171);
        assert_eq!(trace.struct_logs[2].op_family, Some(Evm));
    }
}

#[cfg(test)]
mod eth_types_test {
    use std::str::FromStr;

    use crate::Error;
    use crate::Word;

    use super::*;

    #[test]
    fn address() {
        // Test from_str
        assert_eq!(
            Address::from_str("0x9a0C63EBb78B35D7c209aFbD299B056098b5439b").unwrap(),
            Address::from([
                154, 12, 99, 235, 183, 139, 53, 215, 194, 9, 175, 189, 41, 155, 5, 96, 152, 181,
                67, 155
            ])
        );
        assert_eq!(
            Address::from_str("9a0C63EBb78B35D7c209aFbD299B056098b5439b").unwrap(),
            Address::from([
                154, 12, 99, 235, 183, 139, 53, 215, 194, 9, 175, 189, 41, 155, 5, 96, 152, 181,
                67, 155
            ])
        );

        // Test from_str Errors
        assert_eq!(
            &format!(
                "{:?}",
                Address::from_str("0x9a0C63EBb78B35D7c209aFbD299B056098b543")
            ),
            "Err(Invalid input length)",
        );
        assert_eq!(
            &format!(
                "{:?}",
                Address::from_str("0x9a0C63EBb78B35D7c209aFbD299B056098b543XY")
            ),
            "Err(Invalid character 'X' at position 38)",
        );

        // Test to_word
        assert_eq!(
            Address::from_str("0x0000000000000000000000000000000000000001")
                .unwrap()
                .to_word(),
            Word::from(1u32),
        )
    }

    #[test]
    fn word_bytes_serialization_trip() -> Result<(), Error> {
        let first_usize = 64536usize;
        // Parsing on both ways works.
        assert_eq!(
            Word::from_little_endian(&first_usize.to_le_bytes()),
            Word::from_big_endian(&first_usize.to_be_bytes())
        );
        let addr = Word::from_little_endian(&first_usize.to_le_bytes());
        assert_eq!(addr, Word::from(first_usize));

        // Little endian export
        let mut le_obtained_usize = [0u8; 32];
        addr.to_little_endian(&mut le_obtained_usize);
        let mut le_array = [0u8; 8];
        le_array.copy_from_slice(&le_obtained_usize[0..8]);

        // Big endian export
        let mut be_array = [0u8; 8];
        let be_obtained_usize = addr.to_be_bytes();
        be_array.copy_from_slice(&be_obtained_usize[24..32]);

        assert_eq!(first_usize, usize::from_le_bytes(le_array));
        assert_eq!(first_usize, usize::from_be_bytes(be_array));

        Ok(())
    }

    #[test]
    fn word_from_str() -> Result<(), Error> {
        let word_str = "000000000000000000000000000000000000000000000000000c849c24f39248";

        let word_from_u128 = Word::from(3523505890234952u128);
        let word_from_str = Word::from_str(word_str).unwrap();

        assert_eq!(word_from_u128, word_from_str);
        Ok(())
    }

    #[test]
    fn creation_tx_into_tx_req() -> Result<(), Error> {
        let tx = &geth_types::Transaction {
            to: None,
            ..Default::default()
        };

        let req: ethers_core::types::TransactionRequest = tx.into();
        assert_eq!(req.to, None);
        Ok(())
    }
}
