//! EVM byte code generator

use std::{collections::HashMap, str::FromStr};
use std::cmp::Ordering;
use std::collections::BTreeMap;

use wasm_encoder::{ConstExpr, DataSection, Encode, Instruction};

use crate::{Address, Bytes, evm_types::OpcodeId, ToLittleEndian, U256, Word};

/// Error type for Bytecode related failures
#[derive(Debug)]
pub enum Error {
    /// Serde de/serialization error.
    InvalidAsmError(String),
}

/// Helper struct that represents a single data section in wasm binary
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd)]
pub enum SectionDescriptor {
    Data {
        index: u32,
        offset: u32,
        data: Vec<u8>,
    }
}

impl SectionDescriptor {
    fn order(&self) -> usize {
        match self {
            SectionDescriptor::Data { .. } => 1usize,
        }
    }
}

impl Ord for SectionDescriptor {
    fn cmp(&self, other: &Self) -> Ordering {
        self.order().cmp(&other.order())
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvmCall {
    fn_name: &'static str,
    args_num: usize,
}

/// Helper struct that represents a single element in a bytecode.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BytecodeElement {
    /// The byte value of the element.
    pub value: u8,
    /// Whether the element is an opcode or push data byte.
    pub is_code: bool,
}

/// EVM Bytecode
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Bytecode {
    /// Vector for bytecode elements.
    bytecode_items: Vec<BytecodeElement>,
    global_data: (u32, Vec<u8>),
    section_descriptors: Vec<SectionDescriptor>,
    evm_table: HashMap<EvmCall, usize>,
    num_opcodes: usize,
    markers: HashMap<String, usize>,
}

impl From<Bytecode> for Bytes {
    fn from(code: Bytecode) -> Self {
        code.bytecode_items
            .iter()
            .map(|e| e.value)
            .collect::<Vec<u8>>()
            .into()
    }
}

pub trait WasmBinaryBytecode {
    fn wasm_binary(&self) -> Vec<u8>;
}

pub struct UncheckedWasmBinary(Vec<u8>);

impl UncheckedWasmBinary {
    pub fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl WasmBinaryBytecode for UncheckedWasmBinary {
    fn wasm_binary(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl WasmBinaryBytecode for Bytecode {
    fn wasm_binary(&self) -> Vec<u8> {
        use wasm_encoder::{
            CodeSection, EntityType, ExportKind, ExportSection, Function, FunctionSection,
            ImportSection, MemorySection, MemoryType, Module, TypeSection, ValType,
        };
        let mut module = Module::new();
        // Encode the type & imports section.
        let mut types = TypeSection::new();
        let max_evm_args = self.evm_table.keys().map(|v| { v.args_num }).max().unwrap_or(0) + 1;
        (0..max_evm_args).for_each(|args_num| {
            types.function(vec![ValType::I32; args_num], vec![]);
        });
        let mut imports = ImportSection::new();
        let ordered_evm_table = self.evm_table.clone()
            .into_iter()
            .map(|(k, v)| (v, k))
            .collect::<BTreeMap<_, _>>();
        for (_, evm_call) in ordered_evm_table {
            imports.import("env", evm_call.fn_name, EntityType::Function(evm_call.args_num as u32));
        }
        // Encode the function section
        let mut functions = FunctionSection::new();
        functions.function(0);
        // Create memory section
        let mut memories = MemorySection::new();
        memories.memory(MemoryType {
            minimum: 1,
            maximum: None,
            memory64: false,
            shared: false,
        });
        // Encode the export section.
        let mut exports = ExportSection::new();
        exports.export("main", ExportKind::Func, self.evm_table.len() as u32);
        exports.export("memory", ExportKind::Memory, 0);
        // Encode the code section.
        let mut codes = CodeSection::new();
        let locals = vec![];
        let mut f = Function::new(locals);
        f.raw(self.code());
        f.instruction(&Instruction::End);
        codes.function(&f);
        // build sections order (Custom,Type,Import,Function,Table,Memory,Global,Event,Export,Start,Elem,DataCount,Code,Data)
        module.section(&types);
        module.section(&imports);
        module.section(&functions);
        module.section(&memories);
        module.section(&exports);
        module.section(&codes);
        // if we have global data section then put it into final binary
        let mut sections = self.section_descriptors.clone();
        sections.sort();
        for section in &sections {
            match section {
                SectionDescriptor::Data { index, offset, data } => {
                    let mut data_section = DataSection::new();
                    data_section.active(*index, &ConstExpr::i32_const(*offset as i32), data.clone());
                    module.section(&data_section);
                }
                // _ => unreachable!("unknown section: {:?}", section)
            }
        }
        if self.global_data.1.len() > 0 {
            let mut data_section = DataSection::new();
            data_section.active(0, &ConstExpr::i32_const(self.global_data.0 as i32), self.global_data.1.clone());
            module.section(&data_section);
        }
        let wasm_bytes = module.finish();
        return wasm_bytes;
    }
}

impl Bytecode {
    /// Build not checked bytecode
    pub fn from_raw_unchecked(input: Vec<u8>) -> Self {
        Self {
            bytecode_items: input
                .iter()
                .map(|b| BytecodeElement {
                    value: *b,
                    is_code: true,
                })
                .collect(),
            global_data: (0, Vec::new()),
            section_descriptors: Vec::new(),
            evm_table: HashMap::new(),
            markers: HashMap::new(),
            num_opcodes: 0,
        }
    }

    pub fn alloc_default_global_data(&mut self, size: u32) -> u32 {
        self.fill_default_global_data(vec![0].repeat(size as usize))
    }

    pub fn fill_default_global_data(&mut self, data: Vec<u8>) -> u32 {
        let current_offset = self.global_data.1.len();
        self.global_data.1.extend(&data);
        current_offset as u32
    }

    pub fn with_global_data(&mut self, memory_index: u32, memory_offset: u32, data: Vec<u8>) -> &mut Self {
        self.section_descriptors.push(SectionDescriptor::Data {
            index: memory_index,
            offset: memory_offset,
            data,
        });
        self
    }

    /// Get the raw code
    pub fn raw_code(&self) -> Vec<BytecodeElement> {
        self.bytecode_items.clone()
    }

    /// Get the code
    pub fn code(&self) -> Vec<u8> {
        self.bytecode_items.iter().map(|b| b.value).collect()
    }

    /// Get the bytecode element at an index.
    pub fn get(&self, index: usize) -> Option<BytecodeElement> {
        self.bytecode_items.get(index).cloned()
    }

    /// Get the generated code
    pub fn to_vec(&self) -> Vec<u8> {
        self.wasm_binary()
    }

    /// Append
    pub fn append(&mut self, other: &Bytecode) {
        self.bytecode_items.extend_from_slice(&other.bytecode_items);
        for (key, val) in other.markers.iter() {
            self.insert_marker(key, self.num_opcodes + val);
        }
        if self.section_descriptors.len() > 0 && other.section_descriptors.len() > 0 {
            panic!("section collision might happen, not implemented");
        }
        for section in other.section_descriptors.iter() {
            self.section_descriptors.push(section.clone());
        }
        if self.evm_table.len() > 0 && other.section_descriptors.len() > 0 {
            panic!("EVM table collision might happen, not implemented");
        }
        for (evm_call, call_index) in other.evm_table.iter() {
            self.evm_table.insert(*evm_call, *call_index);
        }
        self.num_opcodes += other.num_opcodes;
    }

    pub fn evm_call(&mut self, op: OpcodeId) -> &mut Self {
        let (fn_name, args_num) = match op {
            OpcodeId::STOP => ("_evm_stop", 0),
            OpcodeId::RETURN => ("_evm_return", 2),
            OpcodeId::SHA3 => ("_evm_keccak", 2),
            OpcodeId::ADDRESS => ("_evm_address", 1),
            OpcodeId::BALANCE => ("_evm_balance", 2),
            OpcodeId::ORIGIN => ("_evm_origin", 1),
            OpcodeId::CALLER => ("_evm_caller", 1),
            OpcodeId::CALLVALUE => ("_evm_callvalue", 1),
            OpcodeId::CALLDATALOAD => ("_evm_calldataload", 2),
            OpcodeId::CALLDATASIZE => ("_evm_calldatasize", 1),
            OpcodeId::CALLDATACOPY => ("_evm_calldatacopy", 3),
            OpcodeId::CODESIZE => ("_evm_codesize", 1),
            OpcodeId::CODECOPY => ("_evm_codecopy", 3),
            OpcodeId::GASPRICE => ("_evm_gasprice", 1),
            OpcodeId::EXTCODESIZE => ("_evm_extcodesize", 2),
            OpcodeId::EXTCODECOPY => ("_evm_extcodecopy", 4),
            OpcodeId::EXTCODEHASH => ("_evm_extcodehash", 2),
            OpcodeId::RETURNDATASIZE => ("_evm_returndatasize", 1),
            OpcodeId::RETURNDATACOPY => ("_evm_returndatacopy", 3),
            OpcodeId::BLOCKHASH => ("_evm_blockhash", 1),
            OpcodeId::COINBASE => ("_evm_coinbase", 1),
            OpcodeId::TIMESTAMP => ("_evm_timestamp", 1),
            OpcodeId::NUMBER => ("_evm_number", 1),
            OpcodeId::DIFFICULTY => ("_evm_difficulty", 1),
            OpcodeId::GASLIMIT => ("_evm_gaslimit", 1),
            OpcodeId::CHAINID => ("_evm_chainid", 1),
            OpcodeId::BASEFEE => ("_evm_basefee", 1),
            OpcodeId::SLOAD => ("_evm_sload", 2),
            OpcodeId::SSTORE => ("_evm_sstore", 2),
            OpcodeId::LOG0 => ("_evm_log0", 2),
            OpcodeId::LOG1 => ("_evm_log1", 3),
            OpcodeId::LOG2 => ("_evm_log2", 4),
            OpcodeId::LOG3 => ("_evm_log3", 5),
            OpcodeId::LOG4 => ("_evm_log4", 6),
            OpcodeId::CREATE => ("_evm_create", 3),
            OpcodeId::CALL => ("_evm_call", 8),
            OpcodeId::CALLCODE => ("_evm_callcode", 8),
            OpcodeId::DELEGATECALL => ("_evm_delegatecall", 7),
            OpcodeId::CREATE2 => ("_evm_create2", 5),
            OpcodeId::STATICCALL => ("_evm_staticcall", 7),
            OpcodeId::REVERT => ("_evm_revert", 2),
            OpcodeId::SELFBALANCE => ("_evm_selfbalance", 1),
            _ => unreachable!("not supported EVM opcode: {op}")
        };
        let evm_call = EvmCall {
            fn_name,
            args_num,
        };

        let call_index = if let Some(call_index) = self.evm_table.get(&evm_call) {
            *call_index
        } else {
            let call_index = self.evm_table.len();
            self.evm_table.insert(evm_call, call_index);
            call_index
        };
        self.write_call(call_index as u32)
    }

    pub fn write_op(&mut self, op: OpcodeId) -> &mut Self {
        if op.is_evm_call() {
            return self.evm_call(op);
        }
        let op = match op {
            // WASM opcode mapping
            OpcodeId::I32Add => Instruction::I32Add,
            OpcodeId::I64Add => Instruction::I64Add,
            OpcodeId::I32Sub => Instruction::I32Sub,
            OpcodeId::I64Sub => Instruction::I64Sub,
            OpcodeId::I32Mul => Instruction::I32Mul,
            OpcodeId::I64Mul => Instruction::I64Mul,
            OpcodeId::I32DivS => Instruction::I32DivS,
            OpcodeId::I64DivS => Instruction::I64DivS,
            OpcodeId::I32DivU => Instruction::I32DivU,
            OpcodeId::I64DivU => Instruction::I64DivU,
            OpcodeId::I32RemU => Instruction::I32RemU,
            OpcodeId::I64RemU => Instruction::I64RemU,
            OpcodeId::I32Ctz => Instruction::I32Ctz,
            OpcodeId::I64Ctz => Instruction::I64Ctz,
            OpcodeId::I32Clz => Instruction::I32Clz,
            OpcodeId::I64Clz => Instruction::I64Clz,
            OpcodeId::End => Instruction::End,
            OpcodeId::Unreachable => Instruction::Unreachable,
            OpcodeId::Drop => Instruction::Drop,
            _ => {
                unreachable!("not supported opcode: {:?} ({})", op, op.as_u8())
            }
        };
        let mut buf: Vec<u8> = vec![];
        op.encode(&mut buf);
        for (i, b) in buf.iter().enumerate() {
            if i == 0 {
                self.write_op_internal(*b);
            } else {
                self.write(*b, false);
            }
        }
        self
    }

    pub fn write_call(&mut self, index: u32) -> &mut Self {
        let mut buf: Vec<u8> = vec![];
        Instruction::Call(index).encode(&mut buf);
        for (i, b) in buf.iter().enumerate() {
            if i == 0 {
                self.write_op_internal(*b);
            } else {
                self.write(*b, false);
            }
        }
        self
    }

    pub fn write_const(&mut self, op: OpcodeId, val: u64) -> &mut Self {
        let op = match op {
            OpcodeId::I32Const => Instruction::I32Const(val as i32),
            OpcodeId::I64Const => Instruction::I64Const(val as i64),
            _ => {
                unreachable!("not supported opcode: {:?} ({})", op, op.as_u8())
            }
        };
        let mut buf: Vec<u8> = vec![];
        op.encode(&mut buf);
        for (i, b) in buf.iter().enumerate() {
            if i == 0 {
                self.write_op_internal(*b);
            } else {
                self.write(*b, false);
            }
        }
        self
    }

    fn write_op_internal(&mut self, op: u8) -> &mut Self {
        self.num_opcodes += 1;
        self.write(op, true)
    }

    /// Write byte
    pub fn write(&mut self, value: u8, is_code: bool) -> &mut Self {
        self.bytecode_items.push(BytecodeElement { value, is_code });
        self
    }

    /// Push
    pub fn push(&mut self, n: u8, value: Word) -> &mut Self {
        debug_assert!((1..=32).contains(&n), "invalid push");

        // Write the op code
        self.write_op((OpcodeId::push_n(n)).expect("valid push size"));

        let mut bytes = [0u8; 32];
        value.to_little_endian(&mut bytes);
        // Write the bytes MSB to LSB
        for i in 0..n {
            self.write(bytes[(n - 1 - i) as usize], false);
        }
        // Check if the full value could be pushed
        for byte in bytes.iter().skip(n as usize) {
            debug_assert!(*byte == 0u8, "value too big for PUSH{}: {}", n, value);
        }
        self
    }

    /// Add marker
    pub fn add_marker(&mut self, marker: String) -> &mut Self {
        self.insert_marker(&marker, self.num_opcodes);
        self
    }

    /// Insert marker
    pub fn insert_marker(&mut self, marker: &str, pos: usize) {
        debug_assert!(
            !self.markers.contains_key(marker),
            "marker already used: {}",
            marker
        );
        self.markers.insert(marker.to_string(), pos);
    }

    /// Get the position of a marker
    pub fn get_pos(&self, marker: &str) -> usize {
        *self
            .markers
            .get(&marker.to_string())
            .unwrap_or_else(|| panic!("marker '{}' not found", marker))
    }

    /// Setup state
    pub fn setup_state(&mut self) -> &mut Self {
        // self.append(&crate::bytecode! {
        //     PUSH1(0x80u64)
        //     PUSH1(0x40u64)
        //     MSTORE
        // });
        self
    }

    /// Call a contract
    #[allow(clippy::too_many_arguments)]
    pub fn emit_evm_call(
        &mut self,
        opcode: OpcodeId,
        gas: u64,
        address: Address,
        value: U256,
        input_offset: u64,
        input_length: u64,
        return_offset: u64,
        return_length: u64,
    ) -> &mut Self {
        if opcode == OpcodeId::CALL || opcode == OpcodeId::CALLCODE {
            let address_offset = self.fill_default_global_data(address.to_fixed_bytes().to_vec());
            let value_offset = self.fill_default_global_data(value.to_le_bytes().to_vec());
            let status_offset = self.alloc_default_global_data(1);
            crate::bytecode_internal!(self,
                I32Const[gas]
                I32Const[address_offset as u64]
                I32Const[value_offset as u64]
                I32Const[input_offset]
                I32Const[input_length]
                I32Const[return_offset]
                I32Const[return_length]
                I32Const[status_offset]
            );
        } else {
            let address_offset = self.fill_default_global_data(address.to_fixed_bytes().to_vec());
            let status_offset = self.alloc_default_global_data(1);
            crate::bytecode_internal!(self,
                I32Const[gas]
                I32Const[address_offset as u64]
                I32Const[input_offset]
                I32Const[input_length]
                I32Const[return_offset]
                I32Const[return_length]
                I32Const[status_offset]
            );
        }
        self.write_op(opcode)
    }

    /// Generate the diassembly
    pub fn disasm(&self) -> String {
        let mut asm = String::new();
        for op in self.iter() {
            asm.push_str(&op.to_string());
            asm.push('\n');
        }
        asm
    }

    /// Append asm
    pub fn append_asm(&mut self, op: &str) -> Result<(), Error> {
        match OpcodeWithData::from_str(op)? {
            OpcodeWithData::Opcode(op) => self.write_op(op),
            OpcodeWithData::Push(n, value) => self.push(n, value),
        };
        Ok(())
    }

    /// Append an opcode
    pub fn append_op(&mut self, op: OpcodeWithData) -> &mut Self {
        match op {
            OpcodeWithData::Opcode(opcode) => {
                self.write_op(opcode);
            }
            OpcodeWithData::Push(n, word) => {
                self.push(n, word);
            }
        }
        self
    }

    /// create iterator
    pub fn iter(&self) -> BytecodeIterator<'_> {
        BytecodeIterator(self.bytecode_items.iter())
    }
}

/// An ASM entry
#[derive(Clone, PartialEq, Eq)]
pub enum OpcodeWithData {
    /// A non-push opcode
    Opcode(OpcodeId),
    /// A push opcode
    Push(u8, Word),
}

impl OpcodeWithData {
    /// get the opcode
    pub fn opcode(&self) -> OpcodeId {
        match self {
            OpcodeWithData::Opcode(op) => *op,
            OpcodeWithData::Push(n, _) => OpcodeId::push_n(*n).expect("valid push size"),
        }
    }
}

impl FromStr for OpcodeWithData {
    type Err = Error;

    #[allow(clippy::manual_range_contains)]
    fn from_str(op: &str) -> Result<Self, Self::Err> {
        let err = || Error::InvalidAsmError(op.to_string());
        if let Some(push) = op.strip_prefix("PUSH") {
            let n_value: Vec<_> = push.splitn(3, ['(', ')']).collect();
            let n = n_value[0].parse::<u8>().map_err(|_| err())?;
            if n < 1 || n > 32 {
                return Err(err());
            }
            let value = if n_value[1].starts_with("0x") {
                Word::from_str_radix(&n_value[1][2..], 16)
            } else {
                Word::from_str_radix(n_value[1], 10)
            }
                .map_err(|_| err())?;
            Ok(OpcodeWithData::Push(n, value))
        } else {
            let opcode = OpcodeId::from_str(op).map_err(|_| err())?;
            Ok(OpcodeWithData::Opcode(opcode))
        }
    }
}

impl ToString for OpcodeWithData {
    fn to_string(&self) -> String {
        match self {
            OpcodeWithData::Opcode(opcode) => format!("{:?}", opcode),
            OpcodeWithData::Push(n, word) => format!("PUSH{}({})", n, word),
        }
    }
}

/// Iterator over the bytecode to retrieve individual opcodes
pub struct BytecodeIterator<'a>(std::slice::Iter<'a, BytecodeElement>);

impl<'a> Iterator for BytecodeIterator<'a> {
    type Item = OpcodeWithData;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|byte| {
            let op = OpcodeId::from(byte.value);
            if op.is_push() {
                let n = op.data_len();
                let mut value = vec![0u8; n];
                for value_byte in value.iter_mut() {
                    *value_byte = self.0.next().unwrap().value;
                }
                OpcodeWithData::Push(n as u8, Word::from(value.as_slice()))
            } else {
                OpcodeWithData::Opcode(op)
            }
        })
    }
}

impl From<Vec<u8>> for Bytecode {
    fn from(input: Vec<u8>) -> Self {
        let mut code = Bytecode::default();

        let mut input_iter = input.iter();
        while let Some(byte) = input_iter.next() {
            let op = OpcodeId::from(*byte);
            code.write_op(op);
            if op.is_push() {
                let n = op.postfix().expect("opcode with postfix");
                for _ in 0..n {
                    match input_iter.next() {
                        Some(v) => {
                            code.write(*v, false);
                        }
                        None => {
                            // out of boundary is allowed
                            // see also: https://github.com/ethereum/go-ethereum/blob/997f1c4f0abcd78f645e6e7ced6db4b42ad59c9d/core/vm/analysis.go#L65
                            break;
                        }
                    }
                }
            }
        }

        code
    }
}

/// EVM code macro
#[macro_export]
macro_rules! bytecode {
    ($($args:tt)*) => {{
        let mut code = $crate::bytecode::Bytecode::default();
        $crate::bytecode_internal!(code, $($args)*);
        code
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! bytecode_internal {
    // Nothing left to do
    ($code:ident, ) => {};
    // WASM const opcodes
    ($code:ident, $x:ident [$v:expr] $($rest:tt)*) => {{
        let _n = $crate::evm_types::OpcodeId::$x.postfix().expect("opcode with postfix");
        $code.write_const($crate::evm_types::OpcodeId::$x, $v as u64);
        $crate::bytecode_internal!($code, $($rest)*);
    }};
    // PUSHX opcodes
    ($code:ident, $x:ident ($v:expr) $($rest:tt)*) => {{
        debug_assert!($crate::evm_types::OpcodeId::$x.is_push(), "invalid push");
        let n = $crate::evm_types::OpcodeId::$x.postfix().expect("opcode with postfix");
        $code.push(n, $v.into());
        $crate::bytecode_internal!($code, $($rest)*);
    }};
    // Default opcode without any inputs
    ($code:ident, $x:ident $($rest:tt)*) => {{
        $code.write_op($crate::evm_types::OpcodeId::$x);
        $crate::bytecode_internal!($code, $($rest)*);
    }};
    // Marker
    ($code:ident, #[$marker:tt] $($rest:tt)*) => {{
        $code.add_marker(stringify!($marker).to_string());
        $crate::bytecode_internal!($code, $($rest)*);
    }};
    // Function calls
    ($code:ident, .$function:ident ($($args:expr),*) $($rest:tt)*) => {{
        $code.$function($($args.into(),)*);
        $crate::bytecode_internal!($code, $($rest)*);
    }};
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::Bytecode;

    use super::*;

    #[test]
    fn test_bytecode_roundtrip() {
        let code = bytecode! {
            PUSH8(0x123)
            POP
            PUSH24(0x321)
            PUSH32(0x432)
            MUL
            CALLVALUE
            CALLER
            POP
            POP
            POP
            STOP
        };
        assert_eq!(Bytecode::try_from(code.to_vec()).unwrap(), code);
    }

    #[test]
    fn test_asm_disasm() {
        let code = bytecode! {
            PUSH1(5)
            PUSH2(0xa)
            MUL
            STOP
        };
        let mut code2 = Bytecode::default();
        code.iter()
            .map(|op| op.to_string())
            .map(|op| OpcodeWithData::from_str(&op).unwrap())
            .for_each(|op| {
                code2.append_op(op);
            });

        assert_eq!(code.bytecode_items, code2.bytecode_items);
    }
}
