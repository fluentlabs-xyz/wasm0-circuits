//! EVM byte code generator

use std::{collections::HashMap, str::FromStr};

use wasm_encoder::{ConstExpr, DataSection, Encode, Instruction};

use crate::{Bytes, evm_types::OpcodeId, Word};

/// Error type for Bytecode related failures
#[derive(Debug)]
pub enum Error {
    /// Serde de/serialization error.
    InvalidAsmError(String),
}

/// Helper struct that represents a single data section in wasm binary
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DataSectionDescriptor {
    pub memory_index: u32,
    pub mem_offset: i32,
    pub data: Vec<u8>,
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
    pub code: Vec<BytecodeElement>,
    num_opcodes: usize,
    markers: HashMap<String, usize>,
}

impl From<Bytecode> for Bytes {
    fn from(code: Bytecode) -> Self {
        code.code
            .iter()
            .map(|e| e.value)
            .collect::<Vec<u8>>()
            .into()
    }
}

impl Bytecode {
    /// Build not checked bytecode
    pub fn from_raw_unchecked(input: Vec<u8>) -> Self {
        Self {
            code: input
                .iter()
                .map(|b| BytecodeElement {
                    value: *b,
                    is_code: true,
                })
                .collect(),
            markers: HashMap::new(),
            num_opcodes: 0,
        }
    }

    pub fn wasm_binary(&self, data_section_descriptors: Option<Vec<DataSectionDescriptor>>) -> Vec<u8> {
        use wasm_encoder::{
            CodeSection, EntityType, ExportKind, ExportSection, Function, FunctionSection,
            ImportSection, MemorySection, MemoryType, Module, TypeSection, ValType,
        };
        let mut module = Module::new();
        // Encode the type & imports section.
        let mut types = TypeSection::new();
        types.function(vec![ValType::I32; 1], vec![]); // 0
        types.function(vec![], vec![]); // 1
        types.function(vec![ValType::I32; 2], vec![]); // 2
        types.function(vec![ValType::I32; 3], vec![]); // 3
        types.function(vec![ValType::I32; 4], vec![]); // 4
        types.function(vec![ValType::I32; 5], vec![]); // 5
        let mut imports = ImportSection::new();
        let evm_functions: Vec<(&str, u32)> = vec![
            ("_evm_stop", 1), // 0
            ("_evm_address", 0), // 1
            ("_evm_caller", 0), // 2
            ("_evm_gaslimit", 0), // 3
            ("_evm_basefee", 0), // 4
            ("_evm_difficulty", 0), // 5
            ("_evm_origin", 0), // 6
            ("_evm_calldatasize", 0), // 7
            ("_evm_callvalue", 0), // 8
            ("_evm_gasprice", 0), // 9
            ("_evm_returndatasize", 0), // 10 TODO some problems
            ("_evm_balance", 2), // 11
            ("_evm_number", 0), // 12
            ("_evm_chainid", 0), // 13
            ("_evm_sload", 2), // 14 TODO
            ("_evm_sstore", 2), // 15
            ("_evm_create", 4), // 16 TODO
            ("_evm_create2", 5), // 17 TODO
            ("_evm_return", 2), // 18 TODO
            ("_evm_revert", 2), // 19 TODO
            ("_evm_codesize", 0), // 20
            ("_evm_selfbalance", 0), // 21
            ("_evm_extcodehash", 2), // 22
            ("_evm_extcodesize", 2), // 23
            ("_evm_calldataload", 2), // 24 TODO

            // TODO
            // ("_evm_calldatacopy", 3),
            // ("_evm_calldataload", 0),
            // ("_evm_callcode", 0),
            // ("_evm_codecopy", 0),
            // ("_evm_extcodecopy", 0),
            // ("_evm_gasprice", 0),
            // ("_evm_log0", 0),
            // ("_evm_log1", 0),
            // ("_evm_log2", 0),
            // ("_evm_log3", 0),
            // ("_evm_log4", 0),
            // ("_evm_revert", 0),
            // ("_evm_returndatacopy", 0),
            // ("_evm_returndatasize", 0),
            // ("_evm_sload", 0),
            // ("_evm_stop", 0),
        ];
        for (func_name, params) in &evm_functions {
            imports.import("env", func_name, EntityType::Function(*params));
        }
        // Encode the function section
        let mut functions = FunctionSection::new();
        functions.function(1);
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
        exports.export("main", ExportKind::Func, evm_functions.len() as u32);
        exports.export("memory", ExportKind::Memory, 0);
        // Encode the code section.
        let mut codes = CodeSection::new();
        let locals = vec![];
        let mut f = Function::new(locals);
        f.raw(self.code());
        f.instruction(&Instruction::End);
        codes.function(&f);
        // build sections (Custom,Type,Import,Function,Table,Memory,Global,Event,Export,Start,Elem,DataCount,Code,Data)
        module.section(&types);
        module.section(&imports);
        module.section(&functions);
        module.section(&memories);
        module.section(&exports);
        module.section(&codes);
        if let Some(vec) = data_section_descriptors {
            for dsd in vec {
                let mut data_section = DataSection::new();
                data_section.active(dsd.memory_index, &ConstExpr::i32_const(dsd.mem_offset), dsd.data.clone());
                module.section(&data_section);
            }
        };
        let wasm_bytes = module.finish();
        return wasm_bytes;
    }

    /// Get the code
    pub fn code(&self) -> Vec<u8> {
        self.code.iter().map(|b| b.value).collect()
    }

    /// Get the bytecode element at an index.
    pub fn get(&self, index: usize) -> Option<BytecodeElement> {
        self.code.get(index).cloned()
    }

    /// Get the generated code
    pub fn to_vec(&self) -> Vec<u8> {
        self.code.iter().map(|e| e.value).collect()
    }

    /// Append
    pub fn append(&mut self, other: &Bytecode) {
        self.code.extend_from_slice(&other.code);
        for (key, val) in other.markers.iter() {
            self.insert_marker(key, self.num_opcodes + val);
        }
        self.num_opcodes += other.num_opcodes;
    }

    /// Write op
    pub fn write_op(&mut self, op: OpcodeId) -> &mut Self {
        let op = match op {
            // WASM opcode mapping
            OpcodeId::I32Const(val) => Instruction::I32Const(val as i32),
            OpcodeId::I64Const(val) => Instruction::I64Const(val as i64),
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
            OpcodeId::End => Instruction::End,
            OpcodeId::Unreachable => Instruction::Unreachable,
            OpcodeId::Drop => Instruction::Drop,
            // EVM opcode mapping
            OpcodeId::STOP => Instruction::Call(0),
            OpcodeId::ADDRESS => Instruction::Call(1),
            OpcodeId::CALLER => Instruction::Call(2),
            OpcodeId::GASLIMIT => Instruction::Call(3),
            OpcodeId::BASEFEE => Instruction::Call(4),
            OpcodeId::DIFFICULTY => Instruction::Call(5),
            OpcodeId::ORIGIN => Instruction::Call(6),
            OpcodeId::CALLDATASIZE => Instruction::Call(7),
            OpcodeId::CALLVALUE => Instruction::Call(8),
            OpcodeId::GASPRICE => Instruction::Call(9),
            OpcodeId::RETURNDATASIZE => Instruction::Call(10),
            OpcodeId::BALANCE => Instruction::Call(11),
            OpcodeId::NUMBER => Instruction::Call(12),
            OpcodeId::CHAINID => Instruction::Call(13),
            OpcodeId::SLOAD => Instruction::Call(14),
            OpcodeId::SSTORE => Instruction::Call(15),
            OpcodeId::CREATE => Instruction::Call(16),
            OpcodeId::CREATE2 => Instruction::Call(17),
            OpcodeId::RETURN => Instruction::Call(18),
            OpcodeId::REVERT => Instruction::Call(19),
            OpcodeId::CODESIZE => Instruction::Call(20),
            OpcodeId::SELFBALANCE => Instruction::Call(21),
            OpcodeId::EXTCODEHASH => Instruction::Call(22),
            OpcodeId::EXTCODESIZE => Instruction::Call(23),
            OpcodeId::CALLDATALOAD => Instruction::Call(24),
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
        self.code.push(BytecodeElement { value, is_code });
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

    // /// Call a contract
    // #[allow(clippy::too_many_arguments)]
    // pub fn call(
    //     &mut self,
    //     gas: Word,
    //     address: Word,
    //     value: Word,
    //     mem_in: Word,
    //     mem_in_size: Word,
    //     mem_out: Word,
    //     mem_out_size: Word,
    // ) -> &mut Self {
    //     self.append(&crate::bytecode! {
    //         PUSH32(mem_out_size)
    //         PUSH32(mem_out)
    //         PUSH32(mem_in_size)
    //         PUSH32(mem_in)
    //         PUSH32(value)
    //         PUSH32(address)
    //         PUSH32(gas)
    //         CALL
    //     });
    //     self
    // }

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
        BytecodeIterator(self.code.iter())
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
    // WASM opcodes
    ($code:ident, $x:ident [$v:expr] $($rest:tt)*) => {{
        let n = $crate::evm_types::OpcodeId::$x($v).postfix().expect("opcode with postfix");
        $code.write_op($crate::evm_types::OpcodeId::$x($v));
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

        assert_eq!(code.code, code2.code);
    }
}
