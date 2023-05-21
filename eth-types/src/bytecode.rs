//! EVM byte code generator

use crate::{evm_types::OpcodeId, Bytes, ToWord, Word, Address, U256, ToLittleEndian};
use std::{collections::HashMap, str::FromStr};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use wasm_encoder::{CodeSection, ConstExpr, DataSection, Encode, Function, FunctionSection, GlobalSection, GlobalType, Instruction, MemArg, TypeSection, ValType};
use wasm_encoder::BlockType::Empty;

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
    type_index: u32,
}

/// Helper struct that represents a single element in a bytecode.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BytecodeElement {
    /// The byte value of the element.
    pub value: u8,
    /// Whether the element is an opcode or push data byte.
    pub is_code: bool,
}

///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalVariable {
    pub index: u32,
    pub init_code: Vec<u8>,
    pub is_64bit: bool,
    pub readonly: bool,
}

///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalFunction {
    pub index: u32,
    pub code: Vec<u8>,
}

impl GlobalVariable {

    pub fn default_i32(index: u32, default_value: u32) -> Self {
        Self::default(index, false, default_value as u64)
    }

    pub fn default_i64(index: u32, default_value: u64) -> Self {
        Self::default(index, true, default_value)
    }

    pub fn default(index: u32, is_64bit: bool, default_value: u64) -> Self {
        let mut init_code = Vec::new();
        if is_64bit {
            Instruction::I64Const(default_value as i64).encode(&mut init_code);
        } else {
            Instruction::I32Const(default_value as i32).encode(&mut init_code);
        }
        GlobalVariable { index, is_64bit, init_code, readonly: false }
    }

    pub fn zero_i32(index: u32) -> Self {
        Self::default_i32(index, 0)
    }

    pub fn zero_i64(index: u32) -> Self {
        Self::default_i64(index, 0)
    }
}

/// EVM Bytecode
#[derive(Debug, Clone)]
pub struct Bytecode {
    /// Vector for bytecode elements.
    pub bytecode_items: Vec<BytecodeElement>,
    global_data: (u32, Vec<u8>),
    section_descriptors: Vec<SectionDescriptor>,
    variables: Vec<GlobalVariable>,
    existing_types: HashMap<u64, u32>,
    types: TypeSection,
    functions: FunctionSection,
    codes: CodeSection,
    main_locals: Vec<(u32, ValType)>,
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
            EntityType, ExportKind, ExportSection,
            ImportSection, MemorySection, MemoryType, Module,
        };
        let mut module = Module::new();
        // Encode the type & imports section.
        let mut imports = ImportSection::new();
        let ordered_evm_table = self.evm_table.clone()
            .into_iter()
            .map(|(k, v)| (v, k))
            .collect::<BTreeMap<_, _>>();
        for (_, evm_call) in ordered_evm_table {
            imports.import("env", evm_call.fn_name, EntityType::Function(evm_call.type_index));
        }
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
        exports.export("main", ExportKind::Func, self.evm_table.len() as u32 + self.functions.len());
        exports.export("memory", ExportKind::Memory, 0);
        // Encode the main function
        let mut functions = self.functions.clone();
        functions.function(0);
        let mut codes = self.codes.clone();
        let mut f = Function::new(self.main_locals.clone());
        f.raw(self.code());
        f.instruction(&Instruction::End);
        codes.function(&f);
        // build sections order (Custom,Type,Import,Function,Table,Memory,Global,Event,Export,Start,Elem,DataCount,Code,Data)
        module.section(&self.types);
        module.section(&imports);
        module.section(&functions);
        module.section(&memories);
        if self.variables.len() > 0 {
            let mut global_section = GlobalSection::new();
            for var in &self.variables {
                let var_type = if var.is_64bit {
                    GlobalType { val_type: ValType::I64, mutable: !var.readonly }
                } else {
                    GlobalType { val_type: ValType::I32, mutable: !var.readonly }
                };
                global_section.global(var_type, &ConstExpr::raw(var.init_code.clone()));
            }
            module.section(&global_section);
        }
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

impl Default for Bytecode {
    fn default() -> Self {
        let mut res = Self {
            bytecode_items: vec![],
            global_data: (0, vec![]),
            section_descriptors: vec![],
            variables: vec![],
            existing_types: Default::default(),
            types: Default::default(),
            functions: Default::default(),
            codes: Default::default(),
            main_locals: Default::default(),
            evm_table: Default::default(),
            num_opcodes: 0,
            markers: Default::default(),
        };
        res.ensure_function_type(vec![], vec![]);
        res
    }
}

impl Bytecode {
    /// Build not checked bytecode
    pub fn from_raw_unchecked(input: Vec<u8>) -> Self {
        let mut res = Self::default();
        res.bytecode_items = input
            .iter()
            .map(|b| BytecodeElement {
                value: *b,
                is_code: true,
            })
            .collect();
        res
    }

    pub fn alloc_default_global_data(&mut self, size: u32) -> u32 {
        self.fill_default_global_data(vec![0].repeat(size as usize))
    }

    pub fn fill_default_global_data(&mut self, data: Vec<u8>) -> u32 {
        let current_offset = self.global_data.1.len();
        self.global_data.1.extend(&data);
        current_offset as u32
    }

    pub fn with_main_locals(&mut self, locals: Vec<(u32, ValType)>) -> &mut Self {
        self.main_locals.extend(&locals);
        self
    }

    pub fn with_global_data(&mut self, memory_index: u32, memory_offset: u32, data: Vec<u8>) -> &mut Self {
        self.section_descriptors.push(SectionDescriptor::Data {
            index: memory_index,
            offset: memory_offset,
            data,
        });
        self
    }

    pub fn with_global_variable(&mut self, global_variable: GlobalVariable) {
        self.variables.push(global_variable);
    }

    fn encode_function_type(input: &Vec<ValType>, output: &Vec<ValType>) -> u64 {
        let mut buf = Vec::new();
        input.encode(&mut buf);
        output.encode(&mut buf);
        let mut hasher = DefaultHasher::new();
        buf.hash(&mut hasher);
        hasher.finish()
    }

    fn ensure_function_type(&mut self, input: Vec<ValType>, output: Vec<ValType>) -> u32 {
        let type_hash = Self::encode_function_type(&input, &output);
        if let Some(type_index) = self.existing_types.get(&type_hash) {
            return *type_index;
        }
        let type_index = self.existing_types.len() as u32;
        self.existing_types.insert(type_hash, type_index);
        self.types.function(input, output);
        type_index
    }

    pub fn new_function(
        &mut self,
        input: Vec<ValType>,
        output: Vec<ValType>,
        bytecode: Bytecode,
        locals: Vec<(u32, ValType)>,
    ) {
        let type_index = self.ensure_function_type(input, output);
        self.functions.function(type_index);
        let mut f = Function::new(locals);
        f.raw(bytecode.code());
        f.instruction(&Instruction::End);
        self.codes.function(&f);
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
        self.variables = other.variables.clone();
        self.existing_types = other.existing_types.clone();
        self.types = other.types.clone();
        self.functions = other.functions.clone();
        self.codes = other.codes.clone();
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
            OpcodeId::BLOCKHASH => ("_evm_blockhash", 2),
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

        let type_index = self.ensure_function_type(vec![ValType::I32; args_num], vec![]);

        let evm_call = EvmCall {
            fn_name,
            type_index,
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

            OpcodeId::I32GtU => Instruction::I32GtU,
            OpcodeId::I32GeU => Instruction::I32GeU,
            OpcodeId::I32LtU => Instruction::I32LtU,
            OpcodeId::I32LeU => Instruction::I32LeU,
            OpcodeId::I32Eq => Instruction::I32Eq,
            OpcodeId::I32Ne => Instruction::I32Ne,
            OpcodeId::I32GtS => Instruction::I32GtS,
            OpcodeId::I32GeS => Instruction::I32GeS,
            OpcodeId::I32LtS => Instruction::I32LtS,
            OpcodeId::I32LeS => Instruction::I32LeS,

            OpcodeId::I64GtU => Instruction::I64GtU,
            OpcodeId::I64GeU => Instruction::I64GeU,
            OpcodeId::I64LtU => Instruction::I64LtU,
            OpcodeId::I64LeU => Instruction::I64LeU,
            OpcodeId::I64Eq => Instruction::I64Eq,
            OpcodeId::I64Ne => Instruction::I64Ne,
            OpcodeId::I64GtS => Instruction::I64GtS,
            OpcodeId::I64GeS => Instruction::I64GeS,
            OpcodeId::I64LtS => Instruction::I64LtS,
            OpcodeId::I64LeS => Instruction::I64LeS,

/*
            OpcodeId::I32Load => Instruction::I32Load,
            OpcodeId::I32Load8S => Instruction::I32Load8S,
            OpcodeId::I32Load8U => Instruction::I32Load8U,
            OpcodeId::I32Load16S => Instruction::I32Load16S,
            OpcodeId::I32Load16U => Instruction::I32Load16U,

            OpcodeId::I64Load => Instruction::I64Load,
            OpcodeId::I64Load8S => Instruction::I64Load8S,
            OpcodeId::I64Load8U => Instruction::I64Load8U,
            OpcodeId::I64Load16S => Instruction::I64Load16S,
            OpcodeId::I64Load16U => Instruction::I64Load16U,
            OpcodeId::I64Load32S => Instruction::I64Load32S,
            OpcodeId::I64Load32U => Instruction::I64Load32U,
*/

            //OpcodeId::Select => Instruction::Select,

/*
            OpcodeId::I32Store => Instruction::I32Store,
            OpcodeId::I32Store8 => Instruction::I32Store8,
            OpcodeId::I32Store16 => Instruction::I32Store16,
            OpcodeId::I64Store => Instruction::I64Store,
            OpcodeId::I64Store8 => Instruction::I64Store8,
            OpcodeId::I64Store16 => Instruction::I64Store16,
            OpcodeId::I64Store32 => Instruction::I64Store32,
*/

            //OpcodeId::GrowMemory => Instruction::MemoryGrow,
            //OpcodeId::CurrentMemory => Instruction::MemorySize,

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
            OpcodeId::I32Eqz => Instruction::I32Eqz,
            OpcodeId::I64Eqz => Instruction::I64Eqz,
            OpcodeId::I32WrapI64 => Instruction::I32WrapI64,
            OpcodeId::I64ExtendI32 => Instruction::I64ExtendI32S,
            OpcodeId::End => Instruction::End,
            OpcodeId::Unreachable => Instruction::Unreachable,
            OpcodeId::Drop => Instruction::Drop,
            OpcodeId::Return => Instruction::Return,
            OpcodeId::Block => Instruction::Block(Empty),
            OpcodeId::Loop => Instruction::Loop(Empty),
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

    pub fn write_memarg(&mut self, op: OpcodeId, offset: u64, align: u32, memory_index: u32) -> &mut Self {
        let mem_arg = MemArg { offset, align, memory_index };
        let op = match op {
            OpcodeId::I32Load => Instruction::I32Load(mem_arg),
            OpcodeId::I64Load => Instruction::I64Load(mem_arg),
            OpcodeId::F32Load => Instruction::F32Load(mem_arg),
            OpcodeId::F64Load => Instruction::F64Load(mem_arg),
            OpcodeId::I32Load8S => Instruction::I32Load8S(mem_arg),
            OpcodeId::I32Load8U => Instruction::I32Load8U(mem_arg),
            OpcodeId::I32Load16S => Instruction::I32Load16S(mem_arg),
            OpcodeId::I32Load16U => Instruction::I32Load16U(mem_arg),
            OpcodeId::I64Load8S => Instruction::I64Load8S(mem_arg),
            OpcodeId::I64Load8U => Instruction::I64Load8U(mem_arg),
            OpcodeId::I64Load16S => Instruction::I64Load16S(mem_arg),
            OpcodeId::I64Load16U => Instruction::I64Load16U(mem_arg),
            OpcodeId::I64Load32S => Instruction::I64Load32S(mem_arg),
            OpcodeId::I64Load32U => Instruction::I64Load32U(mem_arg),
            OpcodeId::I32Store => Instruction::I32Store(mem_arg),
            OpcodeId::I64Store => Instruction::I64Store(mem_arg),
            OpcodeId::F32Store => Instruction::F32Store(mem_arg),
            OpcodeId::F64Store => Instruction::F64Store(mem_arg),
            OpcodeId::I32Store8 => Instruction::I32Store8(mem_arg),
            OpcodeId::I32Store16 => Instruction::I32Store16(mem_arg),
            OpcodeId::I64Store8 => Instruction::I64Store8(mem_arg),
            OpcodeId::I64Store16 => Instruction::I64Store16(mem_arg),
            OpcodeId::I64Store32 => Instruction::I64Store32(mem_arg),
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

    pub fn write_postfix(&mut self, op: OpcodeId, val: u64) -> &mut Self {
        let op = match op {
            OpcodeId::I32Const => Instruction::I32Const(val as i32),
            OpcodeId::I64Const => Instruction::I64Const(val as i64),
            OpcodeId::GetGlobal => Instruction::GlobalGet(val as u32),
            OpcodeId::SetGlobal => Instruction::GlobalSet(val as u32),
            OpcodeId::GetLocal => Instruction::LocalGet(val as u32),
            OpcodeId::SetLocal => Instruction::LocalSet(val as u32),
            OpcodeId::TeeLocal => Instruction::LocalTee(val as u32),
            OpcodeId::Call => Instruction::Call(val as u32),
            OpcodeId::Br => Instruction::Br(val as u32),
            OpcodeId::BrIf => Instruction::BrIf(val as u32),
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
    pub fn push<T: ToWord>(&mut self, n: u8, value: T) -> &mut Self {
        debug_assert!((1..=32).contains(&n), "invalid push");
        let value = value.to_word();

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

    /// JUMPDEST opcode
    pub fn op_jumpdest(&mut self) -> usize {
        self.write_op(OpcodeId::JUMPDEST);
        self.bytecode_items.len()
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
        $code.write_postfix($crate::evm_types::OpcodeId::$x, $v as u64);
        $crate::bytecode_internal!($code, $($rest)*);
    }};
    // PUSHX opcodes
    ($code:ident, $x:ident ($v:expr) $($rest:tt)*) => {{
        debug_assert!($crate::evm_types::OpcodeId::$x.is_push(), "invalid push");
        let n = $crate::evm_types::OpcodeId::$x.postfix().expect("opcode with postfix");
        $code.push(n, $v);
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
    ($code:ident, .$function:ident ($($args:expr),* $(,)?) $($rest:tt)*) => {{
        $code.$function($($args,)*);
        $crate::bytecode_internal!($code, $($rest)*);
    }};
}

macro_rules! impl_push_n {
    ($($push_n:ident, $n:expr)*) => {
        #[allow(missing_docs)]
        impl Bytecode {
            $(
                pub fn $push_n<T: ToWord>(&mut self, value: T) -> &mut Self {
                    self.push($n, value)
                }
            )*
        }
    };
}

impl_push_n! {
    op_push1, 1
    op_push2, 2
    op_push3, 3
    op_push4, 4
    op_push5, 5
    op_push6, 6
    op_push7, 7
    op_push8, 8
    op_push9, 9
    op_push10, 10
    op_push11, 11
    op_push12, 12
    op_push13, 13
    op_push14, 14
    op_push15, 15
    op_push16, 16
    op_push17, 17
    op_push18, 18
    op_push19, 19
    op_push20, 20
    op_push21, 21
    op_push22, 22
    op_push23, 23
    op_push24, 24
    op_push25, 25
    op_push26, 26
    op_push27, 27
    op_push28, 28
    op_push29, 29
    op_push30, 30
    op_push31, 31
    op_push32, 32
}

macro_rules! impl_other_opcodes_inner {
    ($self:ident, ) => {};
    ($self:ident, $arg:ident) => {
        $self.op_push32($arg);
    };
    ($self:ident, $arg:ident $($tail:ident)+) => {
        impl_other_opcodes_inner!($self, $($tail)*);
        $self.op_push32($arg);
    }
}

macro_rules! impl_other_opcodes {
    ($(($op:ident, $x:ident $(, $arg:ident : $arg_ty:ident)*)),* $(,)?) => {
        #[allow(missing_docs)]
        #[allow(clippy::too_many_arguments)]
        impl Bytecode {
            $(
                pub fn $op<$(
                    $arg_ty: ToWord,
                )*>(&mut self, $($arg: $arg_ty),*) -> &mut Self {
                    impl_other_opcodes_inner!(self, $($arg)*);
                    self.write_op($crate::evm_types::OpcodeId::$x)
                }
            )*
        }
    };
}

impl_other_opcodes! {
    (op_stop, STOP),
    (op_add, ADD, a: A, b: B),
    (op_mul, MUL, a: A, b: B),
    (op_sub, SUB, a: A, b: B),
    (op_div, DIV, a: A, b: B),
    (op_sdiv, SDIV, a: A, b: B),
    (op_mod, MOD, a: A, b: B),
    (op_smod, SMOD, a: A, b: B),
    (op_addmod, ADDMOD, a: A, b: B, n: N),
    (op_mulmod, MULMOD, a: A, b: B, n: N),
    (op_exp, EXP, a: A, exponent: B),
    (op_signextend, SIGNEXTEND, b: A, x: B),
    (op_lt, LT, a: A, b: B),
    (op_gt, GT, a: A, b: B),
    (op_slt, SLT, a: A, b: B),
    (op_sgt, SGT, a: A, b: B),
    (op_eq, EQ, a: A, b: B),
    (op_iszero, ISZERO, a: A),
    (op_and, AND, a: A, b: B),
    (op_or, OR, a: A, b: B),
    (op_xor, XOR, a: A, b: B),
    (op_not, NOT, a: A),
    (op_byte, BYTE, i: I, x: X),
    (op_shl, SHL, shift: S, value: V),
    (op_shr, SHR, shift: S, value: V),
    (op_sar, SAR, shift: S, value: V),
    (op_sha3, SHA3, offset: O, size: S),
    (op_address, ADDRESS),
    (op_balance, BALANCE, address: A),
    (op_origin, ORIGIN),
    (op_caller, CALLER),
    (op_callvalue, CALLVALUE),
    (op_calldataload, CALLDATALOAD, i: I),
    (op_calldatasize, CALLDATASIZE),
    (op_calldatacopy, CALLDATACOPY, dest_offset: D, offset: B, size: C),
    (op_codesize, CODESIZE),
    (op_codecopy, CODECOPY, dest_offset: D, offset: B, size: C),
    (op_gasprice, GASPRICE),
    (op_extcodesize, EXTCODESIZE, address: A),
    (op_extcodecopy, EXTCODECOPY, address: A, dest_offset: D, offset: B, size: C),
    (op_returndatasize, RETURNDATASIZE),
    (op_returndatacopy, RETURNDATACOPY, dest_offset: D, offset: B, size: C),
    (op_extcodehash, EXTCODEHASH, address: A),
    (op_blockhash, BLOCKHASH, blocknumber: B),
    (op_coinbase, COINBASE),
    (op_timestamp, TIMESTAMP),
    (op_number, NUMBER),
    (op_prevrandao, DIFFICULTY), // alias for DIFFICULTY
    (op_difficulty, DIFFICULTY),
    (op_gaslimit, GASLIMIT),
    (op_chainid, CHAINID),
    (op_selfbalance, SELFBALANCE),
    // (op_basefee, BASEFEE), ignored
    (op_pop, POP),
    (op_mload, MLOAD, offset: O),
    (op_mstore, MSTORE, offset: O, value: V),
    (op_mstore8, MSTORE8, offset: O, value: V),
    (op_sload, SLOAD, offset: O),
    (op_sstore, SSTORE, offset: O, value: V),
    (op_jump, JUMP, counter: C),
    (op_jumpi, JUMPI, counter: C), // branch not included
    (op_pc, PC),
    (op_msize, MSIZE),
    (op_gas, GAS),
    // (op_jumpdest, JUMPDEST), manually implemented
    (op_dup1, DUP1),
    (op_dup2, DUP2),
    (op_dup3, DUP3),
    (op_dup4, DUP4),
    (op_dup5, DUP5),
    (op_dup6, DUP6),
    (op_dup7, DUP7),
    (op_dup8, DUP8),
    (op_dup9, DUP9),
    (op_dup10, DUP10),
    (op_dup11, DUP11),
    (op_dup12, DUP12),
    (op_dup13, DUP13),
    (op_dup14, DUP14),
    (op_dup15, DUP15),
    (op_dup16, DUP16),
    (op_swap1, SWAP1),
    (op_swap2, SWAP2),
    (op_swap3, SWAP3),
    (op_swap4, SWAP4),
    (op_swap5, SWAP5),
    (op_swap6, SWAP6),
    (op_swap7, SWAP7),
    (op_swap8, SWAP8),
    (op_swap9, SWAP9),
    (op_swap10, SWAP10),
    (op_swap11, SWAP11),
    (op_swap12, SWAP12),
    (op_swap13, SWAP13),
    (op_swap14, SWAP14),
    (op_swap15, SWAP15),
    (op_swap16, SWAP16),
    (op_log0, LOG0, offset: O, size: S),
    (op_log1, LOG1, offset: O, size: S, topic1: T1),
    (op_log2, LOG2, offset: O, size: S, topic1: T1, topic2: T2),
    (op_log3, LOG3, offset: O, size: S, topic1: T1, topic2: T2, topic3: T3),
    (op_log4, LOG4, offset: O, size: S, topic1: T1, topic2: T2, topic3: T3, topic4: T4),
    (op_create, CREATE, value: V, offset: O, size: S),
    (op_call, CALL, gas: G, address: A, value: V, args_offset: AO, args_size: AS, ret_offset: RO, ret_size: RS),
    (op_callcode, CALLCODE, gas: G, address: A, value: V, args_offset: AO, args_size: AS, ret_offset: RO, ret_size: RS),
    (op_return, RETURN, offset: O, size: S),
    (op_delegatecall, DELEGATECALL, gas: G, address: A, args_offset: AO, args_size: AS, ret_offset: RO, ret_size: RS),
    (op_create2, CREATE2, value: V, offset: O, size: SI, salt: SA),
    (op_staticcall, STATICCALL, gas: G, address: A, args_offset: AO, args_size: AS, ret_offset: RO, ret_size: RS),
    (op_revert, REVERT, offset: O, size: S),
    // (op_invalid, INVALID), ignored
    // (op_selfdestruct, SELFDESTRUCT), ignored
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_function_encoding() {
        let mut bytecode = bytecode! {
            Call[0]
            Drop
        };
        bytecode.new_function(vec![], vec![ValType::I32], bytecode! {
            I32Const[0x7f]
        }, vec![]);
        let wasm_binary = bytecode.wasm_binary();
        println!("{}", hex::encode(wasm_binary));
    }

    #[test]
    fn test_wasm_locals_encoding() {
        let mut bytecode = bytecode! {
            I32Const[100]
            I32Const[20]
            Call[0]
            Drop
        };
        bytecode.new_function(vec![ValType::I32; 2], vec![ValType::I32], bytecode! {
            GetLocal[0]
            GetLocal[1]
            I32Add
        }, vec![]);
        let wasm_binary = bytecode.wasm_binary();
        println!("{}", hex::encode(wasm_binary));
    }
}
