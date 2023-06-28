use crate::wasm_circuit::consts::{ControlInstruction, NumericInstruction, NumType, WASM_BLOCKTYPE_DELIMITER, WASM_BLOCK_END, VariableInstruction};
use crate::wasm_circuit::leb128_circuit::helpers::leb128_convert;

#[derive(Copy, Clone)]
pub struct WasmCodeSectionLocalDescriptor {
    pub repetition_count: u64,
    pub local_type: NumType,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum  WasmCodeSectionInstructionTypeDescriptor {
    Control,
    Numeric,
    Variable,
    BlockEnd,
}

#[derive(Copy, Clone)]
pub struct WasmCodeSectionExpressionDescriptor {
    pub inst_type: WasmCodeSectionInstructionTypeDescriptor,
    pub cont_inst: Option<ControlInstruction>,
    pub num_inst: Option<NumericInstruction>,
    pub var_inst: Option<VariableInstruction>,
    pub num_arg: Option<i128>,
}

#[derive(Clone)]
pub struct WasmCodeSectionBodyFuncDescriptor {
    pub locals: Vec<WasmCodeSectionLocalDescriptor>,
    pub expressions: Vec<WasmCodeSectionExpressionDescriptor>,
}

#[derive(Clone)]
pub struct WasmCodeSectionBodyDescriptor {
    pub funcs: Vec<WasmCodeSectionBodyFuncDescriptor>,
}

pub fn generate_wasm_code_section_expr_bytecode(descriptor: &WasmCodeSectionExpressionDescriptor) -> Vec<u8> {
    let mut bytecode: Vec<u8> = vec![];
    match descriptor.inst_type {
        WasmCodeSectionInstructionTypeDescriptor::Control => {
            match descriptor.cont_inst.unwrap() {
                ControlInstruction::Block
                | ControlInstruction::Loop
                | ControlInstruction::If => {
                    bytecode.push(descriptor.cont_inst.unwrap() as u8);
                    bytecode.push(WASM_BLOCKTYPE_DELIMITER as u8);
                }
                ControlInstruction::Else => {
                    bytecode.push(descriptor.cont_inst.unwrap() as u8);
                }
                ControlInstruction::Br | ControlInstruction::BrIf => {
                    bytecode.push(descriptor.cont_inst.unwrap() as u8);
                    bytecode.extend(leb128_convert(false, descriptor.num_arg.unwrap()));
                }
                _ => {
                    panic!("unsupported control instruction '{:x?}'", descriptor.cont_inst.unwrap())
                }
            }
        }
        WasmCodeSectionInstructionTypeDescriptor::Numeric => {
            match descriptor.num_inst.unwrap() {
                NumericInstruction::I32Const
                | NumericInstruction::I64Const => {
                    bytecode.push(descriptor.num_inst.unwrap() as u8);
                    bytecode.extend(leb128_convert(false, descriptor.num_arg.unwrap()));
                }
                NumericInstruction::I32Add => {
                    bytecode.push(descriptor.num_inst.unwrap() as u8);
                }
                _ => {
                    panic!("unsupported numeric instruction '{:x?}'", descriptor.num_inst.unwrap())
                }
            }
        }
        WasmCodeSectionInstructionTypeDescriptor::Variable => {
            match descriptor.var_inst.unwrap() {
                VariableInstruction::LocalSet | VariableInstruction::LocalGet => {
                    bytecode.push(descriptor.var_inst.unwrap() as u8);
                    bytecode.extend(leb128_convert(false, descriptor.num_arg.unwrap()));
                }
                _ => {
                    panic!("unsupported variable instruction '{:x?}'", descriptor.var_inst.unwrap())
                }
            }
        }
        WasmCodeSectionInstructionTypeDescriptor::BlockEnd => {
            bytecode.push(WASM_BLOCK_END as u8);
        }
        _ => {
            panic!("unsupported instruction type '{:x?}'", descriptor.inst_type.clone())
        }
    }

    return bytecode;
}

pub fn generate_wasm_code_section_body_func_bytecode(descriptor: &WasmCodeSectionBodyFuncDescriptor) -> Vec<u8> {
    let mut bytecode: Vec<u8> = vec![];
    let mut func_body_bytecode: Vec<u8> = vec![];

    for i in 1..descriptor.locals.len() {
        if descriptor.locals[i-1].local_type == descriptor.locals[i].local_type {
            panic!("local_type's must be different for adjacent values")
        }
    }
    // type transitions count
    func_body_bytecode.extend(leb128_convert(false, descriptor.locals.len() as i128));
    // repetitions count + type of repetition
    for local in &descriptor.locals {
        func_body_bytecode.extend(leb128_convert(false, local.repetition_count as i128));
        func_body_bytecode.push(local.local_type as u8);
    }

    for expr in &descriptor.expressions {
        func_body_bytecode.extend(generate_wasm_code_section_expr_bytecode(expr));
    }

    // func_body_len computation
    bytecode.extend(leb128_convert(false, func_body_bytecode.len() as i128));
    bytecode.extend(func_body_bytecode);
    return bytecode;
}

// https://webassembly.github.io/spec/core/binary/modules.html#code-section
// example (hex, first two bytes are section_id(10=0xA) and section_leb_len):
// is_funcs_count+ -> func+(is_func_body_len+ -> locals(1)(is_local_type_transitions_count+ -> local_var_descriptor+(is_local_repetition_count+ -> is_local_type(1))) -> is_func_body_code+)
// raw (hex):     [a,  2e, 2, 1d, 1, 1,  7f, 41, 0, 21, 0, 2, 40, 3, 40, 20, 0,  d, 1, 20, 0, 41,  c0,  c4, 7,  6a, 21, 0,  c, 0,  b,  b,  b,  e, 4, 1,  7f, 1,  7e, 2,  7f, 3,  7e, 41, 0, 21, 0, b]
// raw (hex):     [
// a, - section_id
// 2e, - section_body_leb_len
// 2, - funcs_count
// 1d, - func_body_len
// 1, - locals: 1 count of type transitions
// 1, 7f, - locals: 1 repetition of I32
//   41, 0, - func_body: i32.const 0
//   21, 0, - func_body: local.set 0
//   2, 40, - func_body: blocktype.block
//     3, 40, - func_body: blocktype.loop
//       20, 0, - func_body: local.get 0
//       d, 1, - func_body: br_if 1 (;@1;)
//       20, 0, - func_body: local.get 0
//       41,  c0,  c4, 7, - func_body: i32.const 123456
//       6a, - func_body: i32.add
//       21, 0, - func_body: local.set 0
//       c, 0, - func_body: br 0 (;@2;)
//     b, - func_body: blocktype.loop.end
//   b, - func_body: blocktype.block.end
// b, - func_body: func_body.end
// e, - func_body_len
// 4, - locals: 4 type transitions
//   1,  7f, - locals: 1 repetition of I32
//   1,  7e, - locals: 1 repetition of I64
//   2,  7f, - locals: 2 repetitions of I32
//   3,  7e, - locals: 3 repetitions of I64
//   41, 0, - func_body: i32.const 0
//   21, 0, - func_body: local.set 0
// b - func end
// ]
// raw (decimal): [10, 46, 2, 29, 1, 1, 127, 65, 0, 33, 0, 2, 64, 3, 64, 32, 0, 13, 1, 32, 0, 65, 192, 196, 7, 106, 33, 0, 12, 0, 11, 11, 11, 14, 4, 1, 127, 1, 126, 2, 127, 3, 126, 65, 0, 33, 0, 11]
pub fn generate_wasm_code_section_body_bytecode(descriptor: &WasmCodeSectionBodyDescriptor) -> Vec<u8> {
    let mut bytecode: Vec<u8> = vec![];
    if descriptor.funcs.len() <= 0 { return bytecode }
    bytecode.extend(leb128_convert(false, descriptor.funcs.len() as i128));
    for func in &descriptor.funcs {
        bytecode.extend(generate_wasm_code_section_body_func_bytecode(func));
    }

    return bytecode;
}

#[cfg(test)]
mod test_helpers {
    use crate::wasm_circuit::consts::{ControlInstruction, NumericInstruction, NumType, VariableInstruction};
    use crate::wasm_circuit::wasm_sections::wasm_code_section::test_helpers::{generate_wasm_code_section_body_bytecode, WasmCodeSectionBodyDescriptor, WasmCodeSectionBodyFuncDescriptor, WasmCodeSectionExpressionDescriptor, WasmCodeSectionInstructionTypeDescriptor, WasmCodeSectionLocalDescriptor};

    #[test]
    pub fn generate_wasm_code_section_body_bytecode_test() {
        // expected
        //         0  1   2  3   4   5   6  7   8  9  10  11 12  13 14  15 16  17 18  19   20   21 22   23  24 25  26 27  28  29  30  31 32 33   34 35   36 37   38 39   40  41 42  43 44 45
        // (hex): [2, 1d, 1, 1,  7f, 41, 0, 21, 0, 2, 40, 3, 40, 20, 0,  d, 1, 20, 0, 41,  c0,  c4, 7,  6a, 21, 0,  c, 0,  b,  b,  b,  e, 4, 1,  7f, 1,  7e, 2,  7f, 3,  7e, 41, 0, 21, 0, b]
        let expected = [2, 29, 1, 1, 127, 65, 0, 33, 0, 2, 64, 3, 64, 32, 0, 13, 1, 32, 0, 65, 192, 196, 7, 106, 33, 0, 12, 0, 11, 11, 11, 14, 4, 1, 127, 1, 126, 2, 127, 3, 126, 65, 0, 33, 0, 11].as_slice().to_vec();
        let descriptor = WasmCodeSectionBodyDescriptor {
            funcs: vec![
                WasmCodeSectionBodyFuncDescriptor {
                    locals: vec![
                        WasmCodeSectionLocalDescriptor {
                            repetition_count: 1,
                            local_type: NumType::I32,
                        },
                    ],
                    expressions: vec![
                        // 41, 0, - func_body_code: i32.const 0
                        WasmCodeSectionExpressionDescriptor{
                            inst_type: WasmCodeSectionInstructionTypeDescriptor::Numeric,
                            cont_inst: None,
                            num_inst: Some(NumericInstruction::I32Const),
                            var_inst: None,
                            num_arg: Some(0),
                        },
                        // 21, 0, - func_body_code: local.set 0
                        WasmCodeSectionExpressionDescriptor{
                            inst_type: WasmCodeSectionInstructionTypeDescriptor::Variable,
                            cont_inst: None,
                            num_inst: None,
                            var_inst: Some(VariableInstruction::LocalSet),
                            num_arg: Some(0),
                        },
                        // 2, 40, - func_body_code: blocktype.block
                        WasmCodeSectionExpressionDescriptor{
                            inst_type: WasmCodeSectionInstructionTypeDescriptor::Control,
                            cont_inst: Some(ControlInstruction::Block),
                            num_inst: None,
                            var_inst: None,
                            num_arg: None,
                        },
                        //   3, 40, - func_body_code: blocktype.loop
                        WasmCodeSectionExpressionDescriptor{
                            inst_type: WasmCodeSectionInstructionTypeDescriptor::Control,
                            cont_inst: Some(ControlInstruction::Loop),
                            num_inst: None,
                            var_inst: None,
                            num_arg: None,
                        },
                        //     20, 0, - func_body_code: local.get 0
                        WasmCodeSectionExpressionDescriptor{
                            inst_type: WasmCodeSectionInstructionTypeDescriptor::Variable,
                            cont_inst: None,
                            num_inst: None,
                            var_inst: Some(VariableInstruction::LocalGet),
                            num_arg: Some(0),
                        },
                        //     d, 1, - func_body_code: br_if 1 (;@1;)
                        WasmCodeSectionExpressionDescriptor{
                            inst_type: WasmCodeSectionInstructionTypeDescriptor::Control,
                            cont_inst: Some(ControlInstruction::BrIf),
                            num_inst: None,
                            var_inst: None,
                            num_arg: Some(1),
                        },
                        //     20, 0, - func_body_code: local.get 0
                        WasmCodeSectionExpressionDescriptor{
                            inst_type: WasmCodeSectionInstructionTypeDescriptor::Variable,
                            cont_inst: None,
                            num_inst: None,
                            var_inst: Some(VariableInstruction::LocalGet),
                            num_arg: Some(0),
                        },
                        //     41,  c0,  c4, 7, - func_body_code: i32.const 123456
                        WasmCodeSectionExpressionDescriptor{
                            inst_type: WasmCodeSectionInstructionTypeDescriptor::Numeric,
                            cont_inst: None,
                            num_inst: Some(NumericInstruction::I32Const),
                            var_inst: None,
                            num_arg: Some(123456),
                        },
                        //     6a, - func_body_code: i32.add
                        WasmCodeSectionExpressionDescriptor{
                            inst_type: WasmCodeSectionInstructionTypeDescriptor::Numeric,
                            cont_inst: None,
                            num_inst: Some(NumericInstruction::I32Add),
                            var_inst: None,
                            num_arg: None,
                        },
                        //     21, 0, - func_body_code: local.set 0
                        WasmCodeSectionExpressionDescriptor{
                            inst_type: WasmCodeSectionInstructionTypeDescriptor::Variable,
                            cont_inst: None,
                            num_inst: None,
                            var_inst: Some(VariableInstruction::LocalSet),
                            num_arg: Some(0),
                        },
                        //     c, 0, - func_body_code: br 0 (;@2;)
                        WasmCodeSectionExpressionDescriptor{
                            inst_type: WasmCodeSectionInstructionTypeDescriptor::Control,
                            cont_inst: Some(ControlInstruction::Br),
                            num_inst: None,
                            var_inst: None,
                            num_arg: Some(0),
                        },
                        //   b, - func_body_code: blocktype.loop.end
                        WasmCodeSectionExpressionDescriptor{
                            inst_type: WasmCodeSectionInstructionTypeDescriptor::BlockEnd,
                            cont_inst: None,
                            num_inst: None,
                            var_inst: None,
                            num_arg: None,
                        },
                        // b, - func_body_code: blocktype.block.end
                        WasmCodeSectionExpressionDescriptor{
                            inst_type: WasmCodeSectionInstructionTypeDescriptor::BlockEnd,
                            cont_inst: None,
                            num_inst: None,
                            var_inst: None,
                            num_arg: None,
                        },
                        // b, - func_body_code: func.end
                        WasmCodeSectionExpressionDescriptor{
                            inst_type: WasmCodeSectionInstructionTypeDescriptor::BlockEnd,
                            cont_inst: None,
                            num_inst: None,
                            var_inst: None,
                            num_arg: None,
                        },
                    ],
                },
                WasmCodeSectionBodyFuncDescriptor {
                    locals: vec![
                        WasmCodeSectionLocalDescriptor {
                            repetition_count: 1,
                            local_type: NumType::I32,
                        },
                        WasmCodeSectionLocalDescriptor {
                            repetition_count: 1,
                            local_type: NumType::I64,
                        },
                        WasmCodeSectionLocalDescriptor {
                            repetition_count: 2,
                            local_type: NumType::I32,
                        },
                        WasmCodeSectionLocalDescriptor {
                            repetition_count: 3,
                            local_type: NumType::I64,
                        },
                    ],
                    expressions: vec![
                        //   41, 0, - func_body_code: i32.const 0
                        WasmCodeSectionExpressionDescriptor{
                            inst_type: WasmCodeSectionInstructionTypeDescriptor::Numeric,
                            cont_inst: None,
                            num_inst: Some(NumericInstruction::I32Const),
                            var_inst: None,
                            num_arg: Some(0),
                        },
                        //   21, 0, - func_body_code: local.set 0
                        WasmCodeSectionExpressionDescriptor{
                            inst_type: WasmCodeSectionInstructionTypeDescriptor::Variable,
                            cont_inst: None,
                            num_inst: None,
                            var_inst: Some(VariableInstruction::LocalSet),
                            num_arg: Some(0),
                        },
                        // b - func end
                        WasmCodeSectionExpressionDescriptor{
                            inst_type: WasmCodeSectionInstructionTypeDescriptor::BlockEnd,
                            cont_inst: None,
                            num_inst: None,
                            var_inst: None,
                            num_arg: None,
                        },
                    ],
                },
            ],
        };

        let bytecode = generate_wasm_code_section_body_bytecode(&descriptor);
        assert_eq!(expected, bytecode);
    }
}