use halo2_proofs::{
    plonk::{ConstraintSystem, Error},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::Circuit;
use eth_types::{Field, Hash, ToWord};
use gadgets::binary_number::BinaryNumberChip;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::tables::range_table::RangeTableConfig;
use crate::wasm_circuit::utf8_circuit::circuit::UTF8Chip;
use crate::wasm_circuit::wasm_bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::wasm_bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::wasm_sections::wasm_code_section::wasm_code_section_body::circuit::WasmCodeSectionBodyChip;

#[derive(Default)]
struct TestCircuit<'a, F> {
    code_hash: Hash,
    bytecode: &'a [u8],
    offset_start: usize,
    _marker: PhantomData<F>,
}

#[derive(Clone)]
struct TestCircuitConfig<F: Field> {
    wasm_code_section_body_chip: Rc<WasmCodeSectionBodyChip<F>>,
    wasm_bytecode_table: Rc<WasmBytecodeTable>,
    _marker: PhantomData<F>,
}

impl<'a, F: Field> Circuit<F> for TestCircuit<'a, F> {
    type Config = TestCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self::default() }

    fn configure(
        cs: &mut ConstraintSystem<F>,
    ) -> Self::Config {
        let wasm_bytecode_table = Rc::new(WasmBytecodeTable::construct(cs));

        let leb128_config = LEB128Chip::<F>::configure(
            cs,
            &wasm_bytecode_table.value,
        );
        let leb128_chip = Rc::new(LEB128Chip::construct(leb128_config));

        let wasm_code_section_body_config = WasmCodeSectionBodyChip::configure(
            cs,
            wasm_bytecode_table.clone(),
            leb128_chip.clone(),
        );
        let wasm_code_section_body_chip = WasmCodeSectionBodyChip::construct(wasm_code_section_body_config);
        let test_circuit_config = TestCircuitConfig {
            wasm_code_section_body_chip: Rc::new(wasm_code_section_body_chip),
            wasm_bytecode_table: wasm_bytecode_table.clone(),
            _marker: Default::default(),
        };

        test_circuit_config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let wasm_bytecode = WasmBytecode::new(self.bytecode.to_vec().clone(), self.code_hash.to_word());
        config.wasm_bytecode_table.load(&mut layouter, &wasm_bytecode)?;
        layouter.assign_region(
            || "wasm_code_section_body region",
            |mut region| {
                // config.wasm_code_section_body_chip.config.leb128_chip.assign_init(&mut region, self.bytecode.len() - 1);
                // config.wasm_code_section_body_chip.assign_init(&mut region, self.bytecode.len() - 1);
                config.wasm_code_section_body_chip.assign_auto(
                    &mut region,
                    &wasm_bytecode,
                    self.offset_start,
                ).unwrap();

                Ok(())
            }
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod wasm_code_section_body_tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use log::debug;
    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;
    use crate::wasm_circuit::consts::{ControlInstruction, NumericInstruction, NumType, VariableInstruction};
    use crate::wasm_circuit::wasm_sections::wasm_code_section::test_helpers::{generate_wasm_code_section_body_bytecode, WasmCodeSectionBodyDescriptor, WasmCodeSectionBodyFuncDescriptor, WasmCodeSectionExpressionDescriptor, WasmCodeSectionInstructionTypeDescriptor, WasmCodeSectionLocalDescriptor};
    use crate::wasm_circuit::wasm_sections::wasm_code_section::wasm_code_section_body::tests::TestCircuit;

    fn test<'a, F: Field>(
        test_circuit: TestCircuit<'_, F>,
        is_ok: bool,
    ) {
        let k = 8;
        let prover = MockProver::run(k, &test_circuit, vec![]).unwrap();
        if is_ok {
            prover.assert_satisfied();
        } else {
            assert!(prover.verify().is_err());
        }
    }

    #[test]
    pub fn section_body_bytecode_is_ok() {
        let mut bytecodes: Vec<Vec<u8>> = Vec::new();
        // expected
        // (hex): [2, 1d, 1, 1,  7f, 41, 0, 21, 0, 2, 40, 3, 40, 20, 0,  d, 1, 20, 0, 41,  c0,  c4, 7,  6a, 21, 0,  c, 0,  b,  b,  b,  e, 4, 1,  7f, 1,  7e, 2,  7f, 3,  7e, 41, 0, 21, 0, b]
        // (decimal) = [2, 29, 1, 1, 127, 65, 0, 33, 0, 2, 64, 3, 64, 32, 0, 13, 1, 32, 0, 65, 192, 196, 7, 106, 33, 0, 12, 0, 11, 11, 11, 14, 4, 1, 127, 1, 126, 2, 127, 3, 126, 65, 0, 33, 0, 11].as_slice().to_vec();
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
        debug!("bytecode (len {}) (hex): {:x?}", bytecode.len(), bytecode);
        bytecodes.push(bytecode);
        for bytecode in &bytecodes {
            let code_hash = CodeDB::hash(&bytecode);
            let test_circuit = TestCircuit::<Fr> {
                code_hash,
                bytecode: &bytecode,
                offset_start: 0,
                _marker: Default::default(),
            };
            test(test_circuit, true);
        }
    }
}