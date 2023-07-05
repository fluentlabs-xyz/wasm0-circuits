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

// https://webassembly.github.io/spec/core/binary/modules.html#code-section
// example (hex, first two bytes are section_id(10=0xA) and section_leb_len):
// is_funcs_count+ -> func+(is_func_body_len+ -> locals{1}(is_local_type_transitions_count+ -> local_var_descriptor+(is_local_repetition_count+ -> is_local_type{1})) -> is_func_body_code+)
//
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
//     41, 0, - func_body: i32.const 0
//     21, 0, - func_body: local.set 0
// b - func end
// ]
// raw (decimal): [10, 46, 2, 29, 1, 1, 127, 65, 0, 33, 0, 2, 64, 3, 64, 32, 0, 13, 1, 32, 0, 65, 192, 196, 7, 106, 33, 0, 12, 0, 11, 11, 11, 14, 4, 1, 127, 1, 126, 2, 127, 3, 126, 65, 0, 33, 0, 11]

#[cfg(test)]
mod wasm_code_section_body_tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use log::debug;
    use wasmbin::sections::Kind;
    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;
    use crate::wasm_circuit::common::wat_extract_section_body_bytecode;
    use crate::wasm_circuit::consts::{ControlInstruction, NumericInstruction, NumType, VariableInstruction};
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
    pub fn section_body_bytecode_file1_is_ok() {
        // expected (hex): [3, 1d, 1, 1, 7f, 41, 0, 21, 0, 2, 40, 3, 40, 20, 0, d, 1, 20, 0, 41, c0, c4, 7, 6a, 21, 0, c, 0, b, b, b, e, 4, 1, 7f, 1, 7e, 2, 7f, 3, 7e, 41, 0, 21, 0, b, 7, 1, 1, 7f, 41, 0, 1a, b]
        let bytecode = wat_extract_section_body_bytecode(
            "./src/wasm_circuit/test_data/files/block_loop_local_vars.wat",
            Kind::Code,
        );
        debug!("bytecode (len {}) (hex): {:x?}", bytecode.len(), bytecode);
        let code_hash = CodeDB::hash(&bytecode);
        let test_circuit = TestCircuit::<Fr> {
            code_hash,
            bytecode: &bytecode,
            offset_start: 0,
            _marker: Default::default(),
        };
        test(test_circuit, true);
    }

    #[test]
    pub fn section_body_bytecode_file2_is_ok() {
        let bytecode = wat_extract_section_body_bytecode(
            "./src/wasm_circuit/test_data/files/br_breaks_1.wat",
            Kind::Code,
        );
        debug!("bytecode (len {}) (hex): {:x?}", bytecode.len(), bytecode);
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