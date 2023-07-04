use halo2_proofs::{
    plonk::{ConstraintSystem, Error},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::Circuit;
use eth_types::{Field, Hash, ToWord};
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::tables::range_table::RangeTableConfig;
use crate::wasm_circuit::utf8_circuit::circuit::UTF8Chip;
use crate::wasm_circuit::wasm_bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::wasm_bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::wasm_sections::wasm_element_section::wasm_element_section_body::circuit::WasmElementSectionBodyChip;

#[derive(Default)]
struct TestCircuit<'a, F> {
    code_hash: Hash,
    bytecode: &'a [u8],
    offset_start: usize,
    _marker: PhantomData<F>,
}

#[derive(Clone)]
struct TestCircuitConfig<F: Field> {
    wasm_element_section_body_chip: Rc<WasmElementSectionBodyChip<F>>,
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

        let wasm_element_section_body_config = WasmElementSectionBodyChip::configure(
            cs,
            wasm_bytecode_table.clone(),
            leb128_chip.clone(),
        );
        let wasm_element_section_body_chip = WasmElementSectionBodyChip::construct(wasm_element_section_body_config);
        let test_circuit_config = TestCircuitConfig {
            wasm_element_section_body_chip: Rc::new(wasm_element_section_body_chip),
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
            || "wasm_element_section_body region",
            |mut region| {
                config.wasm_element_section_body_chip.assign_auto(
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
mod wasm_element_section_body_tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use log::debug;
    use wasmbin::sections::Kind;
    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;
    use crate::wasm_circuit::common::{wat_extract_section_body_bytecode, wat_extract_section_bytecode};
    use crate::wasm_circuit::consts::MemSegmentType;
    use crate::wasm_circuit::wasm_sections::wasm_element_section::wasm_element_section_body::tests::TestCircuit;

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
        let path_to_file = "./src/wasm_circuit/test_data/files/block_loop_local_vars.wat";
        let kind = Kind::Element;
        // expected
        // raw (hex): [9, 35, 7, 1, 0, 0, 1, 0, 0, 1, 0, 3, 0, 0, 1, 1, 0, 4, 0, 0, 1, 1, 1, 0, 0, 0, 65, 0, 11, 0, 0, 65, 171, 2, 11, 1, 0, ]
        let expected = [
            9, 35, 7, 1, 0, 0, 1, 0, 0, 1, 0, 3, 0, 0, 1, 1, 0, 4, 0, 0, 1, 1, 1, 0, 0, 0, 65, 0, 11, 0, 0, 65, 171, 2, 11, 1, 0,
        ].as_slice().to_vec();
        debug!("expected {:?}", expected);
        debug!("expected (hex) {:x?}", expected);

        let section_bytecode = wat_extract_section_bytecode(path_to_file, kind, );
        debug!("section_bytecode {:?}", section_bytecode);
        debug!("section_bytecode (hex) {:x?}", section_bytecode);
        // assert_eq!(expected, section_bytecode);

        // source WAT:
        // (elem funcref)
        // (elem func)
        // (elem func $f $f $g $g)
        // (elem $t funcref)

        // items_count+ -> elem+(elem_type(1) -> elem_body+)
        // elem_body+(elem_type(1)==0 -> numeric_instruction(1) -> numeric_instruction_leb_arg+ -> numeric_instruction_block_end+ -> funcs_idx_count+ -> func_idxs+)
        // elem_body+(elem_type(1)==1 -> elem_kind(1) -> funcs_idx_count+ -> func_idxs+)
        // expected body
        // raw (hex): [
        // 7,
        // 1, 0, 0, - (elem funcref)
        // 1, 0, 0, - (elem func)
        // 1, 0, 3, 0, 0, 1, - (elem func $f $f $g)
        // 1, 0, 4, 0, 0, 1, 1, - (elem func $f $f $g $g)
        // 1, 0, 0, - (elem $t funcref)
        // 0, 41, 0, b, 0, - (elem (i32.const 0))
        // 0, 41, 9, b, 1, 0, - (elem (i32.const 9) $f)
        // ]
        // raw (hex): [7, 1, 0, 0, 1, 0, 0, 1, 0, 3, 0, 0, 1, 1, 0, 4, 0, 0, 1, 1, 1, 0, 0, 0, 41, 0, b, 0, 0, 41, 9, b, 1, 0, ]
        let expected = [
            7, 1, 0, 0, 1, 0, 0, 1, 0, 3, 0, 0, 1, 1, 0, 4, 0, 0, 1, 1, 1, 0, 0, 0, 65, 0, 11, 0, 0, 65, 171, 2, 11, 1, 0,
        ].as_slice().to_vec();
        let section_body_bytecode = wat_extract_section_body_bytecode(path_to_file, kind, );
        assert_eq!(expected, section_body_bytecode);

        debug!("section_body_bytecode (len {}) (hex): {:x?}", section_body_bytecode.len(), section_body_bytecode);
        let code_hash = CodeDB::hash(&section_body_bytecode);
        let test_circuit = TestCircuit::<Fr> {
            code_hash,
            bytecode: &section_body_bytecode,
            offset_start: 0,
            _marker: Default::default(),
        };
        test(test_circuit, true);
    }
}