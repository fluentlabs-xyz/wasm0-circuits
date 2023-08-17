use std::{cell::RefCell, marker::PhantomData, rc::Rc};

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};

use eth_types::{Field, Hash, ToWord};

use crate::wasm_circuit::{
    bytecode::{bytecode::WasmBytecode, bytecode_table::WasmBytecodeTable},
    leb128::circuit::LEB128Chip,
    sections::r#type::{
        body::circuit::WasmTypeSectionBodyChip, item::circuit::WasmTypeSectionItemChip,
    },
    tables::dynamic_indexes::circuit::DynamicIndexesChip,
    types::SharedState,
};

#[derive(Default)]
struct TestCircuit<'a, F> {
    code_hash: Hash,
    bytecode_bytes: &'a [u8],
    offset_start: usize,
    _marker: PhantomData<F>,
}

#[derive(Clone)]
struct TestCircuitConfig<F> {
    item_chip: Rc<WasmTypeSectionItemChip<F>>,
    body_chip: Rc<WasmTypeSectionBodyChip<F>>,
    wb_table: Rc<WasmBytecodeTable>,
    _marker: PhantomData<F>,
}

impl<'a, F: Field> Circuit<F> for TestCircuit<'a, F> {
    type Config = TestCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        let wb_table = Rc::new(WasmBytecodeTable::construct(cs));
        let func_count = cs.advice_column();
        let error_code = cs.advice_column();
        let body_item_rev_count_lv1 = cs.advice_column();
        let body_item_rev_count_lv2 = cs.advice_column();

        let shared_state = Rc::new(RefCell::new(SharedState::default()));

        let config = DynamicIndexesChip::configure(cs);
        let dynamic_indexes_chip = Rc::new(DynamicIndexesChip::construct(config));

        let leb128_config = LEB128Chip::<F>::configure(cs, &wb_table.value);
        let leb128_chip = Rc::new(LEB128Chip::construct(leb128_config));
        let wasm_type_section_item_config = WasmTypeSectionItemChip::configure(
            cs,
            wb_table.clone(),
            leb128_chip.clone(),
            func_count,
            shared_state.clone(),
            body_item_rev_count_lv2,
            error_code,
        );
        let wasm_type_section_item_chip = Rc::new(WasmTypeSectionItemChip::construct(
            wasm_type_section_item_config,
        ));
        let wasm_type_section_body_config = WasmTypeSectionBodyChip::configure(
            cs,
            wb_table.clone(),
            leb128_chip.clone(),
            wasm_type_section_item_chip.clone(),
            dynamic_indexes_chip.clone(),
            func_count,
            shared_state.clone(),
            body_item_rev_count_lv1,
            error_code,
        );
        let wasm_type_section_body_chip = Rc::new(WasmTypeSectionBodyChip::construct(
            wasm_type_section_body_config,
        ));
        let test_circuit_config = TestCircuitConfig {
            item_chip: wasm_type_section_item_chip.clone(),
            body_chip: wasm_type_section_body_chip.clone(),
            wb_table: wb_table.clone(),
            _marker: Default::default(),
        };

        test_circuit_config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let wb = WasmBytecode::new(
            self.bytecode_bytes.to_vec().clone(),
            self.code_hash.to_word(),
        );
        config.wb_table.load(&mut layouter, &wb)?;
        layouter.assign_region(
            || "wasm_type_section_body region",
            |mut region| {
                let mut offset_start = self.offset_start;
                while offset_start < wb.bytes.len() {
                    offset_start = config
                        .body_chip
                        .assign_auto(&mut region, &wb, offset_start, 0)
                        .unwrap();
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod wasm_type_section_body_tests {
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use log::debug;
    use wasmbin::sections::Kind;

    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;

    use crate::wasm_circuit::{
        common::wat_extract_section_body_bytecode, sections::r#type::body::tests::TestCircuit,
    };

    fn test<'a, F: Field>(test_circuit: TestCircuit<'_, F>, is_ok: bool) {
        let k = 6;
        let prover = MockProver::run(k, &test_circuit, vec![]).unwrap();
        if is_ok {
            prover.assert_satisfied();
        } else {
            assert!(prover.verify().is_err());
        }
    }

    #[test]
    pub fn file1_ok() {
        let bytecode = wat_extract_section_body_bytecode("./test_files/cc1.wat", Kind::Type);
        debug!(
            "bytecode (len {}) hex {:x?} bin {:?}",
            bytecode.len(),
            bytecode,
            bytecode
        );
        let code_hash = CodeDB::hash(&bytecode);
        let test_circuit = TestCircuit::<Fr> {
            code_hash,
            bytecode_bytes: &bytecode,
            offset_start: 0,
            _marker: Default::default(),
        };
        test(test_circuit, true);
    }

    #[test]
    pub fn file2_ok() {
        let bytecode = wat_extract_section_body_bytecode("./test_files/cc2.wat", Kind::Type);
        debug!(
            "bytecode (len {}) hex {:x?} bin {:?}",
            bytecode.len(),
            bytecode,
            bytecode
        );
        let code_hash = CodeDB::hash(&bytecode);
        let test_circuit = TestCircuit::<Fr> {
            code_hash,
            bytecode_bytes: &bytecode,
            offset_start: 0,
            _marker: Default::default(),
        };
        test(test_circuit, true);
    }
}
