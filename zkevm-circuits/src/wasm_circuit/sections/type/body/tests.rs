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
    assign_delta_base: usize,
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
        let wb_table = Rc::new(WasmBytecodeTable::construct(cs, false));
        let func_count = cs.advice_column();
        let error_code = cs.advice_column();
        let body_item_rev_count_lv1 = cs.advice_column();
        let body_item_rev_count_lv2 = cs.advice_column();

        let shared_state = Rc::new(RefCell::new(SharedState::default()));

        let config = DynamicIndexesChip::configure(cs);
        let dynamic_indexes_chip = Rc::new(DynamicIndexesChip::construct(config));

        let leb128_config = LEB128Chip::<F>::configure(cs, &wb_table.value);
        let leb128_chip = Rc::new(LEB128Chip::construct(leb128_config));
        let config = WasmTypeSectionItemChip::configure(
            cs,
            wb_table.clone(),
            leb128_chip.clone(),
            func_count,
            shared_state.clone(),
            body_item_rev_count_lv2,
            error_code,
        );
        let item_chip = Rc::new(WasmTypeSectionItemChip::construct(config));
        let config = WasmTypeSectionBodyChip::configure(
            cs,
            wb_table.clone(),
            leb128_chip.clone(),
            item_chip.clone(),
            dynamic_indexes_chip.clone(),
            func_count,
            shared_state.clone(),
            body_item_rev_count_lv1,
            error_code,
        );
        let body_chip = Rc::new(WasmTypeSectionBodyChip::construct(config));
        let test_circuit_config = TestCircuitConfig {
            item_chip,
            body_chip,
            wb_table,
            _marker: Default::default(),
        };

        test_circuit_config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let assign_delta = self.assign_delta_base;
        let wb = WasmBytecode::new(self.bytecode_bytes.to_vec().clone());
        config.wb_table.load(&mut layouter, &wb, assign_delta)?;
        layouter.assign_region(
            || "wasm_type_section_body region",
            |mut region| {
                config.body_chip.config.shared_state.borrow_mut().reset();
                let assign_delta = self.assign_delta_base;
                let mut wb_offset = 0;
                while wb_offset < wb.bytes.len() {
                    wb_offset = config
                        .body_chip
                        .assign_auto(&mut region, &wb, wb_offset, assign_delta)
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
    use rand::{thread_rng, Rng};
    use wasmbin::sections::Kind;

    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;

    use crate::wasm_circuit::{
        common::wat_extract_section_body_bytecode, sections::r#type::body::tests::TestCircuit,
    };

    fn test<'a, F: Field>(test_circuit: TestCircuit<'_, F>, is_ok: bool, k: u32) {
        let prover = MockProver::run(k, &test_circuit, vec![]).unwrap();
        if is_ok {
            prover.assert_satisfied();
        } else {
            assert!(prover.verify().is_err());
        }
    }

    fn debug_bc(bc: &Vec<u8>) {
        debug!("bytecode (len {}) hex {:x?} bin {:?}", bc.len(), bc, bc);
    }

    #[test]
    pub fn file1_ok() {
        let bytecode = wat_extract_section_body_bytecode("./test_files/cc1.wat", Kind::Type);
        debug_bc(&bytecode);
        let code_hash = CodeDB::hash(&bytecode);
        let test_circuit = TestCircuit::<Fr> {
            code_hash,
            bytecode_bytes: &bytecode,
            ..Default::default()
        };
        test(test_circuit, true, 8);
    }

    #[test]
    pub fn file1_random_assign_delta_ok() {
        let bytecode = wat_extract_section_body_bytecode("./test_files/cc1.wat", Kind::Type);
        debug_bc(&bytecode);
        let code_hash = CodeDB::hash(&bytecode);
        let test_circuit = TestCircuit::<Fr> {
            code_hash,
            bytecode_bytes: &bytecode,
            assign_delta_base: thread_rng().gen_range(5..300),
            ..Default::default()
        };
        test(test_circuit, true, 9);
    }

    #[test]
    pub fn file2_ok() {
        let bytecode = wat_extract_section_body_bytecode("./test_files/cc2.wat", Kind::Type);
        debug_bc(&bytecode);
        let code_hash = CodeDB::hash(&bytecode);
        let test_circuit = TestCircuit::<Fr> {
            code_hash,
            bytecode_bytes: &bytecode,
            ..Default::default()
        };
        test(test_circuit, true, 8);
    }

    #[test]
    pub fn file2_random_assign_delta_ok() {
        let bytecode = wat_extract_section_body_bytecode("./test_files/cc2.wat", Kind::Type);
        debug_bc(&bytecode);
        let code_hash = CodeDB::hash(&bytecode);
        let test_circuit = TestCircuit::<Fr> {
            code_hash,
            bytecode_bytes: &bytecode,
            assign_delta_base: thread_rng().gen_range(5..300),
            ..Default::default()
        };
        test(test_circuit, true, 9);
    }
}
