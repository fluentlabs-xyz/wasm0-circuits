use std::marker::PhantomData;
use std::rc::Rc;

use halo2_proofs::{
    plonk::{ConstraintSystem, Error},
};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::Circuit;

use eth_types::{Field, Hash, ToWord};

use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::sections::table::table_body::circuit::WasmTableSectionBodyChip;
use crate::wasm_circuit::tables::dynamic_indexes::circuit::DynamicIndexesChip;
use crate::wasm_circuit::types::SharedState;

#[derive(Default)]
struct TestCircuit<'a, F> {
    code_hash: Hash,
    bytecode: &'a [u8],
    offset_start: usize,
    _marker: PhantomData<F>,
}

#[derive(Clone)]
struct TestCircuitConfig<F: Field> {
    body_chip: Rc<WasmTableSectionBodyChip<F>>,
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

        let config = DynamicIndexesChip::configure(cs);
        let dynamic_indexes_chip = Rc::new(DynamicIndexesChip::construct(config));

        let leb128_config = LEB128Chip::<F>::configure(
            cs,
            &wasm_bytecode_table.value,
        );
        let leb128_chip = Rc::new(LEB128Chip::construct(leb128_config));

        let wasm_table_section_body_config = WasmTableSectionBodyChip::configure(
            cs,
            wasm_bytecode_table.clone(),
            leb128_chip.clone(),
            dynamic_indexes_chip.clone(),
        );
        let wasm_table_section_body_chip = Rc::new(WasmTableSectionBodyChip::construct(wasm_table_section_body_config));

        let test_circuit_config = TestCircuitConfig {
            body_chip: wasm_table_section_body_chip,
            wasm_bytecode_table,
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
            || "wasm_table_section_body region",
            |mut region| {
                let mut shared_state = SharedState::default();
                let mut offset_start = self.offset_start;
                while offset_start < wasm_bytecode.bytes.len() {
                    offset_start = config.body_chip.assign_auto(
                        &mut region,
                        &wasm_bytecode,
                        offset_start,
                        &mut shared_state,
                    ).unwrap();
                }

                Ok(())
            }
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod wasm_table_section_body_tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use log::debug;
    use wasmbin::sections::Kind;

    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;

    use crate::wasm_circuit::common::wat_extract_section_body_bytecode;
    use crate::wasm_circuit::sections::table::table_body::tests::TestCircuit;

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
    pub fn file1_ok() {
        let path_to_file = "./src/wasm_circuit/test_data/files/cc1.wat";
        let kind = Kind::Table;
        let bytecode = wat_extract_section_body_bytecode(path_to_file, kind, );
        debug!("bytecode (len {}) hex {:x?} bin {:?}", bytecode.len(), bytecode, bytecode);
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
    pub fn file2_ok() {
        let path_to_file = "./src/wasm_circuit/test_data/files/cc2.wat";
        let kind = Kind::Table;
        let bytecode = wat_extract_section_body_bytecode(path_to_file, kind, );
        debug!("bytecode (len {}) hex {:x?} bin {:?}", bytecode.len(), bytecode, bytecode);
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