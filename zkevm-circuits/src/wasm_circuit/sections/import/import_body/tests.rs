use halo2_proofs::{
    plonk::{ConstraintSystem, Error},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::Circuit;
use eth_types::{Field, Hash, ToWord};
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::utf8_circuit::circuit::UTF8Chip;
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::sections::import::import_body::circuit::WasmImportSectionBodyChip;
use crate::wasm_circuit::tables::fixed_range::config::RangeTableConfig;

#[derive(Default)]
struct TestCircuit<'a, F> {
    code_hash: Hash,
    bytecode: &'a [u8],
    offset_start: usize,
    _marker: PhantomData<F>,
}

#[derive(Clone)]
struct TestCircuitConfig<F: Field> {
    body_chip: Rc<WasmImportSectionBodyChip<F>>,
    wasm_bytecode_table: Rc<WasmBytecodeTable>,
    range_table_config_0_128: Rc<RangeTableConfig<F, 0, 128>>,
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

        let range_table_config_0_128 = Rc::new(RangeTableConfig::configure(cs));

        let leb128_config = LEB128Chip::<F>::configure(
            cs,
            &wasm_bytecode_table.value,
        );
        let leb128_chip = Rc::new(LEB128Chip::construct(leb128_config));

        let utf8_config = UTF8Chip::<F>::configure(
            cs,
            range_table_config_0_128.clone(),
            &wasm_bytecode_table.value,
        );
        let utf8_chip = Rc::new(UTF8Chip::construct(utf8_config));

        let wasm_import_section_body_config = WasmImportSectionBodyChip::configure(
            cs,
            wasm_bytecode_table.clone(),
            leb128_chip.clone(),
            utf8_chip.clone(),
        );
        let wasm_import_section_body_chip = WasmImportSectionBodyChip::construct(wasm_import_section_body_config);
        let test_circuit_config = TestCircuitConfig {
            body_chip: Rc::new(wasm_import_section_body_chip),
            wasm_bytecode_table: wasm_bytecode_table.clone(),
            range_table_config_0_128: range_table_config_0_128.clone(),
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
        config.range_table_config_0_128.load(&mut layouter)?;
        layouter.assign_region(
            || "wasm_import_section_body region",
            |mut region| {
                let mut offset_start = self.offset_start;
                loop {
                    offset_start = config.body_chip.assign_auto(
                        &mut region,
                        &wasm_bytecode,
                        offset_start,
                    ).unwrap();
                    if offset_start > wasm_bytecode.bytes.len() - 1 { break }
                }

                Ok(())
            }
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod wasm_import_section_body_tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use log::debug;
    use rand::Rng;
    use wasmbin::sections::Kind;
    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;
    use crate::wasm_circuit::common::wat_extract_section_body_bytecode;
    use crate::wasm_circuit::sections::import::import_body::tests::TestCircuit;

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
    pub fn section_body_bytecode_from_file1() {
        // [1, - IsItemsCount
        // 2, - mod_name_len=2
        // 6a, 73, - 'js'
        // 6, - mod_name_len=6
        // 67, 6c, 6f, 62, 61, 6c, - 'global'
        // 3, 7f, 1 - globaltype i32 mut
        // ]
        // 'env' in hex [65, 6e, 76] in decimal [101, 110, 118]
        // 'global' in hex [67, 6c, 6f, 62, 61, 6c] in decimal [103, 108, 111, 98, 97, 108]
        let bytecode = wat_extract_section_body_bytecode(
            "./src/wasm_circuit/test_data/files/block_loop_local_vars.wat",
            Kind::Import,
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
    pub fn section_body_bytecode_from_file2() {
        let bytecode = wat_extract_section_body_bytecode(
            "./src/wasm_circuit/test_data/files/br_breaks_1.wat",
            Kind::Import,
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