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
use crate::wasm_circuit::wasm_sections::wasm_import_section::wasm_import_section_body::circuit::WasmImportSectionBodyChip;

#[derive(Default)]
struct TestCircuit<'a, F> {
    code_hash: Hash,
    bytecode: &'a [u8],
    offset_start: usize,
    _marker: PhantomData<F>,
}

#[derive(Clone)]
struct TestCircuitConfig<F: Field> {
    wasm_import_section_body_chip: Rc<WasmImportSectionBodyChip<F>>,
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
            wasm_import_section_body_chip: Rc::new(wasm_import_section_body_chip),
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
                config.wasm_import_section_body_chip.config.leb128_chip.assign_init(&mut region, self.bytecode.len() - 1);
                config.wasm_import_section_body_chip.assign_init(&mut region, self.bytecode.len() - 1);
                config.wasm_import_section_body_chip.assign_auto(
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
mod wasm_import_section_body_tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use log::debug;
    use rand::Rng;
    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;
    use crate::wasm_circuit::wasm_sections::consts::NumType;
    use crate::wasm_circuit::wasm_sections::wasm_import_section::test_helpers::{generate_import_section_body_bytecode, ImportDesc, ImportSectionBodyDescriptor, ImportSectionBodyItemDescriptor};
    use crate::wasm_circuit::wasm_sections::wasm_import_section::wasm_import_section_body::consts::ImportDescType;
    use crate::wasm_circuit::wasm_sections::wasm_import_section::wasm_import_section_body::tests::TestCircuit;

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
    pub fn import_section_body_bytecode_is_ok() {
        let mut bytecodes: Vec<Vec<u8>> = Vec::new();
        // taken from src/wasm_circuit/test_data/files/br_breaks_1.wat
        // expected (hex): [3, 3, 65, 6e, 76, c, 5f, 65, 76, 6d, 5f, 61, 64, 64, 72, 65, 73, 73, 0, 2, 3, 65, 6e, 76, c, 5f, 65, 76, 6d, 5f, 62, 61, 6c, 61, 6e, 63, 65, 0, 3, 3, 65, 6e, 76, a4, 1, 5f, 65, 76, 6d, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 0, 5];
        let descriptor = ImportSectionBodyDescriptor {
            items: vec![
                ImportSectionBodyItemDescriptor {
                    mod_name: "env".to_string(),
                    import_name: "_evm_address".to_string(),
                    import_desc: ImportDesc { val_type: ImportDescType::TypeImportDescType, val: 2, },
                },
                ImportSectionBodyItemDescriptor {
                    mod_name: "env".to_string(),
                    import_name: "_evm_balance".to_string(),
                    import_desc: ImportDesc { val_type: ImportDescType::TypeImportDescType, val: 3, },
                },
                ImportSectionBodyItemDescriptor {
                    mod_name: "env".to_string(),
                    import_name: "_evm_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func".to_string(),
                    import_desc: ImportDesc { val_type: ImportDescType::TypeImportDescType, val: 5, },
                },
            ],
        };
        let bytecode = generate_import_section_body_bytecode(&descriptor);
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