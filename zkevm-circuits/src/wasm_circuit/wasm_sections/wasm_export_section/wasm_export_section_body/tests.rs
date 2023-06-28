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
use crate::wasm_circuit::wasm_sections::wasm_export_section::wasm_export_section_body::circuit::WasmExportSectionBodyChip;

#[derive(Default)]
struct TestCircuit<'a, F> {
    code_hash: Hash,
    bytecode: &'a [u8],
    offset_start: usize,
    _marker: PhantomData<F>,
}

#[derive(Clone)]
struct TestCircuitConfig<F: Field> {
    wasm_export_section_body_chip: Rc<WasmExportSectionBodyChip<F>>,
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

        let wasm_export_section_body_config = WasmExportSectionBodyChip::configure(
            cs,
            wasm_bytecode_table.clone(),
            leb128_chip.clone(),
        );
        let wasm_export_section_body_chip = WasmExportSectionBodyChip::construct(wasm_export_section_body_config);
        let test_circuit_config = TestCircuitConfig {
            wasm_export_section_body_chip: Rc::new(wasm_export_section_body_chip),
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
            || "wasm_export_section_body region",
            |mut region| {
                // config.wasm_export_section_body_chip.config.leb128_chip.assign_init(&mut region, self.bytecode.len() - 1);
                // config.wasm_export_section_body_chip.assign_init(&mut region, self.bytecode.len() - 1);
                config.wasm_export_section_body_chip.assign_auto(
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
mod wasm_export_section_body_tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use log::debug;
    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;
    use crate::wasm_circuit::wasm_sections::wasm_export_section::test_helpers::{generate_wasm_export_section_body_bytecode, WasmExportSectionBodyDescriptor, WasmExportSectionBodyItemDescriptor};
    use crate::wasm_circuit::wasm_sections::wasm_export_section::wasm_export_section_body::consts::ExportDesc;
    use crate::wasm_circuit::wasm_sections::wasm_export_section::wasm_export_section_body::tests::TestCircuit;

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
        // expected (hex): [2, 4, 6d, 61, 69, 6e, 0, 0, 6, 6d, 65, 6d, 6f, 72, 79, 2, 0]
        let descriptor = WasmExportSectionBodyDescriptor {
            items: vec![
                WasmExportSectionBodyItemDescriptor {
                    export_name: "main".to_string(),
                    export_desc_type: ExportDesc::FuncExportDesc,
                    export_desc_val: 0,
                },
                WasmExportSectionBodyItemDescriptor {
                    export_name: "memory".to_string(),
                    export_desc_type: ExportDesc::MemExportDesc,
                    export_desc_val: 0,
                },
            ],
        };
        let bytecode = generate_wasm_export_section_body_bytecode(&descriptor);
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