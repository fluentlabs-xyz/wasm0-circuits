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
use crate::wasm_circuit::wasm_sections::wasm_data_section::wasm_data_section_body::circuit::WasmDataSectionBodyChip;

#[derive(Default)]
struct TestCircuit<'a, F> {
    code_hash: Hash,
    bytecode: &'a [u8],
    offset_start: usize,
    _marker: PhantomData<F>,
}

#[derive(Clone)]
struct TestCircuitConfig<F: Field> {
    wasm_data_section_body_chip: Rc<WasmDataSectionBodyChip<F>>,
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

        let wasm_data_section_body_config = WasmDataSectionBodyChip::configure(
            cs,
            wasm_bytecode_table.clone(),
            leb128_chip.clone(),
        );
        let wasm_data_section_body_chip = WasmDataSectionBodyChip::construct(wasm_data_section_body_config);
        let test_circuit_config = TestCircuitConfig {
            wasm_data_section_body_chip: Rc::new(wasm_data_section_body_chip),
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
            || "wasm_data_section_body region",
            |mut region| {
                config.wasm_data_section_body_chip.config.leb128_chip.assign_init(&mut region, self.bytecode.len() - 1);
                config.wasm_data_section_body_chip.assign_init(&mut region, self.bytecode.len() - 1);
                config.wasm_data_section_body_chip.assign_auto(
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
mod wasm_data_section_body_tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use log::debug;
    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;
    use crate::wasm_circuit::consts::MemSegmentType;
    use crate::wasm_circuit::wasm_sections::wasm_data_section::test_helpers::{generate_wasm_data_section_body_bytecode, WasmDataSectionBodyDescriptor, WasmDataSectionBodyItemDescriptor};
    use crate::wasm_circuit::wasm_sections::wasm_data_section::wasm_data_section_body::tests::TestCircuit;

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
        // raw (hex): [2, 0, 41, ff, ff, 3f, b, 4, 6e, 6f, 6e, 65, 0, 41, 80, 80, c0, 0, b, a0, 1, 0, 61, 73, 6d, 1, 0, 0, 0, 1, 9, 2, 60, 2, 7f, 7f, 0, 60, 0, 0, 2, 13, 1, 3, 65, 6e, 76, b, 5f, 65, 76, 6d, 5f, 72, 65, 74, 75, 72, 6e, 0, 0, 3, 2, 1, 1, 5, 3, 1, 0, 11, 6, 19, 3, 7f, 1, 41, 80, 80, c0, 0, b, 7f, 0, 41, 8c, 80, c0, 0, b, 7f, 0, 41, 90, 80, c0, 0, b, 7, 2c, 4, 6, 6d, 65, 6d, 6f, 72, 79, 2, 0, 4, 6d, 61, 69, 6e, 0, 1, a, 5f, 5f, 64, 61, 74, 61, 5f, 65, 6e, 64, 3, 1, b, 5f, 5f, 68, 65, 61, 70, 5f, 62, 61, 73, 65, 3, 2, a, d, 1, b, 0, 41, 80, 80, c0, 0, 41, c, 10, 0, b, b, 15, 1, 0, 41, 80, 80, c0, 0, b, c, 48, 65, 6c, 6c, 6f, 2c, 20, 57, 6f, 72, 6c, 64]
        let descriptor = WasmDataSectionBodyDescriptor {
            items: vec![
                WasmDataSectionBodyItemDescriptor {
                    mem_segment_type: MemSegmentType::ActiveZero,
                    mem_segment_size: 1048575,
                    mem_segment_bytes: "none".as_bytes().to_vec(),
                },
                WasmDataSectionBodyItemDescriptor {
                    mem_segment_type: MemSegmentType::ActiveZero,
                    mem_segment_size: 1048576,
                    mem_segment_bytes: vec![0, 97, 115, 109, 1, 0, 0, 0, 1, 9, 2, 96, 2, 127, 127, 0, 96, 0, 0, 2, 19, 1, 3, 101, 110, 118, 11, 95, 101, 118, 109, 95, 114, 101, 116, 117, 114, 110, 0, 0, 3, 2, 1, 1, 5, 3, 1, 0, 17, 6, 25, 3, 127, 1, 65, 128, 128, 192, 0, 11, 127, 0, 65, 140, 128, 192, 0, 11, 127, 0, 65, 144, 128, 192, 0, 11, 7, 44, 4, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97, 105, 110, 0, 1, 10, 95, 95, 100, 97, 116, 97, 95, 101, 110, 100, 3, 1, 11, 95, 95, 104, 101, 97, 112, 95, 98, 97, 115, 101, 3, 2, 10, 13, 1, 11, 0, 65, 128, 128, 192, 0, 65, 12, 16, 0, 11, 11, 21, 1, 0, 65, 128, 128, 192, 0, 11, 12, 72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100],
                },
            ],
        };
        let bytecode = generate_wasm_data_section_body_bytecode(&descriptor);
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