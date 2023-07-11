use halo2_proofs::{
    plonk::{ConstraintSystem, Error},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::Circuit;
use eth_types::{Field, Hash, ToWord};
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::sections::r#type::type_body::circuit::WasmTypeSectionBodyChip;
use crate::wasm_circuit::sections::r#type::type_item::circuit::WasmTypeSectionItemChip;
use crate::wasm_circuit::tables::dynamic_indexes::circuit::DynamicIndexesChip;

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
        let wasm_type_section_item_config = WasmTypeSectionItemChip::configure(
            cs,
            wasm_bytecode_table.clone(),
            leb128_chip.clone(),
        );
        let wasm_type_section_item_chip = Rc::new(WasmTypeSectionItemChip::construct(wasm_type_section_item_config));
        let wasm_type_section_body_config = WasmTypeSectionBodyChip::configure(
            cs,
            wasm_bytecode_table.clone(),
            leb128_chip.clone(),
            wasm_type_section_item_chip.clone(),
            dynamic_indexes_chip.clone(),
        );
        let wasm_type_section_body_chip = Rc::new(WasmTypeSectionBodyChip::construct(wasm_type_section_body_config));
        let test_circuit_config = TestCircuitConfig {
            item_chip: wasm_type_section_item_chip.clone(),
            body_chip: wasm_type_section_body_chip.clone(),
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
        let wasm_bytecode = WasmBytecode::new(self.bytecode_bytes.to_vec().clone(), self.code_hash.to_word());
        config.wasm_bytecode_table.load(&mut layouter, &wasm_bytecode)?;
        layouter.assign_region(
            || "wasm_type_section_body region",
            |mut region| {
                let mut dynamic_indexes_offset = 0;
                let mut offset_start = self.offset_start;
                loop {
                    offset_start = config.body_chip.assign_auto(
                        &mut region,
                        &wasm_bytecode,
                        offset_start,
                        &mut dynamic_indexes_offset,
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
mod wasm_type_section_body_tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use log::debug;
    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;
    use crate::wasm_circuit::sections::r#type::test_helpers::generate_type_section_body_bytecode;
    use crate::wasm_circuit::sections::r#type::type_body::tests::TestCircuit;

    fn test<'a, F: Field>(
        test_circuit: TestCircuit<'_, F>,
        is_ok: bool,
    ) {
        let k = 5;
        let prover = MockProver::run(k, &test_circuit, vec![]).unwrap();
        if is_ok {
            prover.assert_satisfied();
        } else {
            assert!(prover.verify().is_err());
        }
    }

    #[test]
    pub fn section_body_bytecode_is_ok() {
        for _ in 0..10 {
            let bytecodes = [
                generate_type_section_body_bytecode(0, 2, 2),
                generate_type_section_body_bytecode(1, 2, 2),
                generate_type_section_body_bytecode(2, 2, 2),
                generate_type_section_body_bytecode(3, 2, 2),
                generate_type_section_body_bytecode(4, 2, 2),
            ];
            for bytecode in bytecodes {
                debug!("type_section_body_bytecode (hex) {:x?}", bytecode);
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
    }
}