use halo2_proofs::{
    plonk::{ConstraintSystem, Error},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::Circuit;
use eth_types::{Field, Hash, ToWord};
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::wasm_bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::wasm_bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::wasm_sections::wasm_type_section::wasm_type_section_body::circuit::WasmTypeSectionBodyChip;
use crate::wasm_circuit::wasm_sections::wasm_type_section::wasm_type_section_item::circuit::WasmTypeSectionItemChip;

#[derive(Default)]
struct TestCircuit<'a, F> {
    code_hash: Hash,
    bytecode_bytes: &'a [u8],
    offset_start: usize,
    _marker: PhantomData<F>,
}

#[derive(Clone)]
struct TestCircuitConfig<F> {
    wasm_type_section_item_chip: Rc<WasmTypeSectionItemChip<F>>,
    wasm_type_section_body_chip: Rc<WasmTypeSectionBodyChip<F>>,
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
        let bytes = cs.advice_column();
        let wasm_bytecode_table = WasmBytecodeTable::construct(cs);
        let leb128_config = LEB128Chip::<F>::configure(
            cs,
            &bytes,
        );
        let leb128_chip = Rc::new(LEB128Chip::construct(leb128_config));
        let wasm_type_section_item_config = WasmTypeSectionItemChip::configure(
            cs,
            &wasm_bytecode_table,
            leb128_chip.clone(),
        );
        let wasm_type_section_item_chip = Rc::new(WasmTypeSectionItemChip::construct(wasm_type_section_item_config));
        let wasm_type_section_body_config = WasmTypeSectionBodyChip::configure(
            cs,
            &wasm_bytecode_table,
            leb128_chip.clone(),
            wasm_type_section_item_chip.clone(),
        );
        let wasm_type_section_body_chip = Rc::new(WasmTypeSectionBodyChip::construct(wasm_type_section_body_config));
        let test_circuit_config = TestCircuitConfig {
            wasm_type_section_item_chip: wasm_type_section_item_chip.clone(),
            wasm_type_section_body_chip: wasm_type_section_body_chip.clone(),
            wasm_bytecode_table: Rc::new(wasm_bytecode_table),
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
                config.wasm_type_section_body_chip.assign_init(&mut region, self.bytecode_bytes.len() - 1);
                config.wasm_type_section_body_chip.assign_auto(
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
mod wasm_type_section_body_tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;
    use crate::wasm_circuit::wasm_sections::wasm_type_section::wasm_type_section_body::dev::TestCircuit;

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
    pub fn test_type_section_body_bytecode_is_ok() {
        // type_section_items start at: 1, 4, 7, 12
        let section_body_bytecode = [
            0x4, 0x60, 0, 0, 0x60, 0, 0, 0x60, 0x2, 0x7f, 0x7e, 0, 0x60, 0x2, 0x7e, 0x7f, 0x1, 0x7f
        ];
        let code_hash = CodeDB::hash(&section_body_bytecode);
        let test_circuit = TestCircuit::<Fr> {
            code_hash,
            bytecode_bytes: &section_body_bytecode,
            offset_start: 0,
            _marker: Default::default(),
        };
        test(test_circuit, true);
    }
}