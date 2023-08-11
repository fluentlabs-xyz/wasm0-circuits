use halo2_proofs::{
    plonk::{ConstraintSystem, Error},
};
use std::{marker::PhantomData};
use std::cell::RefCell;
use std::rc::Rc;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Circuit, Column, Expression, Fixed};
use halo2_proofs::poly::Rotation;
use eth_types::{Field, Hash, ToWord};
use gadgets::util::Expr;
use crate::evm_circuit::util::constraint_builder::BaseConstraintBuilder;
use crate::wasm_circuit::leb128::circuit::LEB128Chip;
use crate::wasm_circuit::utf8::circuit::UTF8Chip;
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::sections::data::body::circuit::WasmDataSectionBodyChip;
use crate::wasm_circuit::tables::dynamic_indexes::circuit::DynamicIndexesChip;
use crate::wasm_circuit::tables::dynamic_indexes::types::{LookupArgsParams, Tag};

#[derive(Default)]
struct TestCircuit<F> {
    len: usize,
    tag: Tag,
    _marker: PhantomData<F>,
}

#[derive(Clone)]
struct TestCircuitConfig<F: Field> {
    chip: Rc<DynamicIndexesChip<F>>,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for TestCircuit<F> {
    type Config = TestCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self::default() }

    fn configure(
        cs: &mut ConstraintSystem<F>,
    ) -> Self::Config {
        let config = DynamicIndexesChip::configure(cs, );
        let chip = DynamicIndexesChip::construct(config);

        let test_circuit_config = TestCircuitConfig {
            chip: Rc::new(chip),
            _marker: Default::default(),
        };

        test_circuit_config.chip.lookup_args(
            "start section func index lookup test not_terminator",
            cs,
            |vc| LookupArgsParams {
                cond: 1.expr(),
                index: 1.expr(),
                tag: Tag::FuncIndex.expr(),
                is_terminator: false.expr(),
            }
        );
        test_circuit_config.chip.lookup_args(
            "start section func index lookup test not_terminator",
            cs,
            |vc| LookupArgsParams {
                cond: 1.expr(),
                index: 5.expr(),
                tag: Tag::FuncIndex.expr(),
                is_terminator: true.expr(),
            }
        );

        test_circuit_config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "wasm_data_section_body region",
            |mut region| {
                let mut offset = 0;
                offset = config.chip.assign_auto(
                    &mut region,
                    offset,
                    self.len,
                    self.tag,
                ).unwrap();

                Ok(())
            }
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod dynamic_indexes_tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use log::debug;
    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;
    use crate::wasm_circuit::tables::dynamic_indexes::tests::TestCircuit;
    use crate::wasm_circuit::tables::dynamic_indexes::types::Tag;

    fn test<'a, F: Field>(
        test_circuit: TestCircuit<F>,
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
    pub fn ok() {
        let test_circuit = TestCircuit::<Fr> {
            len: 5,
            tag: Tag::FuncIndex,
            _marker: Default::default(),
        };
        test(test_circuit, true);
    }
}