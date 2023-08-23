use std::{cell::RefCell, marker::PhantomData, rc::Rc};

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};

use eth_types::{Field, ToWord};
use gadgets::util::Expr;

use crate::wasm_circuit::tables::dynamic_indexes::{
    circuit::DynamicIndexesChip,
    types::{LookupArgsParams, Tag},
};

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

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        let shared_state = Rc::new(RefCell::new(Default::default()));
        let config = DynamicIndexesChip::configure(cs, shared_state.clone());
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
                bytecode_number: 1.expr(),
                index: 1.expr(),
                tag: Tag::FuncIndex.expr(),
                is_terminator: false.expr(),
            },
        );
        test_circuit_config.chip.lookup_args(
            "start section func index lookup test not_terminator",
            cs,
            |vc| LookupArgsParams {
                cond: 1.expr(),
                bytecode_number: 1.expr(),
                index: 5.expr(),
                tag: Tag::FuncIndex.expr(),
                is_terminator: true.expr(),
            },
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
                config.chip.config.shared_state.borrow_mut().reset();
                let mut offset = 0;
                offset = config
                    .chip
                    .assign_auto(&mut region, offset, 0, self.len, self.tag)
                    .unwrap();

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod dynamic_indexes_tests {
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};

    use eth_types::Field;

    use crate::wasm_circuit::tables::dynamic_indexes::{tests::TestCircuit, types::Tag};

    fn test<'a, F: Field>(test_circuit: TestCircuit<F>, is_ok: bool) {
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
