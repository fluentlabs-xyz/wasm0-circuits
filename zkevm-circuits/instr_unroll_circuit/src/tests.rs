use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{self, ConstraintSystem, Error},
};
use macro_rules_attribute::apply;
use std::marker::PhantomData as Ph;

use super::{Chip, Config};

#[derive(Default)]
struct Circuit<'a, F> {
    bytes: &'a [u8],
    _marker: Ph<F>,
}

impl<'a, F: Field> plonk::Circuit<F> for Circuit<'a, F> {
    type Config = Config<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let config = Chip::<F>::configure(meta);
        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = Chip::construct(config);
        Ok(())
    }
}

fn test<'a, F: Field>(circuit: Circuit<'_, F>, is_ok: bool) {
    let k = 5;
    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    if is_ok {
        prover.assert_satisfied();
    } else {
        assert!(prover.verify().is_err());
    }
}

#[test]
fn draft_test() {
    let circuit = Circuit::<Fr> {
        bytes: &[],
        _marker: Ph,
    };
    test(circuit, true);
}
