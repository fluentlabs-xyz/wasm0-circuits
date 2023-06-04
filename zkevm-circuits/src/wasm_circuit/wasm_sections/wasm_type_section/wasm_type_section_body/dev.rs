use halo2_proofs::{
    plonk::{ConstraintSystem, Error},
};
use std::{marker::PhantomData};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column};
use halo2_proofs::poly::Rotation;
use eth_types::Field;
use crate::wasm_circuit::leb128_circuit::circuit::{LEB128Chip, LEB128Config};

#[derive(Default)]
struct TestCircuit<'a, F, const LEB_BYTES_N: usize, const IS_SIGNED: bool> {
    leb_base64_words: &'a [u64],
    leb_bytes: &'a [u8],
    leb_bytes_last_byte_index: u64,
    is_negative: bool,
    solid_number: u64,
    _marker: PhantomData<F>,
}

#[derive(Clone)]
struct TestCircuitConfig<F, const LEB_BYTES_N: usize, const IS_SIGNED: bool> {
    solid_number: Column<Advice>,
    leb_bytes: Column<Advice>,
    leb128_config: LEB128Config<F>,
    _marker: PhantomData<F>,
}

impl<'a, F: Field, const LEB_BYTES_N: usize, const IS_SIGNED: bool> Circuit<F> for TestCircuit<'a, F, LEB_BYTES_N, IS_SIGNED> {
    type Config = TestCircuitConfig<F, LEB_BYTES_N, IS_SIGNED>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self::default() }

    fn configure(
        cs: &mut ConstraintSystem<F>,
    ) -> Self::Config {
        let solid_number = cs.advice_column();
        let leb_bytes = cs.advice_column();
        let leb128_config = LEB128Chip::<F>::configure(
            cs,
            |vc| vc.query_advice(solid_number, Rotation::cur()),
            IS_SIGNED,
            &leb_bytes,
            LEB_BYTES_N,
        );
        let test_circuit_config = TestCircuitConfig {
            solid_number,
            leb_bytes,
            leb128_config,
            _marker: Default::default(),
        };

        test_circuit_config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let leb128_number_chip = LEB128Chip::construct(config.leb128_config);

        layouter.assign_region(
            || "leb128 region",
            |mut region| {
                for i in 0..self.leb_bytes.len() {
                    let mut val = 0 as u64;
                    val = self.solid_number;
                    region.assign_advice(
                        || format!("assign solid_number is_negative {} val {} at {}", self.is_negative, val, i),
                        config.solid_number,
                        i,
                        || Value::known(if self.is_negative { F::from(val).neg() } else { F::from(val) }),
                    )?;
                }

                for (i, &leb_byte) in self.leb_bytes.iter().enumerate() {
                    region.assign_advice(
                        || format!("assign leb_byte val {} at {}", leb_byte, i),
                        config.leb_bytes,
                        i,
                        || Value::known(F::from(leb_byte as u64)),
                    ).unwrap();
                    let leb_base64_word = if i < self.leb_base64_words.len() { self.leb_base64_words[i] } else { 0 };
                    leb128_number_chip.assign(
                        &mut region,
                        i,
                        // self.leb_bytes[i] as u64,
                        i == 0,
                        i < (self.leb_bytes_last_byte_index as usize),
                        leb_base64_word,
                    );
                }

                Ok(())
            }
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod leb128_circuit_tests {
    use std::env;
    use std::marker::PhantomData;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use rand::Rng;
    use eth_types::Field;

    fn rust_log_is_debug() -> bool {
        env::var("RUST_LOG").unwrap_or("".to_string()) == "debug"
    }

    fn test<'a, F: Field, const LEB_BYTES_N: usize, const IS_SIGNED: bool>(
        test_circuit: TestCircuit<'_, F, LEB_BYTES_N, IS_SIGNED>,
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
    pub fn test_debug_exact_number_unsigned() {
        exact_number::<1, { IS_SIGNED }>(0);
        exact_number::<1, { IS_SIGNED }>(1);
        exact_number::<1, { IS_SIGNED }>(32);
        exact_number::<2, { IS_SIGNED }>(16382);
        exact_number::<2, { IS_SIGNED }>(16383);
        exact_number::<3, { IS_SIGNED }>(123456);
        exact_number::<4, { IS_SIGNED }>(123456789);
    }
}