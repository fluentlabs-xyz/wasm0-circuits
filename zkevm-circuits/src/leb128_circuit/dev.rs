use halo2_proofs::{
    plonk::{ConstraintSystem, Error},
};
use std::{marker::PhantomData};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::{Circuit};
use eth_types::Field;
use crate::leb128_circuit::circuit::{LEB128NumberChip, LEB128NumberConfig};

#[derive(Default)]
struct TestCircuit<'a, F, const BIT_DEPTH: usize> {
    leb_base64_words: &'a [u64],
    leb_bytes: &'a [u8],
    leb_last_byte_index: u64,
    solid_number: u64,
    _marker: PhantomData<F>,
}

impl<'a, F: Field, const BIT_DEPTH: usize> Circuit<F> for TestCircuit<'a, F, BIT_DEPTH> {
    type Config = LEB128NumberConfig<F, BIT_DEPTH>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self::default() }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let config = LEB128NumberChip::<F, BIT_DEPTH>::configure(meta);

        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let leb128_number_chip = LEB128NumberChip::construct(config);
        // let is_zero_chip = IsZeroChip::construct(leb128_number_chip.config.is_zero_config.clone());

        layouter.assign_region(
            || "leb128 region",
            |mut region| {
                leb128_number_chip.assign(&mut region, self.leb_bytes, self.leb_last_byte_index, self.solid_number, self.leb_base64_words);

                Ok(())
            }
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use itertools::Itertools;
    use rand::Rng;
    use eth_types::Field;
    use crate::constant;
    use crate::leb128_circuit::dev::TestCircuit;

    const ALL_BIT_DEPTHS_BYTES: &[usize] = &[1, 2, 3, 4, 5, 6, 7, 8];

    /// Returns leb repr and last byte index
    fn convert_to_leb_bytes_unsigned(number: u64, exact_bytes_count: u8) -> (Vec<u8>, usize) {
        let mut res = Vec::new();
        let mut last_byte_index: usize = 0;
        let mut number = number;
        while number > 0 {
            let mut byte = number & 0b1111111;
            number >>= 7;
            if number > 0 {
                byte |= 0b10000000;
                last_byte_index += 1;
            }
            res.push(byte as u8);
        }

        let res = res.as_mut_slice();
        // res.reverse();
        if res.len() == exact_bytes_count as usize {
            return (res.to_vec(), last_byte_index);
        }
        if res.len() > exact_bytes_count as usize {
            panic!("result too long")
        }
        let mut res_vec = vec![0; exact_bytes_count as usize];
        for (i, &item) in res.iter().enumerate() {
            res_vec[i] = item;
        }
        (res_vec, last_byte_index)
    }

    pub fn convert_leb_to_base64_words(leb128: &Vec<u8>) -> (u64, u64) {
        let mut word_0: u64 = 0;
        let mut word_1: u64 = 0;
        for (i, &byte) in leb128.iter().rev().enumerate() {
            let real_index = leb128.len() - i - 1;
            if real_index < 8 {
                word_0 = word_0 * 0b100000000 + byte as u64;
            } else {
                word_1 = word_1 * 0b100000000 + byte as u64;
            }
        }
        (word_0, word_1)
    }

    pub fn break_bit(byte_to_break: &mut u8, break_mask: u8) {
        *byte_to_break = (!*byte_to_break & break_mask) | (*byte_to_break & !break_mask);
    }

    pub fn leb_break_continuation_bit(rng: &mut rand::prelude::ThreadRng, leb128: &mut Vec<u8>) {
        const BIT_TO_BREAK_MASK: u8 = 0b10000000;
        let byte_number = rng.gen::<usize>() % leb128.len();
        break_bit(&mut leb128[byte_number], BIT_TO_BREAK_MASK);
    }

    pub fn leb_break_random_bit(rng: &mut rand::prelude::ThreadRng, leb128: &mut Vec<u8>) {
        let byte_number = rng.gen::<usize>() % leb128.len();
        let bit_to_break_number = rng.gen::<u64>() % 8;
        let bit_to_break_mask = 1 << bit_to_break_number;
        break_bit(&mut leb128[byte_number], bit_to_break_mask);
    }

    fn test<'a, F: Field, const BIT_DEPTH: usize>(test_circuit: TestCircuit<'_, F, BIT_DEPTH>, is_ok: bool) {
        let k = 5;
        let prover = MockProver::run(k, &test_circuit, vec![]).unwrap();
        if is_ok {
            prover.assert_satisfied();
        } else {
            assert!(prover.verify().is_err());
        }
    }

    #[test]
    pub fn test_debug_exact_number() {
        let input_number = 72057594037927936;
        let (input_number_leb128, last_byte_index) = convert_to_leb_bytes_unsigned(input_number, 10);
        // println!("input_number {} leb128 {:x?}", input_number, input_number_leb128);
        let base64_words = convert_leb_to_base64_words(&input_number_leb128);
        let circuit = TestCircuit::<Fr, 64> {
            leb_base64_words: &[base64_words.0, base64_words.1],
            leb_bytes: input_number_leb128.as_slice(),
            leb_last_byte_index: last_byte_index as u64,
            solid_number: input_number,
            _marker: PhantomData
        };
        self::test(circuit, true);
    }

    pub fn test_ok<const BIT_DEPTH: usize>() {
        let mut rng = rand::thread_rng();
        let mut numbers_to_check = Vec::<u64>::new();
        numbers_to_check.push(0);
        numbers_to_check.push(1);
        for i in 0..(BIT_DEPTH - 1) {
            let mut val: u64 = 2 << i;
            numbers_to_check.push(val);

            if i > 0 {
                let val_rnd: u64 = rng.gen();
                val = val_rnd % val;
                numbers_to_check.push(val);
            }
        }
        for input_number in numbers_to_check {
            let (input_number_leb128, last_byte_index) = convert_to_leb_bytes_unsigned(input_number, 10);
            // println!("input_number {} leb128 {:x?}", input_number, input_number_leb128);
            let base64_words = convert_leb_to_base64_words(&input_number_leb128);
            let circuit = TestCircuit::<'_, Fr, BIT_DEPTH> {
                leb_base64_words: &[base64_words.0, base64_words.1],
                leb_bytes: input_number_leb128.as_slice(),
                leb_last_byte_index: last_byte_index as u64,
                solid_number: input_number,
                _marker: PhantomData
            };
            self::test(circuit, true);
        }
    }

    #[test]
    pub fn test_ok_() {
        test_ok::<{8*1}>();
        test_ok::<{8*2}>();
        test_ok::<{8*3}>();
        test_ok::<{8*4}>();
        test_ok::<{8*5}>();
        test_ok::<{8*6}>();
        test_ok::<{8*7}>();
        test_ok::<{8*8}>();
    }

    pub fn test_leb_broken_continuation_bit<const BIT_DEPTH: usize>() {
        let mut rng = rand::thread_rng();
        let mut solid_numbers_to_check = Vec::<u64>::new();
        solid_numbers_to_check.push(0);
        solid_numbers_to_check.push(1);
        for i in 0..(8 * 7 + 7) {
            let mut val: u64 = 2 << i;
            solid_numbers_to_check.push(val);

            if i > 0 {
                let val_rnd: u64 = rng.gen();
                val = val_rnd % val;
                solid_numbers_to_check.push(val);
            }
        }
        for (_i, &solid_number) in solid_numbers_to_check.iter().enumerate() {
            let (mut input_number_leb128, last_byte_index) = convert_to_leb_bytes_unsigned(solid_number, 10);

            leb_break_continuation_bit(&mut rng, &mut input_number_leb128);

            // println!("{}. input_number {} leb128 {:x?}", i, solid_number, input_number_leb128);
            let base64_words = convert_leb_to_base64_words(&input_number_leb128);
            let circuit = TestCircuit::<'_, Fr, 64> {
                leb_base64_words: &[base64_words.0, base64_words.1],
                leb_bytes: input_number_leb128.as_slice(),
                leb_last_byte_index: last_byte_index as u64,
                solid_number,
                _marker: PhantomData
            };
            self::test(circuit, false);
        }
    }

    #[test]
    pub fn test_leb_broken_continuation_bit_() {
        test_leb_broken_continuation_bit::<{8*1}>();
        test_leb_broken_continuation_bit::<{8*2}>();
        test_leb_broken_continuation_bit::<{8*3}>();
        test_leb_broken_continuation_bit::<{8*4}>();
        test_leb_broken_continuation_bit::<{8*5}>();
        test_leb_broken_continuation_bit::<{8*6}>();
        test_leb_broken_continuation_bit::<{8*7}>();
        test_leb_broken_continuation_bit::<{8*8}>();
    }

    pub fn test_leb_broken_random_bit<const BIT_DEPTH: usize>() {
        let mut rng = rand::thread_rng();
        let mut solid_numbers_to_check = Vec::<u64>::new();
        solid_numbers_to_check.push(0);
        solid_numbers_to_check.push(1);
        for i in 0..(8 * 7 + 7) {
            let mut val: u64 = 2 << i;
            solid_numbers_to_check.push(val);

            if i > 0 {
                let val_rnd: u64 = rng.gen();
                val = val_rnd % val;
                solid_numbers_to_check.push(val);
            }
        }
        for (_i, &solid_number) in solid_numbers_to_check.iter().enumerate() {
            let (mut input_number_leb128, last_byte_index) = convert_to_leb_bytes_unsigned(solid_number, 10);

            leb_break_random_bit(&mut rng, &mut input_number_leb128);

            // println!("{}. input_number {} leb128 {:x?}", i, solid_number, input_number_leb128);
            let base64_words = convert_leb_to_base64_words(&input_number_leb128);
            let circuit = TestCircuit::<'_, Fr, 64> {
                leb_base64_words: &[base64_words.0, base64_words.1],
                leb_bytes: input_number_leb128.as_slice(),
                leb_last_byte_index: last_byte_index as u64,
                solid_number,
                _marker: PhantomData
            };
            self::test(circuit, false);
        }
    }

    #[test]
    pub fn test_leb_broken_random_bit_() {
        test_leb_broken_random_bit::<{8*1}>();
        test_leb_broken_random_bit::<{8*2}>();
        test_leb_broken_random_bit::<{8*3}>();
        test_leb_broken_random_bit::<{8*4}>();
        test_leb_broken_random_bit::<{8*5}>();
        test_leb_broken_random_bit::<{8*6}>();
        test_leb_broken_random_bit::<{8*7}>();
        test_leb_broken_random_bit::<{8*8}>();
    }

    pub fn test_broken_solid_number<const BIT_DEPTH: usize>() {
        let mut rng = rand::thread_rng();
        let mut solid_numbers_to_check = Vec::<u64>::new();
        solid_numbers_to_check.push(0);
        solid_numbers_to_check.push(1);
        for i in 0..(8 * 7 + 7) {
            let mut val: u64 = 2 << i;
            solid_numbers_to_check.push(val);

            if i > 0 {
                let val_rnd: u64 = rng.gen();
                val = val_rnd % val;
                solid_numbers_to_check.push(val);
            }
        }
        for (_i, &solid_number) in solid_numbers_to_check.iter().enumerate() {
            let (input_number_leb128, last_byte_index) = convert_to_leb_bytes_unsigned(solid_number, 10);

            // break solid number
            let mut broken_solid_number: u64;
            loop {
                broken_solid_number = rng.gen::<u64>();
                if broken_solid_number != solid_number { break }
            }

            // println!("{}. input_number {} leb128 {:x?}", i, broken_solid_number, input_number_leb128);
            let base64_words = convert_leb_to_base64_words(&input_number_leb128);
            let circuit = TestCircuit::<'_, Fr, 64> {
                leb_base64_words: &[base64_words.0, base64_words.1],
                leb_bytes: input_number_leb128.as_slice(),
                leb_last_byte_index: last_byte_index as u64,
                solid_number: broken_solid_number,
                _marker: PhantomData
            };
            self::test(circuit, false);
        }
    }

    #[test]
    pub fn test_broken_solid_number_() {
        test_broken_solid_number::<{8*1}>();
        test_broken_solid_number::<{8*2}>();
        test_broken_solid_number::<{8*3}>();
        test_broken_solid_number::<{8*4}>();
        test_broken_solid_number::<{8*5}>();
        test_broken_solid_number::<{8*6}>();
        test_broken_solid_number::<{8*7}>();
        test_broken_solid_number::<{8*8}>();
    }

    pub fn test_broken_base64_word<const BIT_DEPTH: usize>() {
        let mut rng = rand::thread_rng();
        let mut solid_numbers_to_check = Vec::<u64>::new();
        solid_numbers_to_check.push(0);
        solid_numbers_to_check.push(1);
        for i in 0..(8 * 7 + 7) {
            let mut val: u64 = 2 << i;
            solid_numbers_to_check.push(val);

            if i > 0 {
                let val_rnd: u64 = rng.gen();
                val = val_rnd % val;
                solid_numbers_to_check.push(val);
            }
        }
        for (_i, &solid_number) in solid_numbers_to_check.iter().enumerate() {
            let (input_number_leb128, last_byte_index) = convert_to_leb_bytes_unsigned(solid_number, 10);

            let base64_words = convert_leb_to_base64_words(&input_number_leb128);
            let mut base64_words = [base64_words.0, base64_words.1];
            // break base64 word
            let base64_word_index: usize = rng.gen::<usize>() % 2;
            loop {
                let broken_word = rng.gen::<u64>();
                if broken_word != base64_words[base64_word_index] {
                    base64_words[base64_word_index] = broken_word;
                    break
                }
            }

            // println!("{}. input_number {} leb128 {:x?}", i, solid_number, input_number_leb128);
            let circuit = TestCircuit::<'_, Fr, 64> {
                leb_base64_words: &base64_words,
                leb_bytes: input_number_leb128.as_slice(),
                leb_last_byte_index: last_byte_index as u64,
                solid_number,
                _marker: PhantomData
            };
            self::test(circuit, false);
        }
    }

    #[test]
    pub fn test_broken_base64_word_() {
        test_broken_base64_word::<{8*1}>();
        test_broken_base64_word::<{8*2}>();
        test_broken_base64_word::<{8*3}>();
        test_broken_base64_word::<{8*4}>();
        test_broken_base64_word::<{8*5}>();
        test_broken_base64_word::<{8*6}>();
        test_broken_base64_word::<{8*7}>();
        test_broken_base64_word::<{8*8}>();
    }
}