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
            &leb_bytes,
            IS_SIGNED,
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
    use crate::wasm_circuit::leb128_circuit::consts::{BYTES_IN_BASE64_WORD, EIGHT_LS_BITS_MASK, EIGHT_MS_BIT_MASK, SEVEN_LS_BITS_MASK};
    use crate::wasm_circuit::leb128_circuit::dev::TestCircuit;

    const ALL_BIT_DEPTHS_BYTES: &[usize] = &[1, 2, 3, 4, 5, 6, 7, 8];

    fn rust_log_is_debug() -> bool {
        env::var("RUST_LOG").unwrap_or("".to_string()) == "debug"
    }

    /// unsigned leb repr and last byte index
    fn convert_to_leb_bytes_unsigned(input_number: u64, align_to_bytes_count: usize) -> (Vec<u8>, usize) {
        let mut bytes = Vec::new();
        let mut last_byte_index: usize = 0;
        let mut number = input_number;
        while number > 0 {
            let mut byte = number & 0b1111111;
            number >>= 7;
            if number > 0 {
                byte |= 0b10000000;
                last_byte_index += 1;
            }
            bytes.push(byte as u8);
        }

        let bytes = bytes.as_mut_slice();
        if bytes.len() == align_to_bytes_count {
            return (bytes.to_vec(), last_byte_index);
        }
        if bytes.len() > align_to_bytes_count {
            panic!("bytes count is greater than required. input_number {} align_to_bytes_count {} bytes.len() {}", input_number, align_to_bytes_count, bytes.len())
        }
        let mut res_vec = vec![0; align_to_bytes_count];
        for (i, &item) in bytes.iter().enumerate() {
            res_vec[i] = item;
        }
        (res_vec, last_byte_index)
    }

    /// singed leb repr and last byte index
    fn convert_to_leb_bytes_signed(input_number: i64, align_to_bytes_count: usize) -> (Vec<u8>, usize) {
        if input_number >= 0 {
            panic!("only negative numbers can be converted into signed repr")
        }
        let mut bytes = Vec::new();
        let mut last_byte_index: usize = 0;
        let mut number = input_number;
        if number < 0 {
            number = -number;
        }
        let mut twos_complement_val: u64 = 1;
        let mut overflow: u64 = 0;
        let mut is_full_7_bit = false;
        while number > 0 || is_full_7_bit {
            let mut byte = !(number as u64) & SEVEN_LS_BITS_MASK as u64;
            is_full_7_bit = byte == 0;
            byte += overflow + twos_complement_val;
            twos_complement_val = 0;
            if byte >= EIGHT_MS_BIT_MASK as u64 {
                overflow = 1;
                byte = byte & SEVEN_LS_BITS_MASK as u64;
            } else {
                overflow = 0;
            }
            number >>= 7;
            if number > 0 || is_full_7_bit || overflow == 1 {
                byte |= 0b10000000;
                last_byte_index += 1;
            }
            bytes.push(byte as u8);
        }
        if overflow == 1 {
            bytes.push(!(0b1 & SEVEN_LS_BITS_MASK) & SEVEN_LS_BITS_MASK);
        }

        let res = bytes.as_mut_slice();
        if res.len() == align_to_bytes_count {
            return (res.to_vec(), last_byte_index);
        }
        if res.len() > align_to_bytes_count {
            panic!("bytes count is greater than required. input_number {} align_to_bytes_count {} bytes.len() {}", input_number, align_to_bytes_count, bytes.len())
        }
        let mut res_vec = vec![EIGHT_LS_BITS_MASK; align_to_bytes_count];
        for (i, &item) in res.iter().enumerate() {
            res_vec[i] = item;
        }
        (res_vec, last_byte_index)
    }

    ///
    pub fn convert_to_leb_bytes(is_signed: bool, number: u64, exact_bytes_count: usize) -> (Vec<u8>, usize) {
        if !is_signed || number == 0 {
            return convert_to_leb_bytes_unsigned(number, exact_bytes_count);
        }
        let max_signed_value: u64 = i64::MAX as u64;
        if number >= max_signed_value {
            panic!("max signed value is {} but given {} (is_signed: {})", max_signed_value, number, is_signed)
        }
        convert_to_leb_bytes_signed(if is_signed { -(number as i64) } else { number as i64 }, exact_bytes_count)
    }

    pub fn convert_leb_to_leb_base64_words(leb128: &Vec<u8>, last_byte_index: usize) -> Vec<u64> {
        let mut base64_words = Vec::<u64>::new();
        let mut index = 0;
        for i in 0..=last_byte_index {
            if i % BYTES_IN_BASE64_WORD == 0 {
                base64_words.push(0);
                index = i + 7;
                if index > last_byte_index { index = last_byte_index };
            } else {
                index -= 1;
            }
            let base64_words_last_index = base64_words.len() - 1;
            let current_word = &mut base64_words[base64_words_last_index];
            let byte = leb128[index];
            (*current_word) = (*current_word) * 0b100000000 + byte as u64;
        }
        base64_words
    }

    pub fn break_bit(byte_to_break: &mut u8, break_mask: u8) {
        *byte_to_break = (!*byte_to_break & break_mask) | (*byte_to_break & !break_mask);
    }

    pub fn leb_break_continuation_bit(rng: &mut rand::prelude::ThreadRng, leb128: &mut Vec<u8>) {
        let byte_number = rng.gen::<usize>() % leb128.len();
        break_bit(&mut leb128[byte_number], EIGHT_MS_BIT_MASK);
    }

    pub fn leb_break_random_bit(rng: &mut rand::prelude::ThreadRng, leb128: &mut Vec<u8>) {
        let byte_to_break_number = rng.gen::<usize>() % leb128.len();
        let bit_to_break_number = rng.gen::<u64>() % 8;
        let bit_to_break_mask = 1 << bit_to_break_number;
        break_bit(&mut leb128[byte_to_break_number], bit_to_break_mask);
    }

    pub fn leb_bytes_n_to_max_bit_depth(is_signed: bool, leb_bytes_n: usize) -> usize {
        // max bit depth for u64 solid number
        let max_bit_depth: usize = 7 * 9 + 1 - if is_signed { 1 } else { 0 };
        let max_bit_depth_threshold: usize = 7 * (10 - if is_signed { 1 } else { 0 });
        let mut max_bit_depth_computed = leb_bytes_n * 7;
        if is_signed {
            // TODO recheck
            max_bit_depth_computed -= 1
        }
        if max_bit_depth_computed > max_bit_depth_threshold {
            panic!("computed max bit depth {} is greater threshold {}. there may be problem in program logic", max_bit_depth_computed, max_bit_depth_threshold)
        }
        if max_bit_depth_computed > max_bit_depth {
            return max_bit_depth
        }
        max_bit_depth_computed
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

    pub fn exact_number<const LEB_BYTES_N: usize, const IS_SIGNED: bool>(solid_number: u64) {
        let (input_number_leb128, last_byte_index) = convert_to_leb_bytes(
            IS_SIGNED,
            solid_number,
            LEB_BYTES_N,
        );
        let base64_words = convert_leb_to_leb_base64_words(&input_number_leb128, last_byte_index);
        if rust_log_is_debug() {
            println!(
                "IS_SIGNED:{} solid_number {} base64_words {:x?} leb128 {:x?}",
                IS_SIGNED,
                if IS_SIGNED { -(solid_number as i64) } else { solid_number as i64 },
                base64_words,
                input_number_leb128,
            );
        }
        let circuit = TestCircuit::<Fr, LEB_BYTES_N, IS_SIGNED> {
            leb_base64_words: base64_words.as_slice(),
            leb_bytes: input_number_leb128.as_slice(),
            leb_bytes_last_byte_index: last_byte_index as u64,
            is_negative: IS_SIGNED,
            solid_number,
            _marker: PhantomData
        };
        self::test(circuit, true);
    }

    #[test]
    pub fn test_debug_exact_number_unsigned() {
        const IS_SIGNED: bool = false;
        exact_number::<1, { IS_SIGNED }>(0);
        exact_number::<1, { IS_SIGNED }>(1);
        exact_number::<1, { IS_SIGNED }>(32);
        exact_number::<2, { IS_SIGNED }>(16382);
        exact_number::<2, { IS_SIGNED }>(16383);
        exact_number::<3, { IS_SIGNED }>(123456);
        exact_number::<4, { IS_SIGNED }>(123456789);
    }

    #[test]
    pub fn test_debug_exact_number_signed() {
        const IS_SIGNED: bool = true;
        exact_number::<1, { IS_SIGNED }>(1);
        exact_number::<1, { IS_SIGNED }>(32);
        exact_number::<3, { IS_SIGNED }>(16382);
        exact_number::<3, { IS_SIGNED }>(16383);
        exact_number::<3, { IS_SIGNED }>(123456);
        exact_number::<4, { IS_SIGNED }>(123456789);
    }

    pub fn eligible_numbers<const LEB_BYTES_N: usize, const IS_SIGNED: bool>() {
        let mut rng = rand::thread_rng();
        let mut numbers_to_check = Vec::<(bool, u64)>::new();
        if !IS_SIGNED { // 0 cannot be SIGNED
            numbers_to_check.push((IS_SIGNED, 0));
        }
        numbers_to_check.push((IS_SIGNED, 1));
        for i in 0..leb_bytes_n_to_max_bit_depth(IS_SIGNED, LEB_BYTES_N) - 1 {
            let mut val: u64 = 2 << i;
            numbers_to_check.push((IS_SIGNED, val));

            if i > 0 {
                let val_rnd: u64 = rng.gen();
                val = val_rnd % val;
                if !IS_SIGNED && val != 0 { // 0 cannot be SIGNED
                    numbers_to_check.push((IS_SIGNED, val));
                }
            }
        }
        for (i, &(is_signed, solid_number)) in numbers_to_check.iter().enumerate() {
            let (input_number_leb128, last_byte_index) = convert_to_leb_bytes(
                is_signed,
                solid_number,
                LEB_BYTES_N,
            );
            let base64_words = convert_leb_to_leb_base64_words(&input_number_leb128, last_byte_index);
            if rust_log_is_debug() {
                println!(
                    "{}. IS_SIGNED:{} solid_number {} base64_words {:x?} leb128 {:x?}",
                    i,
                    IS_SIGNED,
                    if IS_SIGNED { -(solid_number as i64) } else { solid_number as i64 },
                    base64_words,
                    input_number_leb128,
                );
            }
            let circuit = TestCircuit::<'_, Fr, LEB_BYTES_N, IS_SIGNED> {
                leb_base64_words: base64_words.as_slice(),
                leb_bytes: input_number_leb128.as_slice(),
                leb_bytes_last_byte_index: last_byte_index as u64,
                is_negative: IS_SIGNED,
                solid_number,
                _marker: PhantomData
            };
            self::test(circuit, true);
        }
    }

    #[test]
    pub fn test_ok_unsigned() {
        const IS_SIGNED: bool = false;
        eligible_numbers::<1, IS_SIGNED>();
        eligible_numbers::<2, IS_SIGNED>();
        eligible_numbers::<3, IS_SIGNED>();
        eligible_numbers::<4, IS_SIGNED>();
        eligible_numbers::<5, IS_SIGNED>();
        eligible_numbers::<6, IS_SIGNED>();
        eligible_numbers::<7, IS_SIGNED>();
        eligible_numbers::<8, IS_SIGNED>();
        eligible_numbers::<9, IS_SIGNED>();
        eligible_numbers::<10, IS_SIGNED>();
    }

    #[test]
    pub fn test_ok_signed() {
        const IS_SIGNED: bool = true;
        eligible_numbers::<1, { IS_SIGNED }>();
        eligible_numbers::<2, { IS_SIGNED }>();
        eligible_numbers::<3, { IS_SIGNED }>();
        eligible_numbers::<4, { IS_SIGNED }>();
        eligible_numbers::<5, { IS_SIGNED }>();
        eligible_numbers::<6, { IS_SIGNED }>();
        eligible_numbers::<7, { IS_SIGNED }>();
        eligible_numbers::<8, { IS_SIGNED }>();
        eligible_numbers::<9, { IS_SIGNED }>();
    }

    pub fn leb_broken_continuation_bit<const LEB_BYTES_N: usize, const IS_SIGNED: bool>() {
        let mut rng = rand::thread_rng();
        let mut solid_numbers_to_check = Vec::<u64>::new();
        solid_numbers_to_check.push(0);
        solid_numbers_to_check.push(1);
        for i in 0..leb_bytes_n_to_max_bit_depth(IS_SIGNED, LEB_BYTES_N) - 1 {
            let mut val: u64 = 2 << i;
            solid_numbers_to_check.push(val);

            if i > 0 {
                let val_rnd: u64 = rng.gen();
                val = val_rnd % val;
                solid_numbers_to_check.push(val);
            }
        }
        for (i, &solid_number) in solid_numbers_to_check.iter().enumerate() {
            let (mut input_number_leb128, last_byte_index) = convert_to_leb_bytes(
                IS_SIGNED,
                solid_number,
                LEB_BYTES_N,
            );

            let base64_words = convert_leb_to_leb_base64_words(&input_number_leb128, last_byte_index);
            leb_break_continuation_bit(&mut rng, &mut input_number_leb128);
            if rust_log_is_debug() {
                println!(
                    "{}. LEB_BYTES_N {} IS_SIGNED:{} solid_number {} base64_words {:x?} leb128 {:x?}",
                    i,
                    LEB_BYTES_N,
                    IS_SIGNED,
                    if IS_SIGNED { -(solid_number as i64) } else { solid_number as i64 },
                    base64_words,
                    input_number_leb128,
                );
            }
            let circuit = TestCircuit::<'_, Fr, LEB_BYTES_N, IS_SIGNED> {
                leb_base64_words: base64_words.as_slice(),
                leb_bytes: input_number_leb128.as_slice(),
                leb_bytes_last_byte_index: last_byte_index as u64,
                is_negative: IS_SIGNED,
                solid_number,
                _marker: PhantomData
            };
            self::test(circuit, false);
        }
    }

    #[test]
    pub fn test_leb_broken_continuation_bit_unsigned() {
        const IS_SIGNED: bool = false;
        leb_broken_continuation_bit::<1, IS_SIGNED>();
        leb_broken_continuation_bit::<2, IS_SIGNED>();
        leb_broken_continuation_bit::<3, IS_SIGNED>();
        leb_broken_continuation_bit::<4, IS_SIGNED>();
        leb_broken_continuation_bit::<5, IS_SIGNED>();
        leb_broken_continuation_bit::<6, IS_SIGNED>();
        leb_broken_continuation_bit::<7, IS_SIGNED>();
        leb_broken_continuation_bit::<8, IS_SIGNED>();
        leb_broken_continuation_bit::<9, IS_SIGNED>();
        leb_broken_continuation_bit::<10, IS_SIGNED>();
    }

    #[test]
    pub fn test_leb_broken_continuation_bit_signed() {
        const IS_SIGNED: bool = true;
        leb_broken_continuation_bit::<1, { IS_SIGNED }>();
        leb_broken_continuation_bit::<2, { IS_SIGNED }>();
        leb_broken_continuation_bit::<3, { IS_SIGNED }>();
        leb_broken_continuation_bit::<4, { IS_SIGNED }>();
        leb_broken_continuation_bit::<5, { IS_SIGNED }>();
        leb_broken_continuation_bit::<6, { IS_SIGNED }>();
        leb_broken_continuation_bit::<7, { IS_SIGNED }>();
        leb_broken_continuation_bit::<8, { IS_SIGNED }>();
        leb_broken_continuation_bit::<9, { IS_SIGNED }>();
    }

    pub fn leb_broken_random_bit<const LEB_BYTES_N: usize, const IS_SIGNED: bool>() {
        let mut rng = rand::thread_rng();
        let mut solid_numbers_to_check = Vec::<u64>::new();
        solid_numbers_to_check.push(0);
        solid_numbers_to_check.push(1);
        for i in 0..leb_bytes_n_to_max_bit_depth(IS_SIGNED, LEB_BYTES_N) - 1 {
            let mut val: u64 = 2 << i;
            solid_numbers_to_check.push(val);

            if i > 0 {
                let val_rnd: u64 = rng.gen();
                val = val_rnd % val;
                solid_numbers_to_check.push(val);
            }
        }
        for (i, &solid_number) in solid_numbers_to_check.iter().enumerate() {
            let (mut input_number_leb128, last_byte_index) = convert_to_leb_bytes(
                IS_SIGNED,
                solid_number,
                LEB_BYTES_N,
            );

            let base64_words = convert_leb_to_leb_base64_words(&input_number_leb128, last_byte_index);
            leb_break_random_bit(&mut rng, &mut input_number_leb128);
            if rust_log_is_debug() {
                println!(
                    "{}. IS_SIGNED:{} solid_number {} base64_words {:x?} leb128 {:x?}",
                    i,
                    IS_SIGNED,
                    if IS_SIGNED { -(solid_number as i64) } else { solid_number as i64 },
                    base64_words,
                    input_number_leb128,
                );
            }
            let circuit = TestCircuit::<'_, Fr, LEB_BYTES_N, IS_SIGNED> {
                leb_base64_words: base64_words.as_slice(),
                leb_bytes: input_number_leb128.as_slice(),
                leb_bytes_last_byte_index: last_byte_index as u64,
                is_negative: IS_SIGNED,
                solid_number,
                _marker: PhantomData
            };
            self::test(circuit, false);
        }
    }

    #[test]
    pub fn test_leb_broken_random_bit_unsigned() {
        const IS_SIGNED: bool = false;
        leb_broken_random_bit::<1, IS_SIGNED>();
        leb_broken_random_bit::<2, IS_SIGNED>();
        leb_broken_random_bit::<3, IS_SIGNED>();
        leb_broken_random_bit::<4, IS_SIGNED>();
        leb_broken_random_bit::<5, IS_SIGNED>();
        leb_broken_random_bit::<6, IS_SIGNED>();
        leb_broken_random_bit::<7, IS_SIGNED>();
        leb_broken_random_bit::<8, IS_SIGNED>();
        leb_broken_random_bit::<9, IS_SIGNED>();
        leb_broken_random_bit::<10, IS_SIGNED>();
    }

    #[test]
    pub fn test_leb_broken_random_bit_signed() {
        const IS_SIGNED: bool = true;
        leb_broken_random_bit::<1, IS_SIGNED>();
        leb_broken_random_bit::<2, IS_SIGNED>();
        leb_broken_random_bit::<3, IS_SIGNED>();
        leb_broken_random_bit::<4, IS_SIGNED>();
        leb_broken_random_bit::<5, IS_SIGNED>();
        leb_broken_random_bit::<6, IS_SIGNED>();
        leb_broken_random_bit::<7, IS_SIGNED>();
        leb_broken_random_bit::<8, IS_SIGNED>();
        leb_broken_random_bit::<9, IS_SIGNED>();
    }

    pub fn broken_base64_word<const LEB_BYTES_N: usize, const IS_SIGNED: bool>() {
        let mut rng = rand::thread_rng();
        let mut solid_numbers_to_check = Vec::<u64>::new();
        solid_numbers_to_check.push(0);
        solid_numbers_to_check.push(1);
        for i in 0..leb_bytes_n_to_max_bit_depth(IS_SIGNED, LEB_BYTES_N) - 1 {
            let mut val: u64 = 2 << i;
            solid_numbers_to_check.push(val);

            if i > 0 {
                let val_rnd: u64 = rng.gen();
                val = val_rnd % val;
                solid_numbers_to_check.push(val);
            }
        }
        for (i, &solid_number) in solid_numbers_to_check.iter().enumerate() {
            let (input_number_leb128, last_byte_index) = convert_to_leb_bytes(
                IS_SIGNED,
                solid_number,
                LEB_BYTES_N,
            );

            let mut base64_words = convert_leb_to_leb_base64_words(&input_number_leb128, last_byte_index);
            // break base64 word
            let base64_word_index: usize = rng.gen::<usize>() % base64_words.len();
            loop {
                let broken_word = rng.gen::<u64>();
                if broken_word != base64_words[base64_word_index] {
                    base64_words[base64_word_index] = broken_word;
                    break
                }
            }

            if rust_log_is_debug() {
                println!(
                    "{}. IS_SIGNED:{} solid_number {} base64_words {:x?} leb128 {:x?}",
                    i,
                    IS_SIGNED,
                    solid_number,
                    base64_words,
                    input_number_leb128,
                );
            }
            let circuit = TestCircuit::<'_, Fr, LEB_BYTES_N, IS_SIGNED> {
                leb_base64_words: base64_words.as_slice(),
                leb_bytes: input_number_leb128.as_slice(),
                leb_bytes_last_byte_index: last_byte_index as u64,
                is_negative: IS_SIGNED,
                solid_number,
                _marker: PhantomData
            };
            self::test(circuit, false);
        }
    }

    #[test]
    pub fn test_broken_base64_word_unsigned() {
        const IS_SIGNED: bool = false;
        broken_base64_word::<1, IS_SIGNED>();
        broken_base64_word::<2, IS_SIGNED>();
        broken_base64_word::<3, IS_SIGNED>();
        broken_base64_word::<4, IS_SIGNED>();
        broken_base64_word::<5, IS_SIGNED>();
        broken_base64_word::<6, IS_SIGNED>();
        broken_base64_word::<7, IS_SIGNED>();
        broken_base64_word::<8, IS_SIGNED>();
        broken_base64_word::<9, IS_SIGNED>();
        broken_base64_word::<10, IS_SIGNED>();
    }

    #[test]
    pub fn test_broken_base64_word_signed() {
        const IS_SIGNED: bool = true;
        broken_base64_word::<1, IS_SIGNED>();
        broken_base64_word::<2, IS_SIGNED>();
        broken_base64_word::<3, IS_SIGNED>();
        broken_base64_word::<4, IS_SIGNED>();
        broken_base64_word::<5, IS_SIGNED>();
        broken_base64_word::<6, IS_SIGNED>();
        broken_base64_word::<7, IS_SIGNED>();
        broken_base64_word::<8, IS_SIGNED>();
        broken_base64_word::<9, IS_SIGNED>();
    }
}