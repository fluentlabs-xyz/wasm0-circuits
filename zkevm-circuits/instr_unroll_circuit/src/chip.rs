use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::{
    circuit::{Chip as _Chip, Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector, TableColumn,
    },
    poly::Rotation,
};
use macro_rules_attribute::apply;
use std::marker::PhantomData as Ph;

/// Config.
#[derive(Debug, Clone)]
pub struct Config<F> {
    pub advice: Advices,
    pub instance: Instances,
    pub selector: Selectors,
    pub table: Tables,
    /// Phantom marker to make `F` usable in type system.
    _marker: Ph<F>,
}

#[derive(Debug, Clone)]
pub struct Advices {
    /// Sequence of bytes to parse.
    pub bytes: Column<Advice>,
    /// What kind of instruction, (instruction with LEB for example, etc).
    pub kind: Column<Advice>,
    /// Each byte in parse sequence spend one cell, and one cell can fill `u64`.
    /// So result of parsing do not require any extra space.
    pub unrolled: Column<Advice>,
}

#[derive(Debug, Clone)]
pub struct Instances {
    //pub some_point: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct Selectors {
    /// Main selector.
    pub main: Selector,
    /// Byte parse selector.
    pub byte_parse: Selector,
}

#[derive(Debug, Clone)]
pub struct Tables {
    pub instr_byte: TableColumn,
    pub instr_kind: TableColumn,
}

/// Chip.
#[derive(Debug, Clone)]
pub struct Chip<F> {
    /// Config for this chip.
    pub config: Config<F>,
    /// Phantom marker to make `F` usable in type system.
    _marker: Ph<F>,
}

macro_rules! impl_chip {
    ($($t:tt)*) => {
        impl<F: Field> Chip<F> {
            $($t)*
        }
    }
}

#[apply(impl_chip)]
pub fn validate_static_state() {}

#[apply(impl_chip)]
pub fn construct(config: Config<F>) -> Self {
    let instance = Self {
        config,
        _marker: Ph,
    };
    Self::validate_static_state();
    instance
}

pub mod kind {
    pub const SIZE: usize = 6;

    pub const INSTR_SIMPLE_TRANSLATION: u64 = 1;
    pub const INSTR_SIMPLE_WITH_ULEB_32: u64 = 2;
    pub const INSTR_SIMPLE_WITH_SLEB_32: u64 = 3;
    pub const INSTR_FIRST_ULEB_32: u64 = 4;
    pub const INSTR_MEM_GET: u64 = 5;
    pub const INSTR_SPECIAL: u64 = 6;
}

#[apply(impl_chip)]
pub fn configure(cs: &mut ConstraintSystem<F>) -> Config<F> {
    Self::validate_static_state();
    let config = Config {
        advice: Advices {
            bytes: cs.advice_column(),
            kind: cs.advice_column(),
            unrolled: cs.advice_column(),
        },
        instance: Instances {},
        selector: Selectors {
            main: cs.selector(),
            byte_parse: cs.complex_selector(),
        },
        table: Tables {
            instr_byte: cs.lookup_table_column(),
            instr_kind: cs.lookup_table_column(),
        },
        _marker: Ph,
    };

    cs.lookup("instr byte lut", |vc| {
        let case = vc.query_selector(config.selector.byte_parse);
        let byte = vc.query_advice(config.advice.bytes, Rotation::cur());
        let kind = vc.query_advice(config.advice.kind, Rotation::cur());
        vec![
            (case.clone() * byte.clone(), config.table.instr_byte),
            (case.clone() * kind.clone(), config.table.instr_kind),
        ]
    });

    // This is just constraint about same content of `byte` and `unrolled` in case with where kind
    // is simple translation.
    cs.create_gate("instr simple translation", |vc| {
        let se = vc.query_selector(config.selector.main);
        let mut cs = Vec::<Expression<F>>::from([]);
        let byte = vc.query_advice(config.advice.byte, Rotation::cur());
        let kind = vc.query_advice(config.advice.kind, Rotation::cur());
        let unrolled = vc.query_advice(config.advice.unrolled, Rotation::cur());
        cs.push(kind - kind::INSTR_SIMPLE_TRANSLATION.expr());
        cs.push(byte - unrolled);
        Constraints::with_selector(se, cs)
    });

    // Operation code inside `unrolled` part is inherited, so constraint for this exist.
    // After this, space inside unrolled with next rotations is used to store `ULEB` result.
    cs.create_gate("instr simple with uleb 32", |vc| {
        let se = vc.query_selector(config.selector.main);
        let mut cs = Vec::<Expression<F>>::from([]);
        let byte_op = vc.query_advice(config.advice.byte, Rotation::cur());
        let kind_op = vc.query_advice(config.advice.kind, Rotation::cur());
        let unrolled_op = vc.query_advice(config.advice.unrolled, Rotation::cur());
        cs.push(kind_op - kind::INSTR_SIMPLE_WITH_ULEB_32.expr());
        cs.push(byte_op - unrolled_op);
        Constraints::with_selector(se, cs)
    });

    // Operation code inside `unrolled` part is inherited, so constraint for this exist.
    // After this, space inside unrolled with next rotations is used to store `ULEB` result.
    // In this case just some different `ULEB` is used, it is signed version here.
    cs.create_gate("instr simple with sleb 32", |vc| {
        let se = vc.query_selector(config.selector.main);
        let mut cs = Vec::<Expression<F>>::from([]);
        let byte_op = vc.query_advice(config.advice.byte, Rotation::cur());
        let kind_op = vc.query_advice(config.advice.kind, Rotation::cur());
        let unrolled_op = vc.query_advice(config.advice.unrolled, Rotation::cur());
        cs.push(kind_op - kind::INSTR_SIMPLE_WITH_SLEB_32.expr());
        cs.push(byte_op - unrolled_op);
        Constraints::with_selector(se, cs)
    });

    cs.create_gate("instr first uleb 32", |vc| {
        let se = vc.query_selector(config.selector.main);
        let mut cs = Vec::<Expression<F>>::from([]);
        let byte_op = vc.query_advice(config.advice.byte, Rotation::cur());
        let kind = vc.query_advice(config.advice.kind, Rotation::cur());
        cs.push(kind - kind::INSTR_FIRST_ULEB_32.expr());
        Constraints::with_selector(se, cs)
    });

    // Operation code inside `unrolled` part is inherited, so constraint for this exist.
    // Two `ULEB` parsing happens with `bytes` after `byte_op` (operation code, see first line of
    // comment). Resulting `align` and `offset` is stored inside `unrolled` with rotations 1 and
    // 2.
    cs.create_gate("instr mem get", |vc| {
        let se = vc.query_selector(config.selector.main);
        let mut cs = Vec::<Expression<F>>::from([]);
        let byte_op = vc.query_advice(config.advice.byte, Rotation::cur());
        let kind = vc.query_advice(config.advice.kind, Rotation::cur());
        let unrolled_op = vc.query_advice(config.advice.unrolled, Rotation::cur());
        let unrolled_align = vc.query_advice(config.advice.unrolled, Rotation(1));
        let unrolled_offset = vc.query_advice(config.advice.unrolled, Rotation(2));
        cs.push(kind - kind::INSTR_MEM_GET.expr());
        cs.push(byte_op - unrolled_op);
        Constraints::with_selector(se, cs)
    });

    cs.create_gate("instr special a", |vc| {
        let se = vc.query_selector(config.selector.main);
        let mut cs = Vec::<Expression<F>>::from([]);
        let kind = vc.query_advice(config.advice.kind, Rotation::cur());
        cs.push(kind - kind::INSTR_SPECIAL.expr());
        Constraints::with_selector(se, cs)
    });

    config
}

#[apply(impl_chip)]
pub fn assign(&self, region: &mut Region<F>, bytes: &[u8]) {
    //self.config.selector.enable(region, 0).unwrap();
}

#[apply(impl_chip)]
fn load_table(&self, mut layouter: impl Layouter<F>) -> Result<(), Error> {
    let config = &self.config;
    macro_rules! assign_cells {
        ( ( $table:ident, $idx:ident,
            [$(($name:expr, $tabi:ident, $fval:expr),)*],
        );) => {$(
            $table.assign_cell(
                || $name,
                config.table.$tabi,
                $idx,
                || Value::known(F::from($fval))
            )?;
        )*}
    }
    layouter.assign_table(
        || "instr byte lut",
        |mut table| {
            let mut idx = 0;
            for byte in 0..256 {
                #[apply(assign_cells)]
                (
                    table,
                    idx,
                    [
                        ("byte", instr_byte, byte),
                        ("kind", instr_kind, byte_to_kind(byte)),
                    ],
                );
                idx += 1;
            }
            Ok(())
        },
    )
}

fn byte_to_kind(b: u64) -> u64 {
    match b {
        0x28..0x3E => kind::INSTR_MEM_GET,
        0x45..0xC4 => kind::INSTR_SIMPLE_TRANSLATION,
        0x11 | 0xFC => kind::INSTR_FIRST_ULEB_32,
        0x0C | 0x0D | 0x10 | 0x20 | 0x21 | 0x22 | 0x23 | 0x24 => kind::INSTR_SIMPLE_WITH_ULEB_32,
        0x41 | 0x42 => kind::INSTR_SIMPLE_WITH_SLEB_32,
        _ => kind::INSTR_SPECIAL,
    }
}
