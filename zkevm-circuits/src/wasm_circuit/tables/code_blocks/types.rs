use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Expression;
use strum_macros::EnumIter;

use gadgets::util::Expr;
use crate::wasm_circuit::error::Error;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    QFirst,
    QLast,
    Index,
    Opcode,
}

#[derive(Default, Copy, Clone, Debug, EnumIter, PartialEq, Eq, PartialOrd, Ord)]
pub enum Opcode {
    #[default]
    Block = 0x02,
    Loop = 0x03,
    If = 0x04,
    Else = 0x05,
    End = 0xB,
}
pub const OPCODE_VALUES: &[Opcode] = &[
    Opcode::Block,
    Opcode::Loop,
    Opcode::If,
    Opcode::Else,
    Opcode::End,
];
impl TryFrom<u8> for Opcode {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        for instr in OPCODE_VALUES {
            if v == *instr as u8 { return Ok(*instr); }
        }
        Err(Error::InvalidEnumValue)
    }
}
impl From<Opcode> for usize {
    fn from(t: Opcode) -> Self {
        t as usize
    }
}
impl<F: FieldExt> Expr<F> for Opcode {
    #[inline]
    fn expr(&self) -> Expression<F> {
        Expression::Constant(F::from(*self as u64))
    }
}