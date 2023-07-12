use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Expression;
use strum_macros::EnumIter;
use gadgets::util::Expr;

// Bit 0 indicates a passive or declarative segment
const SEGMENT_IS_PASSIVE: isize = 0b100;
const SEGMENT_IS_DECLARATIVE: isize = 0b000;
// bit 1 indicates the presence of an explicit table index for an active segment and otherwise distinguishes passive from declarative segments
const SEGMENT_HAS_TABLE_INDEX: isize = 0b10;
const SEGMENT_HAS_NO_TABLE_INDEX: isize = 0b00;
// bit 2 indicates the use of element type and element expressions instead of element kind and element indices
const SEGMENT_USES_ELEMENT_TYPES_AND_EXPRESSIONS: isize = 0b1;
const SEGMENT_USES_ELEMENT_KIND_AND_INDICES: isize = 0b0;

/// https://webassembly.github.io/spec/core/binary/modules.html#element-section
#[derive(Copy, Clone, Debug, EnumIter, PartialEq, Eq, PartialOrd, Ord)]
pub enum ElementType {
    _0 = SEGMENT_USES_ELEMENT_KIND_AND_INDICES | SEGMENT_HAS_NO_TABLE_INDEX | SEGMENT_IS_DECLARATIVE,
    _1 = SEGMENT_USES_ELEMENT_TYPES_AND_EXPRESSIONS | SEGMENT_HAS_NO_TABLE_INDEX | SEGMENT_IS_DECLARATIVE,
    _2 = SEGMENT_USES_ELEMENT_KIND_AND_INDICES | SEGMENT_HAS_TABLE_INDEX | SEGMENT_IS_DECLARATIVE,
    _3 = SEGMENT_USES_ELEMENT_TYPES_AND_EXPRESSIONS | SEGMENT_HAS_TABLE_INDEX | SEGMENT_IS_DECLARATIVE,
    _4 = SEGMENT_IS_PASSIVE | SEGMENT_HAS_NO_TABLE_INDEX | SEGMENT_IS_DECLARATIVE,
    _5 = SEGMENT_IS_PASSIVE | SEGMENT_HAS_NO_TABLE_INDEX | SEGMENT_USES_ELEMENT_TYPES_AND_EXPRESSIONS,
    _6 = SEGMENT_IS_PASSIVE | SEGMENT_HAS_TABLE_INDEX | SEGMENT_IS_DECLARATIVE,
    _7 = SEGMENT_IS_PASSIVE | SEGMENT_HAS_TABLE_INDEX | SEGMENT_USES_ELEMENT_TYPES_AND_EXPRESSIONS,
}
pub const ELEM_TYPE_VALUES: &[ElementType] = &[
    ElementType::_0,
    ElementType::_1,
    ElementType::_2,
    ElementType::_3,
    ElementType::_4,
    ElementType::_5,
    ElementType::_6,
    ElementType::_7,
];
impl TryFrom<u8> for ElementType {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        for instr in ELEM_TYPE_VALUES {
            if v == *instr as u8 { return Ok(*instr); }
        }
        Err(())
    }
}
impl From<ElementType> for usize {
    fn from(t: ElementType) -> Self {
        t as usize
    }
}
impl<F: FieldExt> Expr<F> for ElementType {
    #[inline]
    fn expr(&self) -> Expression<F> {
        Expression::Constant(F::from(*self as u64), )
    }
}
