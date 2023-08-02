use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Expression;
use strum_macros::EnumIter;
use eth_types::Field;
use gadgets::util::Expr;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    Index,
    IsTerminator,
    Tag,
}

#[derive(Default, Copy, Clone, Debug, EnumIter, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tag {
    #[default]
    FuncIndex,
    TypeIndex,
    TableIndex,
    MemIndex,
    GlobalIndex,
    DataIndex,
    // TODO
    // ElemIndex,
    // LocalIndex,
}
pub const TAG_VALUES: &[Tag] = &[
    Tag::FuncIndex,
    Tag::TypeIndex,
    Tag::TableIndex,
    Tag::MemIndex,
    Tag::GlobalIndex,
    Tag::DataIndex,
];
impl<F: FieldExt> Expr<F> for Tag {
    fn expr(&self) -> Expression<F> {
        Expression::Constant(F::from(*self as u64))
    }
}

pub struct LookupArgsParams<F: Field> {
    pub cond: Expression<F>,
    pub index: Expression<F>,
    pub tag: Expression<F>,
    pub is_terminator: Expression<F>,
}