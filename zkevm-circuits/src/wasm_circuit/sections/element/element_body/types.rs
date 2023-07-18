#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    Unknown,

    QFirst,
    QLast,

    ElemType,

    IsItemsCount,
    IsElemType,
    IsElemTypeCtx,
    IsNumericInstruction,
    IsNumericInstructionLebArg,
    IsBlockEnd,
    IsFuncsIdxCount,
    IsFuncIdx,
    IsElemKind,
}
