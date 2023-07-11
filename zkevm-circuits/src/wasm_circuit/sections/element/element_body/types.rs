#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    Unknown,
    IsItemsCount,
    IsElemBody,
    IsElemType,
    IsNumericInstruction,
    IsNumericInstructionLebArg,
    IsBlockEnd,
    IsFuncsIdxCount,
    IsFuncIdx,
    IsElemKind,
}
