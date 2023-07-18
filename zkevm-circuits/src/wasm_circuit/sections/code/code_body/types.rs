#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    QFirst,
    QLast,

    Unknown,
    IsFuncsCount,
    IsFuncBodyLen,
    IsLocalTypeTransitionsCount,
    IsLocalRepetitionCount,
    IsLocalType,
    IsNumericInstruction,
    IsNumericInstructionLebArg,
    IsVariableInstruction,
    IsVariableInstructionLebArg,
    IsControlInstruction,
    IsControlInstructionLebArg,
    IsParametricInstruction,
    IsBlocktypeDelimiter,
    IsBlockEnd,
}
