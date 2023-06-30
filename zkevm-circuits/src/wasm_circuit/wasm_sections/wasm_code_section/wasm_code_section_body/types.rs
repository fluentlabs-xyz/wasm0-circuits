#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    Unknown,
    FuncsCount,
    FuncBodyLen,
    LocalTypeTransitionsCount,
    LocalRepetitionCount,
    LocalType,
    NumericInstruction,
    NumericInstructionLebArg,
    VariableInstruction,
    VariableInstructionLebArg,
    ControlInstruction,
    ControlInstructionLebArg,
    ParametricInstruction,
    BlocktypeDelimiter,
    BlockEnd,
}
