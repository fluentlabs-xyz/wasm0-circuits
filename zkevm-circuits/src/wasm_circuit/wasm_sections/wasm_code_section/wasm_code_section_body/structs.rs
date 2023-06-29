#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WasmCodeSectionAssignType {
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
    BlocktypeDelimiter,
    BlockEnd,
}

#[derive(Copy, Clone, Debug)]
pub struct WasmCodeSectionAssignLebParams {
    pub byte_rel_offset: usize,
    pub last_byte_rel_offset: usize,
    pub sn: u64,
    pub sn_recovered_at_pos: u64,
}
