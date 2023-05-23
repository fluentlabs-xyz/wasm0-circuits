#![feature(proc_macro_hygiene)]
#![feature(exclusive_range_pattern)]

pub mod chip;

pub mod consts;
#[cfg(any(feature = "test", test))]
pub mod tests;

type Natural = u64;

trait BitSize {}

struct Bs32;
impl BitSize for Bs32 {}

struct Bs64;
impl BitSize for Bs64 {}

struct MemArg {
    offset: Natural,
    align: Natural,
}

/*
use value_type::Trait as ValueType;
pub mod value_type {
  pub trait ValueType {}

  pub struct I32;
  impl Trait for I32 {}

  pub struct I64;
  impl Trait for I64 {}

  pub struct F32;
  impl Trait for F32 {}

  pub struct F64;
  impl Trait for F64 {}
}
*/

trait BlockType {}

//struct Inline(Option<ValueType>);
//impl BlockType for Inline {}

/*
data Instruction index =
    -- Control instructions
    Unreachable
    | Nop
    | Block { blockType :: BlockType, body :: Expression }
    | Loop { blockType :: BlockType, body :: Expression }
    | If { blockType :: BlockType, true :: Expression, false :: Expression }
    | Br index
    | BrIf index
    | BrTable [index] index
    | Return
    | Call index
    | CallIndirect index
    -- Parametric instructions
    | Drop
    | Select
    -- Variable instructions
    | GetLocal index
    | SetLocal index
    | TeeLocal index
    | GetGlobal index
    | SetGlobal index
    -- Memory instructions
    | I32Load MemArg
    | I64Load MemArg
    | F32Load MemArg
    | F64Load MemArg
    | I32Load8S MemArg
    | I32Load8U MemArg
    | I32Load16S MemArg
    | I32Load16U MemArg
    | I64Load8S MemArg
    | I64Load8U MemArg
    | I64Load16S MemArg
    | I64Load16U MemArg
    | I64Load32S MemArg
    | I64Load32U MemArg
    | I32Store MemArg
    | I64Store MemArg
    | F32Store MemArg
    | F64Store MemArg
    | I32Store8 MemArg
    | I32Store16 MemArg
    | I64Store8 MemArg
    | I64Store16 MemArg
    | I64Store32 MemArg
    | CurrentMemory
    | GrowMemory
    -- Numeric instructions
    | I32Const Word32
    | I64Const Word64
    | F32Const Float
    | F64Const Double
    | IUnOp BitSize IUnOp
    | IBinOp BitSize IBinOp
    | I32Eqz
    | I64Eqz
    | IRelOp BitSize IRelOp
    | FUnOp BitSize FUnOp
    | FBinOp BitSize FBinOp
    | FRelOp BitSize FRelOp
    | I32WrapI64
    | ITruncFU {- Int Size -} BitSize {- Float Size -} BitSize
    | ITruncFS {- Int Size -} BitSize {- Float Size -} BitSize
    | ITruncSatFU {- Int Size -} BitSize {- Float Size -} BitSize
    | ITruncSatFS {- Int Size -} BitSize {- Float Size -} BitSize
    | I64ExtendSI32
    | I64ExtendUI32
    | FConvertIU {- Float Size -} BitSize {- Int Size -} BitSize
    | FConvertIS {- Float Size -} BitSize {- Int Size -} BitSize
    | F32DemoteF64
    | F64PromoteF32
    | IReinterpretF BitSize
    | FReinterpretI BitSize
    deriving (Show, Eq, Generic, NFData)
*/
