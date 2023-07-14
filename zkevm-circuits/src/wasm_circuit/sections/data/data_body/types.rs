#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    IsItemsCount,
    IsMemSegmentType,
    IsMemSegmentSizeOpcode,
    IsMemSegmentSize,
    IsBlockEnd,
    IsMemSegmentLen,
    IsMemSegmentBytes,

    IsMemSegmentTypeCtx,

    MemSegmentType,
}
