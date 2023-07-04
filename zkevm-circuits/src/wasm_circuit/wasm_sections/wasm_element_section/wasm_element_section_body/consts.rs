use strum_macros::EnumIter;

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
    ElementType0 = SEGMENT_USES_ELEMENT_KIND_AND_INDICES | SEGMENT_HAS_NO_TABLE_INDEX | SEGMENT_IS_DECLARATIVE, // 0
    ElementType1 = SEGMENT_USES_ELEMENT_TYPES_AND_EXPRESSIONS | SEGMENT_HAS_NO_TABLE_INDEX | SEGMENT_IS_DECLARATIVE, // 1
    ElementType2 = SEGMENT_USES_ELEMENT_KIND_AND_INDICES | SEGMENT_HAS_TABLE_INDEX | SEGMENT_IS_DECLARATIVE, // 2,
    ElementType3 = SEGMENT_USES_ELEMENT_TYPES_AND_EXPRESSIONS | SEGMENT_HAS_TABLE_INDEX | SEGMENT_IS_DECLARATIVE, // 3,
    ElementType4 = SEGMENT_IS_PASSIVE | SEGMENT_HAS_NO_TABLE_INDEX | SEGMENT_IS_DECLARATIVE, // 4,
    ElementType5 = SEGMENT_IS_PASSIVE | SEGMENT_HAS_NO_TABLE_INDEX | SEGMENT_USES_ELEMENT_TYPES_AND_EXPRESSIONS, // 5,
    ElementType6 = SEGMENT_IS_PASSIVE | SEGMENT_HAS_TABLE_INDEX | SEGMENT_IS_DECLARATIVE, // 6,
    ElementType7 = SEGMENT_IS_PASSIVE | SEGMENT_HAS_TABLE_INDEX | SEGMENT_USES_ELEMENT_TYPES_AND_EXPRESSIONS, // 7,
}
pub const ELEM_TYPE_ALL: &[ElementType] = &[
    ElementType::ElementType0,
    ElementType::ElementType1,
    ElementType::ElementType2,
    ElementType::ElementType3,
    ElementType::ElementType4,
    ElementType::ElementType5,
    ElementType::ElementType6,
    ElementType::ElementType7,
];
impl TryFrom<i32> for ElementType {
    type Error = ();

    fn try_from(v: i32) -> Result<Self, Self::Error> {
        for instr in ELEM_TYPE_ALL {
            if v == *instr as i32 { return Ok(*instr); }
        }
        Err(())
    }
}
impl From<ElementType> for usize {
    fn from(t: ElementType) -> Self {
        t as usize
    }
}
