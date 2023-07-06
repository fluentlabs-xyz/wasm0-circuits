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
    Zero = SEGMENT_USES_ELEMENT_KIND_AND_INDICES | SEGMENT_HAS_NO_TABLE_INDEX | SEGMENT_IS_DECLARATIVE, // 0
    One = SEGMENT_USES_ELEMENT_TYPES_AND_EXPRESSIONS | SEGMENT_HAS_NO_TABLE_INDEX | SEGMENT_IS_DECLARATIVE, // 1
    Two = SEGMENT_USES_ELEMENT_KIND_AND_INDICES | SEGMENT_HAS_TABLE_INDEX | SEGMENT_IS_DECLARATIVE, // 2,
    Three = SEGMENT_USES_ELEMENT_TYPES_AND_EXPRESSIONS | SEGMENT_HAS_TABLE_INDEX | SEGMENT_IS_DECLARATIVE, // 3,
    Four = SEGMENT_IS_PASSIVE | SEGMENT_HAS_NO_TABLE_INDEX | SEGMENT_IS_DECLARATIVE, // 4,
    Five = SEGMENT_IS_PASSIVE | SEGMENT_HAS_NO_TABLE_INDEX | SEGMENT_USES_ELEMENT_TYPES_AND_EXPRESSIONS, // 5,
    Six = SEGMENT_IS_PASSIVE | SEGMENT_HAS_TABLE_INDEX | SEGMENT_IS_DECLARATIVE, // 6,
    Seven = SEGMENT_IS_PASSIVE | SEGMENT_HAS_TABLE_INDEX | SEGMENT_USES_ELEMENT_TYPES_AND_EXPRESSIONS, // 7,
}
pub const ELEM_TYPE_ALL: &[ElementType] = &[
    ElementType::Zero,
    ElementType::One,
    ElementType::Two,
    ElementType::Three,
    ElementType::Four,
    ElementType::Five,
    ElementType::Six,
    ElementType::Seven,
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
