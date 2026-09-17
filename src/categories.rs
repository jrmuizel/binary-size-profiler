use fxprof_processed_profile::{Category, CategoryColor, CategoryHandle, Profile};
use object::SectionKind;
use wholesym::samply_symbols::object;

/// The kinds of content the profiler can tell apart.
///
/// Each one becomes a category in the profile, and a sample's category is what
/// colours it in the front-end's activity graph, so this list doubles as the
/// graph's legend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Machine code.
    Code,
    /// Bytes inside a text section that no symbol covers.
    Unattributed,
    ReadOnlyData,
    /// Writable data, including thread-local data.
    Data,
    /// Resources: icons, manifests, version info.
    Resources,
    /// Structure rather than content: headers, load commands, relocations,
    /// exception tables, symbol and string tables.
    Metadata,
    DebugInfo,
    /// Alignment padding, and bytes in a container that no section claimed.
    ///
    /// Only used for containers — the file itself, a fat archive member, a
    /// Mach-O segment — because everything they really hold is in a section.
    /// Padding at the end of a *section* takes that section's own colour, since
    /// there is no way to tell it apart from content we haven't broken down.
    Padding,
}

impl Kind {
    pub fn of_section(kind: SectionKind) -> Self {
        match kind {
            SectionKind::Text => Kind::Code,
            SectionKind::Data
            | SectionKind::UninitializedData
            | SectionKind::Tls
            | SectionKind::UninitializedTls
            | SectionKind::TlsVariables => Kind::Data,
            SectionKind::ReadOnlyData
            | SectionKind::ReadOnlyDataWithRel
            | SectionKind::ReadOnlyString
            | SectionKind::OtherString => Kind::ReadOnlyData,
            SectionKind::Debug | SectionKind::DebugString => Kind::DebugInfo,
            // Relocations, notes, linker directives and anything we don't
            // recognise: structure rather than content.
            _ => Kind::Metadata,
        }
    }
}

/// Name and colour per [`Kind`], in the same order as the enum's variants.
const CATEGORIES: [(Kind, &str, CategoryColor); 8] = [
    (Kind::Code, "Code", CategoryColor::Yellow),
    (Kind::Unattributed, "Unattributed", CategoryColor::LightRed),
    (Kind::ReadOnlyData, "Read-only data", CategoryColor::Blue),
    (Kind::Data, "Data", CategoryColor::Green),
    (Kind::Resources, "Resources", CategoryColor::Purple),
    (Kind::Metadata, "Metadata", CategoryColor::Brown),
    (Kind::DebugInfo, "Debug info", CategoryColor::Magenta),
    (Kind::Padding, "Padding", CategoryColor::DarkGray),
];

/// The profile's category handle for each [`Kind`], registered once up front.
pub struct Categories([(Kind, CategoryHandle); CATEGORIES.len()]);

impl Categories {
    pub fn new(profile: &mut Profile) -> Self {
        Self(
            CATEGORIES.map(|(kind, name, color)| {
                (kind, profile.handle_for_category(Category(name, color)))
            }),
        )
    }

    pub fn handle(&self, kind: Kind) -> CategoryHandle {
        // Indexing by the discriminant only works while CATEGORIES lists the
        // kinds in the order the enum declares them, which this checks.
        let (listed, handle) = self.0[kind as usize];
        debug_assert_eq!(listed, kind);
        handle
    }
}
