use std::path::Path;

use object::File;
use object::read::Object;
use uuid::Uuid;
use wholesym::debugid::DebugId;
use wholesym::samply_symbols::object;
use wholesym::{MultiArchDisambiguator, SymbolManager, SymbolManagerConfig};

/// Loads debug info for the binaries we profile.
pub struct Symbolicator {
    symbol_manager: SymbolManager,
}

/// The debug info for one binary: its identity, and a map from addresses to
/// symbols, inline frames and source locations.
pub struct BinarySymbols {
    pub lib_info: wholesym::LibraryInfo,
    pub symbol_map: wholesym::SymbolMap,
}

impl Symbolicator {
    pub fn new() -> Self {
        let config = SymbolManagerConfig::default()
            .respect_nt_symbol_path(true)
            .breakpad_symbol_server(
                "https://symbols.mozilla.org/try/",
                "./breakpad-symbol-cache/",
            )
            .breakpad_symindex_cache_dir("./breakpad-symindex-cache/");
        Self {
            symbol_manager: SymbolManager::with_config(config),
        }
    }

    /// Load the debug info for `object_file`, which lives at `path`. For a fat
    /// archive, `object_file` is one member and its UUID picks the matching
    /// debug info out of the fat debug file.
    pub async fn load(&self, path: &Path, object_file: &File<'_>) -> BinarySymbols {
        let disambiguator = disambiguator_for(object_file);

        let lib_info = SymbolManager::library_info_for_binary_at_path(path, disambiguator.clone())
            .await
            .unwrap();

        let symbol_map = self
            .symbol_manager
            .load_symbol_map_for_binary_at_path(path, disambiguator)
            .await
            .unwrap();

        BinarySymbols {
            lib_info,
            symbol_map,
        }
    }
}

fn disambiguator_for(object_file: &File<'_>) -> Option<MultiArchDisambiguator> {
    let uuid = object_file.mach_uuid().ok()??;
    Some(MultiArchDisambiguator::DebugId(DebugId::from_uuid(
        Uuid::from_bytes(uuid),
    )))
}
