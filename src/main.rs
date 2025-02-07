use std::collections::HashMap;
use std::path::Path;

use fxprof_processed_profile::{
    CategoryHandle, CpuDelta, Frame, FrameFlags, FrameInfo, LibraryInfo, Profile,
    ReferenceTimestamp, SamplingInterval, StackHandle, Timestamp, WeightType,
};
use fxprof_processed_profile::{CategoryPairHandle, ThreadHandle};
use indicatif::{ProgressBar, ProgressStyle};
use mimalloc::MiMalloc;
use object::read::macho::FatArch;
use object::read::macho::MachOFatFile32;
use object::read::Object;
use object::File;
use object::FileKind;
use object::ObjectSection;
use uuid::Uuid;
use wholesym::debugid::DebugId;
use wholesym::samply_symbols::relative_address_base;
use wholesym::MultiArchDisambiguator;
use wholesym::SymbolManager;
use wholesym::SymbolManagerConfig;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;

    let path = &std::env::args().nth(1).unwrap();
    let file_name = Path::new(path).file_name().unwrap().to_str().unwrap();

    let mut data = Vec::new();
    let mut file = std::fs::File::open(path).unwrap();
    file.read_to_end(&mut data).unwrap();

    let file_kind = FileKind::parse(&data[..]).unwrap();

    let mut profile = Profile::new(
        "size-profiler",
        ReferenceTimestamp::from_millis_since_unix_epoch(0.),
        SamplingInterval::from_hz(1000.),
    );

    let process = profile.add_process(file_name, 0, Timestamp::from_millis_since_reference(0.));
    let thread = profile.add_thread(process, 0, Timestamp::from_millis_since_reference(0.), true);
    profile.set_thread_samples_weight_type(thread, WeightType::Bytes);
    let category = CategoryHandle::OTHER.into();

    let root_s = profile.intern_string("(root)");
    let root_frame = profile.intern_frame(
        thread,
        FrameInfo {
            frame: Frame::Label(root_s),
            category_pair: category,
            flags: FrameFlags::empty(),
        },
    );
    let root_stack = profile.intern_stack(thread, None, root_frame);

    let config = SymbolManagerConfig::default()
        .respect_nt_symbol_path(true)
        .breakpad_symbols_server(
            "https://symbols.mozilla.org/try/",
            "./breakpad-symbol-cache/",
        )
        .breakpad_symindex_cache_dir("./breakpad-symindex-cache/");
    let symbol_manager = SymbolManager::with_config(config);

    // If we got a fat binary, pick the first member.
    let data = if dbg!(file_kind) == FileKind::MachOFat32 {
        let member = MachOFatFile32::parse(&data[..])
            .unwrap()
            .arches()
            .first()
            .unwrap();
        let offset = member.offset();
        let size = member.size();
        &data[offset as usize..][..size as usize]
    } else {
        &data[..]
    };

    let object_file = File::parse(data).unwrap();

    let disambiguator = if let Ok(Some(uuid)) = object_file.mach_uuid() {
        let uuid = Uuid::from_bytes(uuid);
        Some(MultiArchDisambiguator::DebugId(DebugId::from_uuid(uuid)))
    } else {
        None
    };

    let lib_info =
        SymbolManager::library_info_for_binary_at_path(Path::new(path), disambiguator.clone())
            .await
            .unwrap();

    let symbol_map = symbol_manager
        .load_symbol_map_for_binary_at_path(Path::new(path), disambiguator)
        .await
        .unwrap();

    process_binary(
        &mut profile,
        thread,
        root_stack,
        &object_file,
        lib_info,
        symbol_map,
        category,
    )
    .await;
    let output_file = std::fs::File::create("output.json").unwrap();
    let writer = std::io::BufWriter::new(output_file);
    serde_json::to_writer(writer, &profile).unwrap();

    Ok(())
}

async fn process_binary(
    profile: &mut Profile,
    thread: ThreadHandle,
    root_stack: StackHandle,
    object_file: &File<'_>,
    lib_info: wholesym::LibraryInfo,
    symbol_map: wholesym::SymbolMap,
    category: CategoryPairHandle,
) {
    let lib = LibraryInfo {
        name: lib_info.name.unwrap(),
        debug_name: lib_info.debug_name.unwrap(),
        path: lib_info.path.unwrap(),
        debug_path: lib_info.debug_path.unwrap(),
        debug_id: lib_info.debug_id.unwrap(),
        code_id: lib_info.code_id.map(|ci| ci.to_string()),
        arch: lib_info.arch,
        symbol_table: None,
    };

    let base_addr = relative_address_base(object_file);

    let _lib = profile.add_lib(lib);

    let unknown_path_str = profile.intern_string("<unknown path>");
    let unknown_path_frame = profile.intern_frame(
        thread,
        FrameInfo {
            frame: Frame::Label(unknown_path_str),
            category_pair: category,
            flags: FrameFlags::empty(),
        },
    );

    let unknown_bytes_str = profile.intern_string("<unknown bytes>");
    let unknown_bytes_frame = profile.intern_frame(
        thread,
        FrameInfo {
            frame: Frame::Label(unknown_bytes_str),
            category_pair: category,
            flags: FrameFlags::empty(),
        },
    );

    for s in object_file.sections() {
        let section_size = s.size();
        let section_start_rel = s.address() - base_addr;
        let section_end_rel = s.address() + s.size() - base_addr;
        let mut time = 0;

        let section_s = profile.intern_string(s.name().unwrap());
        let section_frame = profile.intern_frame(
            thread,
            FrameInfo {
                frame: Frame::Label(section_s),
                category_pair: category,
                flags: FrameFlags::empty(),
            },
        );
        let section_stack = profile.intern_stack(thread, Some(root_stack), section_frame);

        let unknown_path_stack =
            profile.intern_stack(thread, Some(section_stack), unknown_path_frame);

        let pb = ProgressBar::new(section_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
                )
                .unwrap()
                .progress_chars("#>-"),
        );

        let mut last_stack = None;
        // let mut last_address_stack = None;
        let mut stack_prefix_for_path: HashMap<String, StackHandle> = HashMap::new();
        let mut weight = 0;
        for addr in section_start_rel..section_end_rel {
            if addr & 0xffff == 0 {
                pb.set_position(addr - section_start_rel);
            }

            let addr_info = symbol_map
                .lookup(wholesym::LookupAddress::Relative(addr as u32))
                .await;

            fn get_outer_function_location(
                addr_info: &Option<wholesym::AddressInfo>,
            ) -> Option<String> {
                let frames = addr_info.as_ref()?.frames.as_ref()?;
                let file_path = frames.last()?.file_path.as_ref()?;
                Some(file_path.display_path())
            }

            let path_stack = if let Some(path) = get_outer_function_location(&addr_info) {
                match stack_prefix_for_path.get(&path) {
                    Some(ps) => *ps,
                    None => {
                        let path = path.trim_start_matches("C:\\b\\s\\w\\ir\\cache\\builder\\");
                        let mut accum_path = String::new();

                        let mut path_stack = section_stack;

                        for p in path.split(['/', '\\']) {
                            use std::fmt::Write;
                            write!(&mut accum_path, "/{p}").unwrap();
                            let frame_str = profile.intern_string(&accum_path);
                            let frame = profile.intern_frame(
                                thread,
                                FrameInfo {
                                    frame: Frame::Label(frame_str),
                                    flags: FrameFlags::empty(),
                                    category_pair: category,
                                },
                            );
                            path_stack = profile.intern_stack(thread, Some(path_stack), frame);
                        }
                        stack_prefix_for_path.insert(path.to_owned(), path_stack);
                        path_stack
                    }
                }
            } else {
                unknown_path_stack
            };

            let stack = if let Some(addr_info) = addr_info {
                let symbol_addr = addr_info.symbol.address;
                let mut s = path_stack;
                if let Some(mut frames) = addr_info.frames {
                    frames.reverse();
                    for f in frames {
                        let name = f
                            .function
                            .unwrap_or_else(|| format!("unnamed_{symbol_addr:x}"));
                        let name = profile.intern_string(&name);
                        let frame = profile.intern_frame(
                            thread,
                            FrameInfo {
                                frame: Frame::Label(name),
                                flags: FrameFlags::empty(),
                                category_pair: category,
                            },
                        );
                        s = profile.intern_stack(thread, Some(s), frame);
                    }
                } else {
                    let name = profile.intern_string(&addr_info.symbol.name);
                    let frame = profile.intern_frame(
                        thread,
                        FrameInfo {
                            frame: Frame::Label(name),
                            flags: FrameFlags::empty(),
                            category_pair: category,
                        },
                    );
                    s = profile.intern_stack(thread, Some(s), frame);
                }
                s
            } else {
                profile.intern_stack(thread, Some(path_stack), unknown_bytes_frame)
            };

            weight += 1;

            if let Some(last_stack) = last_stack {
                if stack != last_stack {
                    profile.add_sample(
                        thread,
                        Timestamp::from_millis_since_reference(time as f64),
                        Some(last_stack),
                        CpuDelta::ZERO,
                        weight,
                    );
                    weight = 0;
                }
            }
            time += 1;
            last_stack = Some(stack);
        }
        profile.add_sample(
            thread,
            Timestamp::from_millis_since_reference(time as f64),
            last_stack,
            CpuDelta::ZERO,
            weight,
        );

        pb.finish_with_message("Section processed");
    }
}
