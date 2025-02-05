use std::path::Path;

use fxprof_processed_profile::{
    CategoryHandle, CpuDelta, Frame, FrameFlags, FrameInfo, Profile, ReferenceTimestamp,
    SamplingInterval, Timestamp, WeightType,
};
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

#[allow(unused)]
use mimalloc::MiMalloc;

use indicatif::{ProgressBar, ProgressStyle};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;

    let path = &std::env::args().nth(1).unwrap();
    let file_name = Path::new(path).file_name().unwrap().to_str().unwrap();

    let mut data = Vec::new();
    let mut file = std::fs::File::open(path).unwrap();
    file.read_to_end(&mut data).unwrap();

    let file_kind = FileKind::parse(&data[..]).unwrap();

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

    let config = SymbolManagerConfig::default()
        .respect_nt_symbol_path(true)
        .breakpad_symbols_server(
            "https://symbols.mozilla.org/try/",
            "./breakpad-symbol-cache/",
        )
        .breakpad_symindex_cache_dir("./breakpad-symindex-cache/");
    let symbol_manager = SymbolManager::with_config(config);
    let symbol_map = symbol_manager
        .load_symbol_map_for_binary_at_path(Path::new(path), disambiguator)
        .await
        .unwrap();

    let mut profile = Profile::new(
        "size-profiler",
        ReferenceTimestamp::from_millis_since_unix_epoch(0.),
        SamplingInterval::from_hz(1000.),
    );
    let process = profile.add_process(file_name, 0, Timestamp::from_millis_since_reference(0.));
    let thread = profile.add_thread(process, 0, Timestamp::from_millis_since_reference(0.), true);
    profile.set_thread_samples_weight_type(thread, WeightType::Bytes);
    let category = CategoryHandle::OTHER.into();

    let base_addr = relative_address_base(&object_file);

    for s in object_file.sections() {
        let section_size = s.size();
        let section_start_rel = s.address() - base_addr;
        let mut addr = section_start_rel;
        let mut time = 0;
        eprintln!("Processing section: {}", s.name().unwrap());

        let pb = ProgressBar::new(section_size);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})").unwrap()
            .progress_chars("#>-"));

        let mut last_stack = None;
        let mut weight = 1;
        for _ in 0..section_size {
            if addr & 0xffff == 0 {
                pb.set_position((addr - section_start_rel) as u64);
            }

            let addr_info = symbol_map
                .lookup(wholesym::LookupAddress::Relative(addr as u32))
                .await;
            let Some(addr_info) = addr_info else {
                addr += 1;
                time += 1;
                continue;
            };
            let mut sample_frames: Vec<_> = Vec::new();
            let symbol_addr = addr_info.symbol.address;

            if let Some(mut frames) = addr_info.frames {
                frames.reverse();

                fn get_outer_function_location(
                    frames: &[wholesym::FrameDebugInfo],
                ) -> Option<String> {
                    let file_path = frames.first()?.file_path.as_ref()?;
                    Some(file_path.display_path())
                }

                if let Some(path) = get_outer_function_location(&frames) {
                    let path = path.trim_start_matches("C:\\b\\s\\w\\ir\\cache\\builder\\");
                    let mut accum_path = String::new();
                    for p in path.split(['/', '\\']) {
                        use std::fmt::Write;
                        write!(&mut accum_path, "/{p}").unwrap();
                        sample_frames.push(FrameInfo {
                            frame: Frame::Label(profile.intern_string(&accum_path)),
                            flags: FrameFlags::empty(),
                            category_pair: category,
                        });
                    }
                }

                for f in frames {
                    let name = f
                        .function
                        .unwrap_or_else(|| format!("unnamed_{symbol_addr:x}"));
                    sample_frames.push(FrameInfo {
                        frame: Frame::Label(profile.intern_string(&name)),
                        flags: FrameFlags::empty(),
                        category_pair: category,
                    });
                }
            } else {
                sample_frames.push(FrameInfo {
                    frame: Frame::Label(profile.intern_string(&addr_info.symbol.name)),
                    flags: FrameFlags::empty(),
                    category_pair: category,
                });
            }

            let stack = profile.intern_stack_frames(thread, sample_frames.into_iter());
            if stack != last_stack {
                profile.add_sample(
                    thread,
                    Timestamp::from_millis_since_reference(time as f64),
                    last_stack,
                    CpuDelta::ZERO,
                    weight,
                );
                weight = 1;
            } else {
                weight += 1;
            }
            last_stack = stack;

            time += 1;
            addr += 1;
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
    let output_file = std::fs::File::create("output.json").unwrap();
    let writer = std::io::BufWriter::new(output_file);
    serde_json::to_writer(writer, &profile).unwrap();

    Ok(())
}
