mod binary;
mod emit;
mod symbols;
mod text;

use std::path::Path;

use fxprof_processed_profile::{
    CategoryHandle, Profile, ProfileFormat, ReferenceTimestamp, SamplingInterval, ThreadHandle,
    TimelineUnit, Timestamp, WeightType,
};
use memmap2::Mmap;
use mimalloc::MiMalloc;
use object::read::macho::{FatArch, MachOFatFile32};
use object::{File, FileKind};
use wholesym::samply_symbols::object;

use crate::emit::{ProfileBuilder, Region};
use crate::symbols::Symbolicator;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = &std::env::args().nth(1).unwrap();
    let file_name = Path::new(path).file_name().unwrap().to_str().unwrap();

    // Map the binary instead of reading it: for a universal XUL this is ~466MB of
    // resident memory we never have to hold, and the pages we touch are read once.
    let file = std::fs::File::open(path).unwrap();
    let data = unsafe { Mmap::map(&file).unwrap() };

    let (profile, thread) = new_profile(file_name);
    let mut b = ProfileBuilder::new(profile, thread, CategoryHandle::OTHER);

    let root_stack = b.labelled_stack(None, "(root)");
    let mut root = Region::new(0..data.len() as u64, root_stack, "the file");

    let symbolicator = Symbolicator::new();

    match FileKind::parse(&data[..]).unwrap() {
        FileKind::MachOFat32 => {
            process_fat_file(&mut b, &mut root, &symbolicator, Path::new(path), &data).await
        }
        _ => {
            let object_file = File::parse(&data[..]).unwrap();
            let symbols = symbolicator.load(Path::new(path), &object_file).await;
            binary::process_binary(&mut b, &mut root, &object_file, symbols).await;
        }
    }

    root.finish(&mut b);

    // Add a final sample with zero weight, so that the profiler's automatic time range detection
    // includes all the file bytes.
    b.weighted_sample(data.len() as u64, 0, root_stack);

    let output_file = std::fs::File::create("output.jslb").unwrap();
    let writer = std::io::BufWriter::new(output_file);
    b.profile
        .to_writer(writer, ProfileFormat::JsonSlabs)
        .unwrap();

    Ok(())
}

/// Break a Mach-O universal binary down into its per-architecture members.
async fn process_fat_file(
    b: &mut ProfileBuilder,
    root: &mut Region,
    symbolicator: &Symbolicator,
    path: &Path,
    data: &[u8],
) {
    for member in MachOFatFile32::parse(data).unwrap().arches() {
        let start = member.offset() as u64;
        let member_range = start..start + member.size() as u64;

        let member_data = &data[member_range.start as usize..member_range.end as usize];
        let object_file = File::parse(member_data).unwrap();

        let symbols = symbolicator.load(path, &object_file).await;

        let member_name = match &symbols.lib_info.arch {
            Some(name) => name.to_owned(),
            None => format!(
                "Fat32 archive member with cputype {} and cpusubtype {}",
                member.cputype(),
                member.cpusubtype()
            ),
        };

        let mut member_region = root.child(b, member_range, &member_name);
        binary::process_binary(b, &mut member_region, &object_file, symbols).await;
        member_region.finish(b);
    }
}

/// A profile whose time axis is the file offset and whose sample weights are
/// byte counts, with the single thread that all samples go onto.
fn new_profile(file_name: &str) -> (Profile, ThreadHandle) {
    let mut profile = Profile::new(
        "size-profiler",
        ReferenceTimestamp::from_millis_since_unix_epoch(0.),
        SamplingInterval::from_hz(1000.),
    );
    profile.set_timeline_unit(TimelineUnit::Bytes);

    let process = profile.add_process(file_name, 0, Timestamp::from_millis_since_reference(0.));
    let thread = profile.add_thread(process, 0, Timestamp::from_millis_since_reference(0.), true);
    profile.set_thread_samples_weight_type(thread, WeightType::Bytes);
    profile.set_symbolicated(true);

    (profile, thread)
}
