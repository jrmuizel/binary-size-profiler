use std::ops::Range;

use fxprof_processed_profile::{
    CategoryHandle, CpuDelta, FrameFlags, Profile, StackHandle, ThreadHandle, Timestamp,
};

/// The profile under construction, plus the context that every sample shares.
///
/// The profile's time axis is the file offset: a sample at "time" `t` describes
/// the byte at file offset `t`, and a sample's weight is a byte count.
pub struct ProfileBuilder {
    /// Exposed directly because emitting symbolicated frames needs most of the
    /// `Profile` API; wrapping it would be all forwarding and no value.
    pub profile: Profile,
    thread: ThreadHandle,
    category: CategoryHandle,
}

impl ProfileBuilder {
    pub fn new(profile: Profile, thread: ThreadHandle, category: CategoryHandle) -> Self {
        Self {
            profile,
            thread,
            category,
        }
    }

    pub fn category(&self) -> CategoryHandle {
        self.category
    }

    /// Attribute the bytes in `range` to `stack`, as two samples: one opening the
    /// range at its first byte and one closing it at its last.
    ///
    /// The front-end's activity graph fills the space between consecutive
    /// samples, so a range is only drawn in its own colour if the samples on both
    /// sides of it are its own. With one sample per range, each range's space
    /// would be bounded by the next range's sample and take the next range's
    /// colour.
    ///
    /// Adjacent ranges therefore have two samples at the same file offset, one
    /// closing the earlier range and one opening the later one. The space between
    /// those is zero wide, so nothing is drawn for it.
    pub fn sample(&mut self, range: Range<u64>, stack: StackHandle) {
        let bytes = range.end - range.start;

        // The opening sample has a CPU delta of zero because the sample before it
        // sits at the same file offset, and a CPU delta over a zero-wide gap
        // would be an infinite height.
        self.add_sample(range.start, 0, CpuDelta::ZERO, stack);

        // The graph's height is the CPU delta divided by how far apart the two
        // samples are. One byte of file offset is one millisecond of "time", so a
        // delta of one millisecond per byte fills the graph to the top.
        self.add_sample(range.end, bytes, CpuDelta::from_millis(bytes as f64), stack);
    }

    fn add_sample(
        &mut self,
        file_offset: u64,
        bytes: u64,
        cpu_delta: CpuDelta,
        stack: StackHandle,
    ) {
        self.profile.add_sample(
            self.thread,
            Timestamp::from_millis_since_reference(file_offset as f64),
            Some(stack),
            cpu_delta,
            i32::try_from(bytes).unwrap(),
        );
    }

    /// A stack ending in a plain label frame, e.g. a section or segment name.
    pub fn labelled_stack(&mut self, parent: Option<StackHandle>, label: &str) -> StackHandle {
        let s = self.profile.handle_for_string(label);
        let frame = self
            .profile
            .handle_for_frame_with_label(s, self.category, FrameFlags::empty());
        self.profile.handle_for_stack(frame, parent)
    }
}

/// A contiguous byte range of the file which is subdivided into labelled child
/// ranges, in ascending file order.
///
/// Children are claimed one at a time via [`Region::child`] or [`Region::leaf`].
/// Bytes that no child claims — padding, alignment, or anything we failed to
/// recognise — are attributed to the region itself, so they still show up in the
/// profile under the region's own stack instead of silently vanishing.
///
/// This is the one place that knows how to detect overlaps and fill gaps, so
/// every level of the hierarchy (fat members, segments, sections, and whatever
/// comes next) gets that behaviour for free.
pub struct Region {
    range: Range<u64>,
    stack: StackHandle,
    /// What this region is, used in panic messages.
    label: String,
    /// End of the most recently claimed child range.
    cursor: u64,
    last_child_label: Option<String>,
}

impl Region {
    pub fn new(range: Range<u64>, stack: StackHandle, label: &str) -> Self {
        Self {
            cursor: range.start,
            range,
            stack,
            label: label.to_owned(),
            last_child_label: None,
        }
    }

    /// The stack that unclaimed bytes in this region are attributed to. Callers
    /// that build deeper stacks themselves use this as their prefix.
    pub fn stack(&self) -> StackHandle {
        self.stack
    }

    pub fn range(&self) -> Range<u64> {
        self.range.clone()
    }

    /// Claim `range` for a child region, which gets its own label frame on top of
    /// this region's stack.
    pub fn child(&mut self, b: &mut ProfileBuilder, range: Range<u64>, label: &str) -> Region {
        self.claim(b, &range, label);
        self.last_child_label = Some(label.to_owned());
        let stack = b.labelled_stack(Some(self.stack), label);
        Region::new(range, stack, label)
    }

    /// Claim `range` and attribute it to `stack` directly, without creating a
    /// child region. Used by breakdowns that build their own deeper stacks, such
    /// as the per-address symbolication of text sections.
    pub fn leaf(&mut self, b: &mut ProfileBuilder, range: Range<u64>, stack: StackHandle) {
        self.claim(b, &range, "an address range");
        b.sample(range, stack);
    }

    fn claim(&mut self, b: &mut ProfileBuilder, range: &Range<u64>, what: &str) {
        if range.start < self.cursor {
            let previous = match &self.last_child_label {
                Some(label) => format!("child {label}"),
                None => "the previous child".to_owned(),
            };
            panic!(
                "Overlapping children of {}: {what} starts at file offset {:#x}, \
                 which is before the end file offset {:#x} of {previous}",
                self.label, range.start, self.cursor
            );
        }
        if range.start > self.cursor {
            b.sample(self.cursor..range.start, self.stack);
        }
        self.cursor = range.end;
    }

    /// Attribute any bytes after the last child to this region, and check that no
    /// child ran past the end.
    pub fn finish(self, b: &mut ProfileBuilder) {
        if self.cursor > self.range.end {
            let previous = match &self.last_child_label {
                Some(label) => format!("child {label}"),
                None => "its last child".to_owned(),
            };
            panic!(
                "Truncated {}: it ends at file offset {:#x}, which is before the \
                 end file offset {:#x} of {previous}",
                self.label, self.range.end, self.cursor
            );
        }
        if self.cursor < self.range.end {
            b.sample(self.cursor..self.range.end, self.stack);
        }
    }
}
