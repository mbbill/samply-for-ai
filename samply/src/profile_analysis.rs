//! Profile analysis engine for computing hotspots, call trees, and summaries.
//!
//! This module parses Firefox Profiler JSON format and provides analysis capabilities.

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

/// Deserialize a Vec where -1 values are treated as None
fn deserialize_optional_i64_as_u64<'de, D>(deserializer: D) -> Result<Vec<Option<u64>>, D::Error>
where
    D: Deserializer<'de>,
{
    let values: Vec<Option<i64>> = Vec::deserialize(deserializer)?;
    Ok(values
        .into_iter()
        .map(|v| match v {
            Some(n) if n >= 0 => Some(n as u64),
            _ => None,
        })
        .collect())
}

/// Error type for profile analysis operations
#[derive(Debug)]
pub enum AnalysisError {
    IoError(std::io::Error),
    JsonError(serde_json::Error),
    InvalidProfile(String),
}

impl std::fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalysisError::IoError(e) => write!(f, "IO error: {}", e),
            AnalysisError::JsonError(e) => write!(f, "JSON parse error: {}", e),
            AnalysisError::InvalidProfile(msg) => write!(f, "Invalid profile: {}", msg),
        }
    }
}

impl std::error::Error for AnalysisError {}

impl From<std::io::Error> for AnalysisError {
    fn from(e: std::io::Error) -> Self {
        AnalysisError::IoError(e)
    }
}

impl From<serde_json::Error> for AnalysisError {
    fn from(e: serde_json::Error) -> Self {
        AnalysisError::JsonError(e)
    }
}

// ============================================================================
// JSON structures for parsing Firefox Profiler format
// ============================================================================

#[derive(Debug, Deserialize)]
struct RawProfile {
    meta: RawMeta,
    #[serde(default)]
    libs: Vec<RawLib>,
    threads: Vec<RawThread>,
    #[serde(default)]
    shared: Option<RawShared>,
}

#[derive(Debug, Deserialize, Clone)]
struct RawLib {
    #[serde(default)]
    name: String,
    #[serde(default)]
    path: String,
    #[serde(rename = "debugName", default)]
    debug_name: String,
    #[serde(rename = "debugPath", default)]
    debug_path: String,
    #[serde(rename = "breakpadId", default)]
    breakpad_id: String,
    #[serde(rename = "codeId", default)]
    code_id: String,
    #[serde(default)]
    arch: String,
}

#[derive(Debug, Deserialize)]
struct RawMeta {
    #[serde(default)]
    product: String,
    #[serde(default)]
    interval: f64,
    #[serde(rename = "startTime", default)]
    start_time: f64,
}

#[derive(Debug, Deserialize)]
struct RawShared {
    #[serde(rename = "stringArray", default)]
    string_array: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawThread {
    #[serde(default)]
    name: String,
    #[serde(default)]
    pid: String,
    #[serde(default)]
    tid: String,
    #[serde(rename = "isMainThread", default)]
    is_main_thread: bool,
    #[serde(rename = "processName", default)]
    process_name: String,
    samples: RawSamples,
    #[serde(rename = "stackTable")]
    stack_table: RawStackTable,
    #[serde(rename = "frameTable")]
    frame_table: RawFrameTable,
    #[serde(rename = "funcTable")]
    func_table: RawFuncTable,
    #[serde(rename = "nativeSymbols", default)]
    native_symbols: Option<RawNativeSymbols>,
    #[serde(rename = "resourceTable", default)]
    resource_table: Option<RawResourceTable>,
    #[serde(rename = "stringTable", default)]
    string_table: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawSamples {
    #[serde(default)]
    stack: Vec<Option<usize>>,
    #[serde(default)]
    weight: Vec<i64>,
    #[serde(default)]
    length: usize,
}

#[derive(Debug, Deserialize)]
struct RawStackTable {
    #[serde(default)]
    prefix: Vec<Option<usize>>,
    #[serde(default)]
    frame: Vec<usize>,
    #[serde(default)]
    length: usize,
}

#[derive(Debug, Deserialize)]
struct RawFrameTable {
    #[serde(default)]
    func: Vec<usize>,
    #[serde(default)]
    line: Vec<Option<u32>>,
    #[serde(default, deserialize_with = "deserialize_optional_i64_as_u64")]
    address: Vec<Option<u64>>,
    #[serde(rename = "nativeSymbol", default)]
    native_symbol: Vec<Option<usize>>,
    #[serde(default)]
    length: usize,
}

#[derive(Debug, Deserialize)]
struct RawFuncTable {
    #[serde(default)]
    name: Vec<usize>, // Indices into string table
    #[serde(rename = "fileName", default)]
    file_name: Vec<Option<usize>>,
    #[serde(rename = "lineNumber", default)]
    line_number: Vec<Option<u32>>,
    #[serde(default)]
    resource: Vec<Option<i32>>, // Resource index (-1 if none)
    #[serde(default)]
    length: usize,
}

#[derive(Debug, Deserialize, Default)]
struct RawNativeSymbols {
    #[serde(default)]
    address: Vec<u64>,
    #[serde(rename = "functionSize", default)]
    function_size: Vec<Option<u32>>,
    #[serde(rename = "libIndex", default)]
    lib_index: Vec<usize>,
    #[serde(default)]
    name: Vec<usize>,
    #[serde(default)]
    length: usize,
}

#[derive(Debug, Deserialize, Default)]
struct RawResourceTable {
    #[serde(default)]
    lib: Vec<Option<usize>>,
    #[serde(default)]
    name: Vec<usize>,
    #[serde(default)]
    length: usize,
}

// ============================================================================
// Analysis result types (for JSON output)
// ============================================================================

/// Debug information for source/asm lookups
#[derive(Debug, Clone, Serialize)]
pub struct DebugInfo {
    pub debug_name: String,
    pub debug_id: String,
}

/// Extended function information with library, address, and size
#[derive(Debug, Clone, Serialize)]
pub struct FunctionInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>, // Hex string like "0x12340"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
}

/// Per-line sample information
#[derive(Debug, Clone, Serialize)]
pub struct HotLine {
    pub line: u32,
    pub samples: i64,
    pub percent: f64,
}

/// Per-address sample information with source line mapping
#[derive(Debug, Clone, Serialize)]
pub struct HotAddress {
    pub offset: u64,  // Offset from function start
    pub address: String, // Absolute address as hex string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_line: Option<u32>, // Source line if available
    pub samples: i64,
    pub percent: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HotspotEntry {
    pub rank: usize,
    pub function: FunctionInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_info: Option<DebugInfo>,
    pub self_samples: i64,
    pub total_samples: i64,
    pub self_percent: f64,
    pub total_percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_chain: Option<Vec<CallerSummary>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hot_lines: Option<Vec<HotLine>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hot_addresses: Option<Vec<HotAddress>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CallerSummary {
    pub name: String,
    pub percent: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CallerEntry {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    pub call_count: i64,
    pub percent: f64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub callers: Vec<CallerEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CalleeEntry {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    pub call_count: i64,
    pub percent: f64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub callees: Vec<CalleeEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreadSummary {
    pub name: String,
    pub pid: String,
    pub tid: String,
    pub is_main: bool,
    pub sample_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileSummary {
    pub product_name: String,
    pub total_samples: i64,
    pub sampling_interval_ms: f64,
    pub thread_count: usize,
    pub threads: Vec<ThreadSummary>,
    /// Whether the profile appears to be symbolicated (function names are readable, not hex addresses)
    pub is_symbolicated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CallersResponse {
    pub function: String,
    pub callers: Vec<CallerEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CalleesResponse {
    pub function: String,
    pub callees: Vec<CalleeEntry>,
}

/// A single disassembled instruction
#[derive(Debug, Clone, Serialize)]
pub struct AsmInstruction {
    pub address: String,
    pub asm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub samples: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent: Option<f64>,
}

/// A region of instructions grouped by source line
#[derive(Debug, Clone, Serialize)]
pub struct AsmRegion {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_text: Option<String>,
    pub instructions: Vec<AsmInstruction>,
}

/// Response for assembly query
#[derive(Debug, Clone, Serialize)]
pub struct AsmResponse {
    pub function: FunctionInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    /// Regions of instructions with context around hot spots
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regions: Option<Vec<AsmRegion>>,
    /// Total self samples in this function
    pub self_samples: i64,
    /// Error message if disassembly failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ============================================================================
// Drilldown response types
// ============================================================================

/// A callee in the drilldown path with time percentage
#[derive(Debug, Clone, Serialize)]
pub struct DrilldownCallee {
    pub name: String,
    pub percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_hottest: Option<bool>,
}

/// One node in the drilldown path
#[derive(Debug, Clone, Serialize)]
pub struct DrilldownNode {
    pub function: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    pub total_samples: i64,
    pub total_percent: f64,
    pub self_samples: i64,
    pub self_percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_bottleneck: Option<bool>,
    pub callees: Vec<DrilldownCallee>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hot_lines: Option<Vec<HotLine>>,
}

/// Summary of detected bottleneck
#[derive(Debug, Clone, Serialize)]
pub struct BottleneckSummary {
    pub function: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    pub self_percent: f64,
    pub reason: String,
}

/// Response for drilldown query
#[derive(Debug, Clone, Serialize)]
pub struct DrilldownResponse {
    pub root: String,
    pub total_samples: i64,
    pub path: Vec<DrilldownNode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bottleneck: Option<BottleneckSummary>,
    /// Error message if function was not found or had no samples
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Top functions as suggestions when the requested function wasn't found
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestions: Option<Vec<String>>,
}

// ============================================================================
// ProfileAnalyzer - main analysis engine
// ============================================================================

/// Library information
#[derive(Debug, Clone)]
struct LibInfo {
    name: String,
    path: String,
    debug_name: String,
    debug_id: String, // breakpadId
    arch: String,
}

/// Native symbol information for a function
#[derive(Debug, Clone, Default)]
struct NativeSymbolInfo {
    address: u64,
    size: Option<u32>,
    lib_index: Option<usize>,
}

/// Holds parsed profile data and provides analysis methods
pub struct ProfileAnalyzer {
    product_name: String,
    sampling_interval_ms: f64,
    threads: Vec<ThreadData>,
    /// Global string table (from shared.stringArray if present)
    global_strings: Vec<String>,
    /// Library information
    libs: Vec<LibInfo>,
}

struct ThreadData {
    name: String,
    pid: String,
    tid: String,
    is_main_thread: bool,
    /// (stack_index, weight) pairs
    samples: Vec<(Option<usize>, i64)>,
    /// Stack table: prefix[i] and frame[i] for stack i
    stack_prefix: Vec<Option<usize>>,
    stack_frame: Vec<usize>,
    /// Frame table: func[i] for frame i
    frame_func: Vec<usize>,
    /// Frame table: address and line for each frame
    frame_address: Vec<Option<u64>>,
    frame_line: Vec<Option<u32>>,
    frame_native_symbol: Vec<Option<usize>>,
    /// Func table: name string index, file name index, line number, resource
    func_name_idx: Vec<usize>,
    func_file_idx: Vec<Option<usize>>,
    func_line: Vec<Option<u32>>,
    func_resource: Vec<Option<i32>>,
    /// Native symbols: address, size, lib_index per symbol
    native_symbols: Vec<NativeSymbolInfo>,
    /// Resource table: lib_index per resource
    resource_lib: Vec<Option<usize>>,
    /// Local string table
    string_table: Vec<String>,
}

impl ThreadData {
    fn get_string(&self, idx: usize, global_strings: &[String]) -> String {
        // Try local string table first, then global
        if idx < self.string_table.len() {
            self.string_table[idx].clone()
        } else if idx < global_strings.len() {
            global_strings[idx].clone()
        } else {
            format!("<string {}>", idx)
        }
    }

    fn get_func_name(&self, func_idx: usize, global_strings: &[String]) -> String {
        if func_idx < self.func_name_idx.len() {
            let name_idx = self.func_name_idx[func_idx];
            self.get_string(name_idx, global_strings)
        } else {
            format!("<func {}>", func_idx)
        }
    }

    fn get_func_file(&self, func_idx: usize, global_strings: &[String]) -> Option<String> {
        if func_idx < self.func_file_idx.len() {
            self.func_file_idx[func_idx].map(|idx| self.get_string(idx, global_strings))
        } else {
            None
        }
    }

    fn get_func_line(&self, func_idx: usize) -> Option<u32> {
        if func_idx < self.func_line.len() {
            self.func_line[func_idx]
        } else {
            None
        }
    }

    /// Get library index for a function via resource table
    fn get_func_lib_index(&self, func_idx: usize) -> Option<usize> {
        if func_idx < self.func_resource.len() {
            if let Some(res_idx) = self.func_resource[func_idx] {
                if res_idx >= 0 && (res_idx as usize) < self.resource_lib.len() {
                    return self.resource_lib[res_idx as usize];
                }
            }
        }
        None
    }

    fn get_frame_func(&self, frame_idx: usize) -> usize {
        if frame_idx < self.frame_func.len() {
            self.frame_func[frame_idx]
        } else {
            0
        }
    }

    fn get_frame_address(&self, frame_idx: usize) -> Option<u64> {
        if frame_idx < self.frame_address.len() {
            self.frame_address[frame_idx]
        } else {
            None
        }
    }

    fn get_frame_line(&self, frame_idx: usize) -> Option<u32> {
        if frame_idx < self.frame_line.len() {
            self.frame_line[frame_idx]
        } else {
            None
        }
    }

    fn get_frame_native_symbol(&self, frame_idx: usize) -> Option<&NativeSymbolInfo> {
        if frame_idx < self.frame_native_symbol.len() {
            if let Some(ns_idx) = self.frame_native_symbol[frame_idx] {
                return self.native_symbols.get(ns_idx);
            }
        }
        None
    }

    fn get_stack_frame(&self, stack_idx: usize) -> usize {
        if stack_idx < self.stack_frame.len() {
            self.stack_frame[stack_idx]
        } else {
            0
        }
    }

    fn get_stack_prefix(&self, stack_idx: usize) -> Option<usize> {
        if stack_idx < self.stack_prefix.len() {
            self.stack_prefix[stack_idx]
        } else {
            None
        }
    }

    /// Walk the stack from leaf to root, collecting function indices
    fn walk_stack(&self, stack_idx: usize) -> Vec<usize> {
        let mut funcs = Vec::new();
        let mut current = Some(stack_idx);

        while let Some(idx) = current {
            let frame_idx = self.get_stack_frame(idx);
            let func_idx = self.get_frame_func(frame_idx);
            funcs.push(func_idx);
            current = self.get_stack_prefix(idx);
        }

        funcs
    }

    /// Walk the stack from leaf to root, collecting (func_idx, frame_idx) pairs
    fn walk_stack_with_frames(&self, stack_idx: usize) -> Vec<(usize, usize)> {
        let mut result = Vec::new();
        let mut current = Some(stack_idx);

        while let Some(idx) = current {
            let frame_idx = self.get_stack_frame(idx);
            let func_idx = self.get_frame_func(frame_idx);
            result.push((func_idx, frame_idx));
            current = self.get_stack_prefix(idx);
        }

        result
    }
}

impl ProfileAnalyzer {
    /// Load and parse a profile from a file path
    pub fn from_file(path: &Path) -> Result<Self, AnalysisError> {
        let file = File::open(path)?;

        // Handle gzipped files
        let profile: RawProfile = if path.extension().map_or(false, |e| e == "gz") {
            let decoder = flate2::read::GzDecoder::new(file);
            let reader = BufReader::new(decoder);
            serde_json::from_reader(reader)?
        } else {
            let reader = BufReader::new(file);
            serde_json::from_reader(reader)?
        };

        Self::from_raw_profile(profile)
    }

    fn from_raw_profile(raw: RawProfile) -> Result<Self, AnalysisError> {
        let global_strings = raw.shared.map(|s| s.string_array).unwrap_or_default();

        // Extract library information
        let libs: Vec<LibInfo> = raw
            .libs
            .into_iter()
            .map(|lib| LibInfo {
                name: lib.name,
                path: lib.path,
                debug_name: lib.debug_name,
                debug_id: lib.breakpad_id,
                arch: lib.arch,
            })
            .collect();

        let threads: Vec<ThreadData> = raw
            .threads
            .into_iter()
            .map(|t| {
                // Extract native symbols
                let native_symbols: Vec<NativeSymbolInfo> = t
                    .native_symbols
                    .map(|ns| {
                        (0..ns.length)
                            .map(|i| NativeSymbolInfo {
                                address: ns.address.get(i).copied().unwrap_or(0),
                                size: ns.function_size.get(i).copied().flatten(),
                                lib_index: ns.lib_index.get(i).copied(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // Extract resource table (lib mapping)
                let resource_lib: Vec<Option<usize>> = t
                    .resource_table
                    .map(|rt| rt.lib)
                    .unwrap_or_default();

                ThreadData {
                    name: t.name,
                    pid: t.pid,
                    tid: t.tid,
                    is_main_thread: t.is_main_thread,
                    samples: t
                        .samples
                        .stack
                        .into_iter()
                        .zip(t.samples.weight.into_iter())
                        .collect(),
                    stack_prefix: t.stack_table.prefix,
                    stack_frame: t.stack_table.frame,
                    frame_func: t.frame_table.func,
                    frame_address: t.frame_table.address,
                    frame_line: t.frame_table.line,
                    frame_native_symbol: t.frame_table.native_symbol,
                    func_name_idx: t.func_table.name,
                    func_file_idx: t.func_table.file_name,
                    func_line: t.func_table.line_number,
                    func_resource: t.func_table.resource,
                    native_symbols,
                    resource_lib,
                    string_table: t.string_table,
                }
            })
            .collect();

        Ok(Self {
            product_name: raw.meta.product,
            sampling_interval_ms: raw.meta.interval,
            threads,
            global_strings,
            libs,
        })
    }

    /// Compute hotspots across all threads
    ///
    /// By default, hot_lines and hot_addresses are NOT included to keep output compact.
    /// Pass include_lines=true or include_addresses=true to include them.
    pub fn compute_hotspots(
        &self,
        limit: usize,
        thread_filter: Option<&str>,
        include_lines: bool,
        include_addresses: bool,
    ) -> Vec<HotspotEntry> {
        // Extended tracking structure for each function
        #[derive(Default)]
        struct FuncStats {
            self_samples: i64,
            total_samples: i64,
            func_idx: Option<usize>,
            thread_idx: Option<usize>,
            // Per-line sample counts (line_number -> samples)
            line_samples: HashMap<u32, i64>,
            // Per-address sample counts (address -> samples)
            address_samples: HashMap<u64, i64>,
        }

        let mut func_stats: HashMap<String, FuncStats> = HashMap::new();
        let mut total_weight: i64 = 0;

        // Aggregate samples across threads
        for (thread_idx, thread) in self.threads.iter().enumerate() {
            // Apply thread filter if specified
            if let Some(filter) = thread_filter {
                if !thread.name.contains(filter) {
                    continue;
                }
            }

            for (stack_idx_opt, weight) in &thread.samples {
                total_weight += weight;

                if let Some(stack_idx) = stack_idx_opt {
                    // Walk stack with frame info for per-line/address tracking
                    let stack_with_frames = thread.walk_stack_with_frames(*stack_idx);

                    // Self time: only for the leaf function (first in the list)
                    if let Some(&(leaf_func_idx, leaf_frame_idx)) = stack_with_frames.first() {
                        let name = thread.get_func_name(leaf_func_idx, &self.global_strings);
                        let stats = func_stats.entry(name).or_default();
                        stats.self_samples += weight;

                        // Store func/thread indices for later info lookup
                        if stats.func_idx.is_none() {
                            stats.func_idx = Some(leaf_func_idx);
                            stats.thread_idx = Some(thread_idx);
                        }

                        // Track per-line samples
                        if let Some(line) = thread.get_frame_line(leaf_frame_idx) {
                            *stats.line_samples.entry(line).or_insert(0) += weight;
                        }

                        // Track per-address samples
                        if let Some(addr) = thread.get_frame_address(leaf_frame_idx) {
                            *stats.address_samples.entry(addr).or_insert(0) += weight;
                        }
                    }

                    // Total time: for each unique function in stack
                    let mut seen = std::collections::HashSet::new();
                    for (func_idx, _frame_idx) in &stack_with_frames {
                        let name = thread.get_func_name(*func_idx, &self.global_strings);
                        if seen.insert(name.clone()) {
                            let stats = func_stats.entry(name).or_default();
                            stats.total_samples += weight;

                            // Store func/thread indices
                            if stats.func_idx.is_none() {
                                stats.func_idx = Some(*func_idx);
                                stats.thread_idx = Some(thread_idx);
                            }
                        }
                    }
                }
            }
        }

        // Convert to sorted list
        let mut hotspots: Vec<_> = func_stats.into_iter().collect();

        // Sort by self samples descending
        hotspots.sort_by(|a, b| b.1.self_samples.cmp(&a.1.self_samples));

        // Take top N and convert to HotspotEntry
        hotspots
            .into_iter()
            .take(limit)
            .enumerate()
            .map(|(i, (name, stats))| {
                // Build FunctionInfo with extended fields
                let (func_info, debug_info) = if let (Some(func_idx), Some(thread_idx)) =
                    (stats.func_idx, stats.thread_idx)
                {
                    let thread = &self.threads[thread_idx];

                    // Get library index via resource table
                    let lib_index = thread.get_func_lib_index(func_idx);
                    let library = lib_index.and_then(|idx| self.libs.get(idx).map(|l| l.name.clone()));

                    // Get debug info from library
                    let debug = lib_index.and_then(|idx| {
                        self.libs.get(idx).map(|l| DebugInfo {
                            debug_name: l.debug_name.clone(),
                            debug_id: l.debug_id.clone(),
                        })
                    });

                    // Try to get address/size from native symbols
                    // We need to find a frame that maps to this function and has native symbol info
                    let (address, size) = self.find_func_native_symbol_info(thread_idx, func_idx);

                    (
                        FunctionInfo {
                            name: name.clone(),
                            library,
                            file_path: thread.get_func_file(func_idx, &self.global_strings),
                            line_number: thread.get_func_line(func_idx),
                            address,
                            size,
                        },
                        debug,
                    )
                } else {
                    (
                        FunctionInfo {
                            name: name.clone(),
                            library: None,
                            file_path: None,
                            line_number: None,
                            address: None,
                            size: None,
                        },
                        None,
                    )
                };

                // Build hot_lines from line_samples (only if requested)
                let hot_lines = if !include_lines || stats.line_samples.is_empty() {
                    None
                } else {
                    let mut lines: Vec<_> = stats
                        .line_samples
                        .into_iter()
                        .map(|(line, samples)| HotLine {
                            line,
                            samples,
                            percent: if stats.self_samples > 0 {
                                100.0 * samples as f64 / stats.self_samples as f64
                            } else {
                                0.0
                            },
                        })
                        .collect();
                    lines.sort_by(|a, b| b.samples.cmp(&a.samples));
                    Some(lines)
                };

                // Build hot_addresses from address_samples
                // For address offset, we need the function base address
                let func_base_addr = func_info
                    .address
                    .as_ref()
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                    .unwrap_or(0);

                // Build hot_addresses from address_samples (only if requested)
                let hot_addresses = if !include_addresses || stats.address_samples.is_empty() {
                    None
                } else {
                    let mut addrs: Vec<_> = stats
                        .address_samples
                        .into_iter()
                        .map(|(addr, samples)| HotAddress {
                            offset: addr.saturating_sub(func_base_addr),
                            address: format!("0x{:x}", addr),
                            source_line: None, // Not tracked in compute_hotspots
                            samples,
                            percent: if stats.self_samples > 0 {
                                100.0 * samples as f64 / stats.self_samples as f64
                            } else {
                                0.0
                            },
                        })
                        .collect();
                    addrs.sort_by(|a, b| b.samples.cmp(&a.samples));
                    Some(addrs)
                };

                HotspotEntry {
                    rank: i + 1,
                    function: func_info,
                    debug_info,
                    self_samples: stats.self_samples,
                    total_samples: stats.total_samples,
                    self_percent: if total_weight > 0 {
                        100.0 * stats.self_samples as f64 / total_weight as f64
                    } else {
                        0.0
                    },
                    total_percent: if total_weight > 0 {
                        100.0 * stats.total_samples as f64 / total_weight as f64
                    } else {
                        0.0
                    },
                    caller_chain: None, // TODO: Add caller chain if requested
                    hot_lines,
                    hot_addresses,
                }
            })
            .collect()
    }

    /// Find native symbol info (address, size) for a function
    fn find_func_native_symbol_info(
        &self,
        thread_idx: usize,
        func_idx: usize,
    ) -> (Option<String>, Option<u32>) {
        let thread = &self.threads[thread_idx];

        // Search frames for one that maps to this function and has native symbol
        for (frame_idx, &fid) in thread.frame_func.iter().enumerate() {
            if fid == func_idx {
                if let Some(ns_info) = thread.get_frame_native_symbol(frame_idx) {
                    return (
                        Some(format!("0x{:x}", ns_info.address)),
                        ns_info.size,
                    );
                }
            }
        }

        (None, None)
    }

    /// Find callers of a function
    pub fn find_callers(&self, function_pattern: &str, depth: usize, limit: usize) -> CallersResponse {
        // Build caller graph: callee -> caller -> (count, func_idx, thread_idx)
        #[derive(Default, Clone)]
        struct FuncData {
            count: i64,
            func_idx: Option<usize>,
            thread_idx: Option<usize>,
        }
        let mut caller_data: HashMap<String, HashMap<String, FuncData>> = HashMap::new();

        for (thread_idx, thread) in self.threads.iter().enumerate() {
            for (stack_idx_opt, weight) in &thread.samples {
                if let Some(stack_idx) = stack_idx_opt {
                    let funcs = thread.walk_stack(*stack_idx);
                    let func_info: Vec<(String, usize)> = funcs
                        .iter()
                        .map(|&idx| (thread.get_func_name(idx, &self.global_strings), idx))
                        .collect();

                    // For each pair (callee, caller) in the stack
                    for i in 0..func_info.len().saturating_sub(1) {
                        let (callee_name, _) = &func_info[i];
                        let (caller_name, caller_idx) = &func_info[i + 1];
                        let data = caller_data
                            .entry(callee_name.clone())
                            .or_default()
                            .entry(caller_name.clone())
                            .or_default();
                        data.count += weight;
                        if data.func_idx.is_none() {
                            data.func_idx = Some(*caller_idx);
                            data.thread_idx = Some(thread_idx);
                        }
                    }
                }
            }
        }

        // Find matching function
        let target = self.find_matching_function(function_pattern);

        // Build caller tree recursively
        fn build_caller_tree(
            analyzer: &ProfileAnalyzer,
            caller_data: &HashMap<String, HashMap<String, FuncData>>,
            target: &str,
            depth: usize,
            limit: usize,
            visited: &mut std::collections::HashSet<String>,
        ) -> Vec<CallerEntry> {
            if depth == 0 || visited.contains(target) {
                return vec![];
            }
            visited.insert(target.to_string());

            let mut callers: Vec<_> = caller_data
                .get(target)
                .map(|callers| {
                    callers
                        .iter()
                        .map(|(caller_name, data)| {
                            let sub_callers =
                                build_caller_tree(analyzer, caller_data, caller_name, depth - 1, limit, visited);

                            // Get extended function info
                            let (library, file_path, line_number) =
                                if let (Some(func_idx), Some(thread_idx)) = (data.func_idx, data.thread_idx) {
                                    let thread = &analyzer.threads[thread_idx];
                                    let lib_idx = thread.get_func_lib_index(func_idx);
                                    (
                                        lib_idx.and_then(|idx| analyzer.libs.get(idx).map(|l| l.name.clone())),
                                        thread.get_func_file(func_idx, &analyzer.global_strings),
                                        thread.get_func_line(func_idx),
                                    )
                                } else {
                                    (None, None, None)
                                };

                            CallerEntry {
                                name: caller_name.clone(),
                                library,
                                file_path,
                                line_number,
                                call_count: data.count,
                                percent: 0.0, // Computed later
                                callers: sub_callers,
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            // Compute percentages
            let total: i64 = callers.iter().map(|c| c.call_count).sum();
            for caller in &mut callers {
                caller.percent = if total > 0 {
                    100.0 * caller.call_count as f64 / total as f64
                } else {
                    0.0
                };
            }

            callers.sort_by(|a, b| b.call_count.cmp(&a.call_count));
            callers.truncate(limit);
            visited.remove(target);
            callers
        }

        let callers = build_caller_tree(self, &caller_data, &target, depth, limit, &mut Default::default());

        CallersResponse {
            function: target,
            callers,
        }
    }

    /// Find callees of a function
    pub fn find_callees(&self, function_pattern: &str, depth: usize, limit: usize) -> CalleesResponse {
        // Build callee graph: caller -> callee -> (count, func_idx, thread_idx)
        #[derive(Default, Clone)]
        struct FuncData {
            count: i64,
            func_idx: Option<usize>,
            thread_idx: Option<usize>,
        }
        let mut callee_data: HashMap<String, HashMap<String, FuncData>> = HashMap::new();

        for (thread_idx, thread) in self.threads.iter().enumerate() {
            for (stack_idx_opt, weight) in &thread.samples {
                if let Some(stack_idx) = stack_idx_opt {
                    let funcs = thread.walk_stack(*stack_idx);
                    let func_info: Vec<(String, usize)> = funcs
                        .iter()
                        .map(|&idx| (thread.get_func_name(idx, &self.global_strings), idx))
                        .collect();

                    // For each pair (callee, caller) in the stack
                    // In our walk, index 0 is leaf, index n-1 is root
                    // So caller is at higher index, callee at lower
                    for i in 0..func_info.len().saturating_sub(1) {
                        let (callee_name, callee_idx) = &func_info[i];
                        let (caller_name, _) = &func_info[i + 1];
                        let data = callee_data
                            .entry(caller_name.clone())
                            .or_default()
                            .entry(callee_name.clone())
                            .or_default();
                        data.count += weight;
                        if data.func_idx.is_none() {
                            data.func_idx = Some(*callee_idx);
                            data.thread_idx = Some(thread_idx);
                        }
                    }
                }
            }
        }

        // Find matching function
        let target = self.find_matching_function(function_pattern);

        // Build callee tree recursively
        fn build_callee_tree(
            analyzer: &ProfileAnalyzer,
            callee_data: &HashMap<String, HashMap<String, FuncData>>,
            target: &str,
            depth: usize,
            limit: usize,
            visited: &mut std::collections::HashSet<String>,
        ) -> Vec<CalleeEntry> {
            if depth == 0 || visited.contains(target) {
                return vec![];
            }
            visited.insert(target.to_string());

            let mut callees: Vec<_> = callee_data
                .get(target)
                .map(|callees| {
                    callees
                        .iter()
                        .map(|(callee_name, data)| {
                            let sub_callees =
                                build_callee_tree(analyzer, callee_data, callee_name, depth - 1, limit, visited);

                            // Get extended function info
                            let (library, file_path, line_number) =
                                if let (Some(func_idx), Some(thread_idx)) = (data.func_idx, data.thread_idx) {
                                    let thread = &analyzer.threads[thread_idx];
                                    let lib_idx = thread.get_func_lib_index(func_idx);
                                    (
                                        lib_idx.and_then(|idx| analyzer.libs.get(idx).map(|l| l.name.clone())),
                                        thread.get_func_file(func_idx, &analyzer.global_strings),
                                        thread.get_func_line(func_idx),
                                    )
                                } else {
                                    (None, None, None)
                                };

                            CalleeEntry {
                                name: callee_name.clone(),
                                library,
                                file_path,
                                line_number,
                                call_count: data.count,
                                percent: 0.0,
                                callees: sub_callees,
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            // Compute percentages
            let total: i64 = callees.iter().map(|c| c.call_count).sum();
            for callee in &mut callees {
                callee.percent = if total > 0 {
                    100.0 * callee.call_count as f64 / total as f64
                } else {
                    0.0
                };
            }

            callees.sort_by(|a, b| b.call_count.cmp(&a.call_count));
            callees.truncate(limit);
            visited.remove(target);
            callees
        }

        let callees = build_callee_tree(self, &callee_data, &target, depth, limit, &mut Default::default());

        CalleesResponse {
            function: target,
            callees,
        }
    }

    /// Get profile summary
    pub fn get_summary(&self) -> ProfileSummary {
        let threads: Vec<ThreadSummary> = self
            .threads
            .iter()
            .map(|t| ThreadSummary {
                name: t.name.clone(),
                pid: t.pid.clone(),
                tid: t.tid.clone(),
                is_main: t.is_main_thread,
                sample_count: t.samples.len(),
            })
            .collect();

        let total_samples: i64 = self
            .threads
            .iter()
            .flat_map(|t| t.samples.iter())
            .map(|(_, w)| w)
            .sum();

        ProfileSummary {
            product_name: self.product_name.clone(),
            total_samples,
            sampling_interval_ms: self.sampling_interval_ms,
            thread_count: threads.len(),
            threads,
            is_symbolicated: !self.is_likely_unsymbolicated(),
        }
    }

    /// Check if the profile appears to be unsymbolicated.
    /// Returns true if >80% of the top 20 function names look like hex addresses (0x...).
    pub fn is_likely_unsymbolicated(&self) -> bool {
        // Get top function names by sample count
        let hotspots = self.compute_hotspots(20, None, false, false);
        if hotspots.is_empty() {
            return false;
        }

        // Count how many function names look like hex addresses
        let hex_pattern_count = hotspots
            .iter()
            .filter(|h| Self::looks_like_hex_address(&h.function.name))
            .count();

        // If >80% are hex addresses, profile is likely unsymbolicated
        let ratio = hex_pattern_count as f64 / hotspots.len() as f64;
        ratio > 0.8
    }

    /// Check if a function name looks like a hex address (e.g., "0x1efcfc")
    fn looks_like_hex_address(name: &str) -> bool {
        if !name.starts_with("0x") {
            return false;
        }
        let hex_part = &name[2..];
        !hex_part.is_empty() && hex_part.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Get assembly information for a function with sample annotations
    pub fn get_asm(&self, function_pattern: &str) -> AsmResponse {
        // Find the function and aggregate its samples
        let target = self.find_matching_function(function_pattern);

        let mut func_idx = None;
        let mut thread_idx = None;
        let mut lib_idx = None;
        let mut self_samples: i64 = 0;
        // Track (samples, source_line) per address
        let mut address_data: HashMap<u64, (i64, Option<u32>)> = HashMap::new();

        for (tidx, thread) in self.threads.iter().enumerate() {
            for (stack_idx_opt, weight) in &thread.samples {
                if let Some(stack_idx) = stack_idx_opt {
                    let stack_with_frames = thread.walk_stack_with_frames(*stack_idx);

                    // Only count self time (leaf function)
                    if let Some(&(leaf_func_idx, leaf_frame_idx)) = stack_with_frames.first() {
                        let name = thread.get_func_name(leaf_func_idx, &self.global_strings);
                        if name == target {
                            self_samples += weight;

                            if func_idx.is_none() {
                                func_idx = Some(leaf_func_idx);
                                thread_idx = Some(tidx);
                                lib_idx = thread.get_func_lib_index(leaf_func_idx);
                            }

                            // Track per-address samples with source line
                            if let Some(addr) = thread.get_frame_address(leaf_frame_idx) {
                                let line = thread.get_frame_line(leaf_frame_idx);
                                let entry = address_data.entry(addr).or_insert((0, None));
                                entry.0 += weight;
                                // Keep the first line we find for this address
                                if entry.1.is_none() {
                                    entry.1 = line;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Build function info
        let (func_info, file_path) = if let (Some(fidx), Some(tidx)) = (func_idx, thread_idx) {
            let thread = &self.threads[tidx];
            let lib_index = thread.get_func_lib_index(fidx);
            let library = lib_index.and_then(|idx| self.libs.get(idx).map(|l| l.name.clone()));
            let (address, size) = self.find_func_native_symbol_info(tidx, fidx);
            let file_path = thread.get_func_file(fidx, &self.global_strings);

            (
                FunctionInfo {
                    name: target.clone(),
                    library,
                    file_path: file_path.clone(),
                    line_number: thread.get_func_line(fidx),
                    address,
                    size,
                },
                file_path,
            )
        } else {
            (
                FunctionInfo {
                    name: target.clone(),
                    library: None,
                    file_path: None,
                    line_number: None,
                    address: None,
                    size: None,
                },
                None,
            )
        };

        // Try to disassemble
        let func_base_addr = func_info
            .address
            .as_ref()
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());

        let func_size = func_info.size;

        // Get library info for disassembly
        let lib_info = lib_idx.and_then(|idx| self.libs.get(idx));

        // Try to disassemble
        let (regions, error) = if let (Some(base_addr), Some(size), Some(lib)) = (func_base_addr, func_size, lib_info) {
            match self.disassemble_function(lib, base_addr, size, &address_data, self_samples, &file_path) {
                Ok(regions) => (Some(regions), None),
                Err(e) => (None, Some(e)),
            }
        } else {
            (None, Some("Missing function address, size, or library info".to_string()))
        };

        AsmResponse {
            function: func_info,
            file_path,
            regions,
            self_samples,
            error,
        }
    }

    /// Disassemble a function and return regions with context around hot spots
    fn disassemble_function(
        &self,
        lib: &LibInfo,
        base_addr: u64,
        size: u32,
        address_samples: &HashMap<u64, (i64, Option<u32>)>,
        total_samples: i64,
        source_file: &Option<String>,
    ) -> Result<Vec<AsmRegion>, String> {
        use capstone::prelude::*;
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        // Read the binary file
        let binary_path = std::path::Path::new(&lib.path);
        if !binary_path.exists() {
            return Err(format!("Binary not found: {}", lib.path));
        }

        // Parse the binary using the object crate
        let file_data = std::fs::read(binary_path)
            .map_err(|e| format!("Failed to read binary: {}", e))?;
        let obj_file = object::File::parse(&*file_data)
            .map_err(|e| format!("Failed to parse binary: {}", e))?;

        // Find the section containing the function
        use object::Object;
        use object::ObjectSection;
        use object::ObjectSegment;

        // The profile stores addresses as relative offsets from the library load base.
        // We need to find the image base (the virtual address where code starts) to
        // convert to absolute virtual addresses used in the binary.
        //
        // Cross-platform approach:
        // - Mach-O: Use the lowest segment vmaddr that isn't __PAGEZERO (typically __TEXT at 0x100000000)
        // - ELF: Use the lowest PT_LOAD vaddr (typically 0 or 0x400000)
        // - PE: Use the image_base from headers
        let image_base = {
            let mut min_vaddr: Option<u64> = None;
            for segment in obj_file.segments() {
                let vaddr = segment.address();
                // Check the file range - segments with no file data (like __PAGEZERO) have file_size = 0
                let (_, file_size) = segment.file_range();
                let has_file_data = file_size > 0;
                if has_file_data {
                    match min_vaddr {
                        None => min_vaddr = Some(vaddr),
                        Some(min) if vaddr < min => min_vaddr = Some(vaddr),
                        _ => {}
                    }
                }
            }
            min_vaddr.unwrap_or(0)
        };

        // Convert relative address to absolute virtual address
        let absolute_addr = base_addr + image_base;

        let mut func_bytes = None;

        for section in obj_file.sections() {
            if let Ok(name) = section.name() {
                // Look for executable sections
                if name == "__text" || name == ".text" || name.contains("text") {
                    if let Ok(data) = section.data() {
                        let sec_addr = section.address();
                        let sec_end = sec_addr + data.len() as u64;

                        // Check if our function is in this section
                        if absolute_addr >= sec_addr && absolute_addr < sec_end {
                            let offset = (absolute_addr - sec_addr) as usize;
                            let end_offset = offset + size as usize;
                            if end_offset <= data.len() {
                                func_bytes = Some(&data[offset..end_offset]);
                                break;
                            }
                        }
                    }
                }
            }
        }

        let code_bytes = func_bytes.ok_or_else(|| {
            format!(
                "Function not found in binary. Address 0x{:x} not within executable sections.",
                base_addr
            )
        })?;

        // Create capstone disassembler based on architecture
        let cs = match lib.arch.as_str() {
            "aarch64" | "arm64" => {
                Capstone::new()
                    .arm64()
                    .mode(arch::arm64::ArchMode::Arm)
                    .detail(true)
                    .build()
                    .map_err(|e| format!("Failed to create disassembler: {}", e))?
            }
            "x86_64" | "x86-64" | "" => {
                Capstone::new()
                    .x86()
                    .mode(arch::x86::ArchMode::Mode64)
                    .detail(true)
                    .build()
                    .map_err(|e| format!("Failed to create disassembler: {}", e))?
            }
            "x86" | "i386" => {
                Capstone::new()
                    .x86()
                    .mode(arch::x86::ArchMode::Mode32)
                    .detail(true)
                    .build()
                    .map_err(|e| format!("Failed to create disassembler: {}", e))?
            }
            arch => return Err(format!("Unsupported architecture: {}", arch)),
        };

        // Disassemble
        let insns = cs.disasm_all(code_bytes, base_addr)
            .map_err(|e| format!("Disassembly failed: {}", e))?;

        // Read source file lines if available
        let source_lines: HashMap<u32, String> = if let Some(ref path) = source_file {
            if let Ok(file) = File::open(path) {
                BufReader::new(file)
                    .lines()
                    .enumerate()
                    .filter_map(|(i, line)| line.ok().map(|l| ((i + 1) as u32, l)))
                    .collect()
            } else {
                HashMap::new()
            }
        } else {
            HashMap::new()
        };

        // Build instruction list with annotations
        let mut all_insns: Vec<(u64, String, Option<i64>, Option<f64>, Option<u32>)> = Vec::new();

        for insn in insns.iter() {
            let addr = insn.address();
            let asm_text = format!("{} {}", insn.mnemonic().unwrap_or(""), insn.op_str().unwrap_or("")).trim().to_string();

            let (samples, percent, source_line) = if let Some(&(s, line)) = address_samples.get(&addr) {
                let pct = if total_samples > 0 {
                    100.0 * s as f64 / total_samples as f64
                } else {
                    0.0
                };
                (Some(s), Some(pct), line)
            } else {
                (None, None, None)
            };

            all_insns.push((addr, asm_text, samples, percent, source_line));
        }

        // Group into regions: show context around hot instructions
        const CONTEXT_LINES: usize = 5;
        let mut regions: Vec<AsmRegion> = Vec::new();
        let mut hot_indices: Vec<usize> = Vec::new();

        // Find indices of hot instructions
        for (i, (_, _, samples, _, _)) in all_insns.iter().enumerate() {
            if samples.is_some() {
                hot_indices.push(i);
            }
        }

        if hot_indices.is_empty() {
            // No hot instructions, return empty
            return Ok(vec![]);
        }

        // Merge overlapping ranges
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        for &idx in &hot_indices {
            let start = idx.saturating_sub(CONTEXT_LINES);
            let end = (idx + CONTEXT_LINES + 1).min(all_insns.len());

            if let Some(last) = ranges.last_mut() {
                if start <= last.1 {
                    // Merge with previous range
                    last.1 = last.1.max(end);
                } else {
                    ranges.push((start, end));
                }
            } else {
                ranges.push((start, end));
            }
        }

        // Build regions from ranges
        let mut last_end = 0;
        for (start, end) in ranges {
            // Add gap indicator if needed
            if start > last_end && !regions.is_empty() {
                regions.push(AsmRegion {
                    source_line: None,
                    source_text: Some("...".to_string()),
                    instructions: vec![],
                });
            }

            // Group instructions by source line within this range
            let mut current_line: Option<u32> = None;
            let mut current_insns: Vec<AsmInstruction> = Vec::new();

            for i in start..end {
                let (addr, asm_text, samples, percent, source_line) = &all_insns[i];

                // If source line changes, start a new region
                if *source_line != current_line && !current_insns.is_empty() {
                    let source_text = current_line.and_then(|l| source_lines.get(&l).cloned());
                    regions.push(AsmRegion {
                        source_line: current_line,
                        source_text,
                        instructions: std::mem::take(&mut current_insns),
                    });
                }

                current_line = *source_line;
                current_insns.push(AsmInstruction {
                    address: format!("0x{:x}", addr),
                    asm: asm_text.clone(),
                    samples: *samples,
                    percent: *percent,
                });
            }

            // Flush remaining instructions
            if !current_insns.is_empty() {
                let source_text = current_line.and_then(|l| source_lines.get(&l).cloned());
                regions.push(AsmRegion {
                    source_line: current_line,
                    source_text,
                    instructions: current_insns,
                });
            }

            last_end = end;
        }

        Ok(regions)
    }

    /// Drilldown from a function, following the hottest callee path
    ///
    /// This is the key query for performance debugging. Starting from a function,
    /// it recursively follows the hottest callee until:
    /// - Max depth is reached
    /// - Self-time exceeds threshold (bottleneck found)
    /// - No more callees
    pub fn drilldown(
        &self,
        function_pattern: &str,
        max_depth: usize,
        threshold_percent: f64,
    ) -> DrilldownResponse {
        // Build comprehensive stats: function -> (self_samples, total_samples, callees, info)
        #[derive(Default, Clone)]
        struct FuncStats {
            self_samples: i64,
            total_samples: i64,
            func_idx: Option<usize>,
            thread_idx: Option<usize>,
            line_samples: HashMap<u32, i64>,
        }

        #[derive(Default, Clone)]
        struct CalleeData {
            samples: i64,
        }

        let mut func_stats: HashMap<String, FuncStats> = HashMap::new();
        let mut callee_map: HashMap<String, HashMap<String, CalleeData>> = HashMap::new();
        let mut total_weight: i64 = 0;

        // Collect all stats in one pass
        for (thread_idx, thread) in self.threads.iter().enumerate() {
            for (stack_idx_opt, weight) in &thread.samples {
                total_weight += weight;

                if let Some(stack_idx) = stack_idx_opt {
                    let stack_with_frames = thread.walk_stack_with_frames(*stack_idx);
                    let func_info: Vec<(String, usize, usize)> = stack_with_frames
                        .iter()
                        .map(|&(func_idx, frame_idx)| {
                            (thread.get_func_name(func_idx, &self.global_strings), func_idx, frame_idx)
                        })
                        .collect();

                    // Self time: leaf function only
                    if let Some((ref name, func_idx, frame_idx)) = func_info.first() {
                        let stats = func_stats.entry(name.clone()).or_default();
                        stats.self_samples += weight;
                        if stats.func_idx.is_none() {
                            stats.func_idx = Some(*func_idx);
                            stats.thread_idx = Some(thread_idx);
                        }
                        // Track per-line samples for hot_lines
                        if let Some(line) = thread.get_frame_line(*frame_idx) {
                            *stats.line_samples.entry(line).or_insert(0) += weight;
                        }
                    }

                    // Total time: each unique function in stack
                    let mut seen = std::collections::HashSet::new();
                    for (name, func_idx, _) in &func_info {
                        if seen.insert(name.clone()) {
                            let stats = func_stats.entry(name.clone()).or_default();
                            stats.total_samples += weight;
                            if stats.func_idx.is_none() {
                                stats.func_idx = Some(*func_idx);
                                stats.thread_idx = Some(thread_idx);
                            }
                        }
                    }

                    // Caller->Callee relationships (sample attributed to the relationship)
                    // In walk_stack, index 0 is leaf (callee), higher indices are callers
                    for i in 0..func_info.len().saturating_sub(1) {
                        let (callee_name, _, _) = &func_info[i];
                        let (caller_name, _, _) = &func_info[i + 1];
                        callee_map
                            .entry(caller_name.clone())
                            .or_default()
                            .entry(callee_name.clone())
                            .or_default()
                            .samples += weight;
                    }
                }
            }
        }

        // Find the starting function
        let root = self.find_matching_function(function_pattern);

        // Follow the hot path
        let mut path: Vec<DrilldownNode> = Vec::new();
        let mut current = root.clone();
        let mut visited = std::collections::HashSet::new();
        let mut bottleneck: Option<BottleneckSummary> = None;

        for _depth in 0..max_depth {
            // Skip if we've already visited this function (cycle detection)
            // but don't stop - we'll find an unvisited callee at the end of the loop
            if visited.contains(&current) {
                // Find the first unvisited callee from the previous node's callees
                // This handles cycles in the call graph (e.g., Rust's catch_unwind pattern)
                if let Some(prev_node) = path.last() {
                    if let Some(next_callee) = prev_node.callees.iter()
                        .filter(|c| !visited.contains(&c.name))
                        .max_by(|a, b| a.percent.partial_cmp(&b.percent).unwrap_or(std::cmp::Ordering::Equal))
                    {
                        current = next_callee.name.clone();
                        continue;
                    }
                }
                break; // No unvisited callees, truly stuck in a cycle
            }
            visited.insert(current.clone());

            let stats = func_stats.get(&current);
            let (self_samples, total_samples) = stats
                .map(|s| (s.self_samples, s.total_samples))
                .unwrap_or((0, 0));

            let self_percent = if total_weight > 0 {
                100.0 * self_samples as f64 / total_weight as f64
            } else {
                0.0
            };
            let total_percent = if total_weight > 0 {
                100.0 * total_samples as f64 / total_weight as f64
            } else {
                0.0
            };

            // Get function info
            let (library, file_path, line_number) = if let Some(s) = stats {
                if let (Some(fidx), Some(tidx)) = (s.func_idx, s.thread_idx) {
                    let thread = &self.threads[tidx];
                    let lib_idx = thread.get_func_lib_index(fidx);
                    (
                        lib_idx.and_then(|idx| self.libs.get(idx).map(|l| l.name.clone())),
                        thread.get_func_file(fidx, &self.global_strings),
                        thread.get_func_line(fidx),
                    )
                } else {
                    (None, None, None)
                }
            } else {
                (None, None, None)
            };

            // Get callees sorted by samples
            let callees_data = callee_map.get(&current);
            let callee_total: i64 = callees_data
                .map(|c| c.values().map(|d| d.samples).sum())
                .unwrap_or(0);

            let mut callees: Vec<DrilldownCallee> = callees_data
                .map(|c| {
                    c.iter()
                        .map(|(name, data)| DrilldownCallee {
                            name: name.clone(),
                            percent: if callee_total > 0 {
                                100.0 * data.samples as f64 / callee_total as f64
                            } else {
                                0.0
                            },
                            is_hottest: None,
                        })
                        .collect()
                })
                .unwrap_or_default();

            callees.sort_by(|a, b| b.percent.partial_cmp(&a.percent).unwrap_or(std::cmp::Ordering::Equal));

            // Mark the hottest callee
            if let Some(first) = callees.first_mut() {
                first.is_hottest = Some(true);
            }

            // Check if this is a bottleneck
            let is_bottleneck = self_percent > threshold_percent;

            // Build hot_lines if bottleneck
            let hot_lines = if is_bottleneck {
                stats.and_then(|s| {
                    if s.line_samples.is_empty() {
                        None
                    } else {
                        let mut lines: Vec<HotLine> = s.line_samples
                            .iter()
                            .map(|(&line, &samples)| HotLine {
                                line,
                                samples,
                                percent: if self_samples > 0 {
                                    100.0 * samples as f64 / self_samples as f64
                                } else {
                                    0.0
                                },
                            })
                            .collect();
                        lines.sort_by(|a, b| b.samples.cmp(&a.samples));
                        Some(lines)
                    }
                })
            } else {
                None
            };

            path.push(DrilldownNode {
                function: current.clone(),
                library: library.clone(),
                file_path: file_path.clone(),
                line_number,
                total_samples,
                total_percent,
                self_samples,
                self_percent,
                is_bottleneck: if is_bottleneck { Some(true) } else { None },
                callees: callees.clone(),
                hot_lines,
            });

            // If bottleneck found, record it and stop
            if is_bottleneck {
                bottleneck = Some(BottleneckSummary {
                    function: current.clone(),
                    library,
                    file_path,
                    line_number,
                    self_percent,
                    reason: format!(
                        "High self-time ({:.1}%) indicates this function's own code is the bottleneck",
                        self_percent
                    ),
                });
                break;
            }

            // Drill into hottest callee
            if let Some(hottest) = callees.first() {
                current = hottest.name.clone();
            } else {
                break; // No callees, stop here
            }
        }

        // Check if function wasn't found or had no samples
        let root_has_samples = func_stats.get(&root).map(|s| s.total_samples > 0).unwrap_or(false);
        let (error, suggestions) = if !root_has_samples {
            // Get top 5 functions as suggestions
            let mut top_funcs: Vec<(&String, i64)> = func_stats
                .iter()
                .map(|(name, stats)| (name, stats.total_samples))
                .collect();
            top_funcs.sort_by(|a, b| b.1.cmp(&a.1));
            let suggestions: Vec<String> = top_funcs
                .iter()
                .take(5)
                .map(|(name, samples)| {
                    let percent = if total_weight > 0 {
                        100.0 * *samples as f64 / total_weight as f64
                    } else {
                        0.0
                    };
                    format!("{} ({:.1}%)", name, percent)
                })
                .collect();

            let error_msg = format!(
                "Function '{}' not found or has no samples. Try one of the top functions listed in 'suggestions'.",
                function_pattern
            );
            (Some(error_msg), Some(suggestions))
        } else {
            (None, None)
        };

        DrilldownResponse {
            root,
            total_samples: total_weight,
            path,
            bottleneck,
            error,
            suggestions,
        }
    }

    /// Find a function by pattern (substring match)
    fn find_matching_function(&self, pattern: &str) -> String {
        // First, try exact match
        for thread in &self.threads {
            for &name_idx in &thread.func_name_idx {
                let name = thread.get_string(name_idx, &self.global_strings);
                if name == pattern {
                    return name;
                }
            }
        }

        // Then, try substring match
        for thread in &self.threads {
            for &name_idx in &thread.func_name_idx {
                let name = thread.get_string(name_idx, &self.global_strings);
                if name.contains(pattern) {
                    return name;
                }
            }
        }

        // Return the pattern itself if no match found
        pattern.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_error_display() {
        let err = AnalysisError::InvalidProfile("test".to_string());
        assert!(err.to_string().contains("test"));
    }
}
