//! Profile analysis engine for computing hotspots, call trees, and summaries.
//!
//! This module parses Firefox Profiler JSON format and provides analysis capabilities.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

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
    threads: Vec<RawThread>,
    #[serde(default)]
    shared: Option<RawShared>,
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
    length: usize,
}

// ============================================================================
// Analysis result types (for JSON output)
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct FunctionInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HotspotEntry {
    pub rank: usize,
    pub function: FunctionInfo,
    pub self_samples: i64,
    pub total_samples: i64,
    pub self_percent: f64,
    pub total_percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_chain: Option<Vec<CallerSummary>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CallerSummary {
    pub name: String,
    pub percent: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CallerEntry {
    pub name: String,
    pub call_count: i64,
    pub percent: f64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub callers: Vec<CallerEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CalleeEntry {
    pub name: String,
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

// ============================================================================
// ProfileAnalyzer - main analysis engine
// ============================================================================

/// Holds parsed profile data and provides analysis methods
pub struct ProfileAnalyzer {
    product_name: String,
    sampling_interval_ms: f64,
    threads: Vec<ThreadData>,
    /// Global string table (from shared.stringArray if present)
    global_strings: Vec<String>,
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
    /// Func table: name string index, file name index, line number
    func_name_idx: Vec<usize>,
    func_file_idx: Vec<Option<usize>>,
    func_line: Vec<Option<u32>>,
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

    fn get_frame_func(&self, frame_idx: usize) -> usize {
        if frame_idx < self.frame_func.len() {
            self.frame_func[frame_idx]
        } else {
            0
        }
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

        let threads: Vec<ThreadData> = raw
            .threads
            .into_iter()
            .map(|t| ThreadData {
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
                func_name_idx: t.func_table.name,
                func_file_idx: t.func_table.file_name,
                func_line: t.func_table.line_number,
                string_table: t.string_table,
            })
            .collect();

        Ok(Self {
            product_name: raw.meta.product,
            sampling_interval_ms: raw.meta.interval,
            threads,
            global_strings,
        })
    }

    /// Compute hotspots across all threads
    pub fn compute_hotspots(&self, limit: usize, thread_filter: Option<&str>) -> Vec<HotspotEntry> {
        let mut self_counts: HashMap<String, i64> = HashMap::new();
        let mut total_counts: HashMap<String, i64> = HashMap::new();
        let mut func_info: HashMap<String, FunctionInfo> = HashMap::new();
        let mut total_weight: i64 = 0;

        // Aggregate samples across threads
        for thread in &self.threads {
            // Apply thread filter if specified
            if let Some(filter) = thread_filter {
                if !thread.name.contains(filter) {
                    continue;
                }
            }

            for (stack_idx_opt, weight) in &thread.samples {
                total_weight += weight;

                if let Some(stack_idx) = stack_idx_opt {
                    let funcs = thread.walk_stack(*stack_idx);

                    // Self time: only for the leaf function (first in the list)
                    if let Some(&leaf_func_idx) = funcs.first() {
                        let name = thread.get_func_name(leaf_func_idx, &self.global_strings);
                        *self_counts.entry(name.clone()).or_insert(0) += weight;

                        // Store function info
                        func_info.entry(name.clone()).or_insert_with(|| FunctionInfo {
                            name: name.clone(),
                            file_path: thread.get_func_file(leaf_func_idx, &self.global_strings),
                            line_number: thread.get_func_line(leaf_func_idx),
                        });
                    }

                    // Total time: for each unique function in stack
                    let mut seen = std::collections::HashSet::new();
                    for func_idx in funcs {
                        let name = thread.get_func_name(func_idx, &self.global_strings);
                        if seen.insert(name.clone()) {
                            *total_counts.entry(name.clone()).or_insert(0) += weight;

                            // Store function info
                            func_info.entry(name.clone()).or_insert_with(|| FunctionInfo {
                                name: name.clone(),
                                file_path: thread.get_func_file(func_idx, &self.global_strings),
                                line_number: thread.get_func_line(func_idx),
                            });
                        }
                    }
                }
            }
        }

        // Convert to sorted list
        let mut hotspots: Vec<_> = self_counts
            .into_iter()
            .map(|(name, self_samples)| {
                let total_samples = total_counts.get(&name).copied().unwrap_or(0);
                let info = func_info.remove(&name).unwrap_or_else(|| FunctionInfo {
                    name: name.clone(),
                    file_path: None,
                    line_number: None,
                });
                (name, self_samples, total_samples, info)
            })
            .collect();

        // Sort by self samples descending
        hotspots.sort_by(|a, b| b.1.cmp(&a.1));

        // Take top N and convert to HotspotEntry
        hotspots
            .into_iter()
            .take(limit)
            .enumerate()
            .map(|(i, (_, self_samples, total_samples, info))| HotspotEntry {
                rank: i + 1,
                function: info,
                self_samples,
                total_samples,
                self_percent: if total_weight > 0 {
                    100.0 * self_samples as f64 / total_weight as f64
                } else {
                    0.0
                },
                total_percent: if total_weight > 0 {
                    100.0 * total_samples as f64 / total_weight as f64
                } else {
                    0.0
                },
                caller_chain: None, // TODO: Add caller chain if requested
            })
            .collect()
    }

    /// Find callers of a function
    pub fn find_callers(&self, function_pattern: &str, depth: usize) -> CallersResponse {
        // Build caller graph: callee -> caller -> count
        let mut caller_counts: HashMap<String, HashMap<String, i64>> = HashMap::new();

        for thread in &self.threads {
            for (stack_idx_opt, weight) in &thread.samples {
                if let Some(stack_idx) = stack_idx_opt {
                    let funcs = thread.walk_stack(*stack_idx);
                    let func_names: Vec<String> = funcs
                        .iter()
                        .map(|&idx| thread.get_func_name(idx, &self.global_strings))
                        .collect();

                    // For each pair (callee, caller) in the stack
                    for i in 0..func_names.len().saturating_sub(1) {
                        let callee = &func_names[i];
                        let caller = &func_names[i + 1];
                        *caller_counts
                            .entry(callee.clone())
                            .or_default()
                            .entry(caller.clone())
                            .or_insert(0) += weight;
                    }
                }
            }
        }

        // Find matching function
        let target = self.find_matching_function(function_pattern);

        // Build caller tree recursively
        fn build_caller_tree(
            caller_counts: &HashMap<String, HashMap<String, i64>>,
            target: &str,
            depth: usize,
            visited: &mut std::collections::HashSet<String>,
        ) -> Vec<CallerEntry> {
            if depth == 0 || visited.contains(target) {
                return vec![];
            }
            visited.insert(target.to_string());

            let mut callers: Vec<_> = caller_counts
                .get(target)
                .map(|callers| {
                    callers
                        .iter()
                        .map(|(caller, &count)| {
                            let sub_callers =
                                build_caller_tree(caller_counts, caller, depth - 1, visited);
                            CallerEntry {
                                name: caller.clone(),
                                call_count: count,
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
            visited.remove(target);
            callers
        }

        let callers = build_caller_tree(&caller_counts, &target, depth, &mut Default::default());

        CallersResponse {
            function: target,
            callers,
        }
    }

    /// Find callees of a function
    pub fn find_callees(&self, function_pattern: &str, depth: usize) -> CalleesResponse {
        // Build callee graph: caller -> callee -> count
        let mut callee_counts: HashMap<String, HashMap<String, i64>> = HashMap::new();

        for thread in &self.threads {
            for (stack_idx_opt, weight) in &thread.samples {
                if let Some(stack_idx) = stack_idx_opt {
                    let funcs = thread.walk_stack(*stack_idx);
                    let func_names: Vec<String> = funcs
                        .iter()
                        .map(|&idx| thread.get_func_name(idx, &self.global_strings))
                        .collect();

                    // For each pair (callee, caller) in the stack
                    // In our walk, index 0 is leaf, index n-1 is root
                    // So caller is at higher index, callee at lower
                    for i in 0..func_names.len().saturating_sub(1) {
                        let callee = &func_names[i];
                        let caller = &func_names[i + 1];
                        *callee_counts
                            .entry(caller.clone())
                            .or_default()
                            .entry(callee.clone())
                            .or_insert(0) += weight;
                    }
                }
            }
        }

        // Find matching function
        let target = self.find_matching_function(function_pattern);

        // Build callee tree recursively
        fn build_callee_tree(
            callee_counts: &HashMap<String, HashMap<String, i64>>,
            target: &str,
            depth: usize,
            visited: &mut std::collections::HashSet<String>,
        ) -> Vec<CalleeEntry> {
            if depth == 0 || visited.contains(target) {
                return vec![];
            }
            visited.insert(target.to_string());

            let mut callees: Vec<_> = callee_counts
                .get(target)
                .map(|callees| {
                    callees
                        .iter()
                        .map(|(callee, &count)| {
                            let sub_callees =
                                build_callee_tree(callee_counts, callee, depth - 1, visited);
                            CalleeEntry {
                                name: callee.clone(),
                                call_count: count,
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
            visited.remove(target);
            callees
        }

        let callees = build_callee_tree(&callee_counts, &target, depth, &mut Default::default());

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
