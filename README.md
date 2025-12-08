# Samply - CPU Profiler with AI CLI

A sampling CPU profiler with a CLI designed for AI-assisted performance debugging.

## Quick Start

```bash
# Record a profile and start analysis server (--serve for AI/CLI workflow)
samply record --serve ./my-application my-arguments
# Now run queries directly (server running in foreground, Ctrl+C to stop)

# OR: Traditional workflow (server runs in background)
samply analyze serve profile.json --no-open &
samply query drilldown main --depth 20
samply analyze stop
```

## Recording Profiles

```bash
# Record and start analysis server (for AI/CLI workflow)
samply record --serve ./my-application
# Server runs in foreground, ready for samply query commands

# Basic recording (opens Firefox Profiler UI when done, pre-symbolicated by default)
samply record ./my-application

# Save without opening browser
samply record -o profile.json --save-only ./my-application

```

### Platform Setup

**Linux** - Grant perf access:
```bash
echo '-1' | sudo tee /proc/sys/kernel/perf_event_paranoid
```

**macOS** - Self-sign for process attachment:
```bash
samply setup
```

## AI CLI - Performance Analysis

### Setup

**IMPORTANT:** `samply analyze serve` runs a persistent server that does NOT exit until killed. You MUST run it in the background, otherwise your terminal will be blocked.

```bash
# Start analysis server (run in background with &)
samply analyze serve profile.json --no-open &

# Server auto-discovered via ~/.samply/session.json
# Now run queries...

# Stop when done
samply analyze stop
```

### Commands

#### drilldown - Find Bottleneck (START HERE)

```bash
samply query drilldown FUNCTION [--depth N] [--threshold PCT]
```

Follows hottest callee path from FUNCTION. Stops when self-time > threshold (bottleneck found).

**Options:**
- `--depth N` - Maximum depth to drill (default: 20)
- `--threshold PCT` - Self-time percentage to consider a bottleneck (default: 5.0)

**Threshold explained:**
- At each function, checks if `self_percent > threshold`
- `self_percent` = % of samples where CPU is executing THIS function's code (not its callees)
- `--threshold 5.0` - Default, catches most bottlenecks
- `--threshold 20.0` - Only flags significant bottlenecks
- `--threshold 50.0` - Only stops at severe bottlenecks

```bash
samply query drilldown main --depth 20
```

Output marks `is_hottest: true` at each level, `is_bottleneck: true` when found.

#### hotspots - Functions by Self-Time

```bash
samply query hotspots [--limit N] [--thread NAME] [--show-lines] [--show-addresses]
```

**Options:**
- `--limit N` - Number of functions to return (default: 20)
- `--thread NAME` - Filter to specific thread
- `--show-lines` - Include per-line sample counts
- `--show-addresses` - Include per-address sample counts

**Note**: Often shows stdlib (`malloc`, `memcpy`). Use `drilldown` to find YOUR bottleneck.

#### callers / callees - Call Relationships

```bash
samply query callers FUNCTION [--depth N] [--limit N]
samply query callees FUNCTION [--depth N] [--limit N]
```

**Options:**
- `--depth N` - Maximum depth of call chain (default: 5)
- `--limit N` - Maximum callers/callees per level (default: 20)

#### asm - Address-Level Samples with Source Mapping

```bash
samply query asm FUNCTION
```

Returns `hot_addresses` sorted by offset (code order), each with:
- `offset` - offset from function start
- `address` - absolute address
- `source_line` - corresponding source line number (if available)
- `samples` / `percent` - sample counts

#### summary - Profile Overview

```bash
samply query summary
```

### Workflow

```bash
# 1. Find bottleneck
samply query drilldown main --depth 20
# → Shows: parse_json at line 234 is bottleneck (65% self-time)
# → drilldown includes hot_lines for the bottleneck function

# 2. If you need address-level detail
samply query asm parse_json
# → Shows hot addresses sorted by code order with source line mapping

# 3. If stdlib bottleneck (malloc, pthread_wait), drill from higher level
samply query drilldown "MyApp::process" --depth 10
```

## Key Concepts

| Term | Meaning |
|------|---------|
| **self-time** | Time in function itself, not callees |
| **total-time** | Time in function + all callees |
| **bottleneck** | High self-time = CPU cycles burned here |
| **hot path** | Call chain consuming most time |

## Output Format

All queries return JSON:

```json
{
  "success": true,
  "query": "drilldown",
  "data": {
    "root": "main",
    "path": [...],
    "bottleneck": {
      "function": "parse_json",
      "file_path": "/src/parser.rs",
      "line_number": 234,
      "self_percent": 65.0
    }
  }
}
```

### drilldown node

```json
{
  "function": "parse_json",
  "library": "myapp",
  "file_path": "/src/parser.rs",
  "line_number": 234,
  "total_percent": 70.0,
  "self_percent": 65.0,
  "is_bottleneck": true,
  "callees": [{"name": "alloc", "percent": 5.0, "is_hottest": true}],
  "hot_lines": [{"line": 236, "samples": 800, "percent": 52.5}]
}
```

### hotspot entry

```json
{
  "rank": 1,
  "function": {"name": "...", "library": "...", "file_path": "...", "line_number": 234},
  "self_samples": 1523,
  "self_percent": 15.2,
  "total_samples": 4521,
  "total_percent": 45.2
}
```

With `--show-lines`: adds `"hot_lines": [{"line": 236, "samples": 800, "percent": 52.5}]`
With `--show-addresses`: adds `"hot_addresses": [{"offset": 12, "address": "0x1234", "source_line": 236, "samples": 500, "percent": 32.8}]`

## Tips

1. **Start with `drilldown main`** - automatically shows hot path
2. **Default threshold is 5%** - catches most bottlenecks; use `--threshold 20` for only severe
3. **Wait bottlenecks** (`pthread_cond_wait`) = blocking, drill from elsewhere
4. **Substring match** - `drilldown dispatch` matches `Interpreter::dispatch`
5. **Pre-symbolication is on by default** - use `--no-presymbolicate` to skip if you want faster recording

## Building

```bash
cargo build --release
./target/release/samply record ./my-app
```

## Troubleshooting

### Unsymbolicated Profile (Function Names Are Hex Addresses)

If you see function names like `0x1efcfc` instead of readable names, your profile isn't symbolicated.

**Symptoms:**
- `samply query hotspots` shows functions like `0x1efcfc`, `0x4ba9dc`
- `samply query drilldown main` returns empty with "function not found" error
- Server startup shows warning about unsymbolicated profile

**Solutions:**
1. **Re-record with presymbolication** (enabled by default):
   ```bash
   samply record ./my-app
   ```

2. **Symbolicate an existing profile:**
   ```bash
   samply import --presymbolicate profile.json -o symbolicated.json
   samply analyze serve symbolicated.json --no-open &
   ```

### Function Not Found in Drilldown

If `drilldown` returns an error, the response includes `suggestions` with the top functions in the profile:
```json
{
  "error": "Function 'main' not found...",
  "suggestions": ["0x1efcfc (4.4%)", "my_func (2.1%)", ...]
}
```

Use one of the suggested functions, or check if your profile is symbolicated.

## License

Apache-2.0 OR MIT
