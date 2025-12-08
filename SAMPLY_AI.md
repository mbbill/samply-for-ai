# Samply AI CLI Interface

This document describes the AI-friendly CLI interface added to samply for programmatic analysis of profiling data.

## Overview

Samply is a sampling CPU profiler. This fork adds a CLI interface designed for AI assistants (like Claude Code) to analyze profiling data programmatically. The key insight is that AI assistants can only run one-shot commands, not interactive sessions.

## Architecture

```
┌─────────────────┐         ┌─────────────────────────────┐
│  samply query   │  HTTP   │     samply analyze serve    │
│  (one-shot CLI) │ ──────► │   (background server with   │
│                 │ ◄────── │    loaded profile + state)  │
└─────────────────┘  JSON   └─────────────────────────────┘
         │
         └── Reads ~/.samply/session.json for server discovery
```

## Workflow

```bash
# Step 1: Start the analysis server (human or AI can do this)
samply analyze serve profile.json
# Output: Server running at http://localhost:3000
#         Session file: ~/.samply/session.json

# Step 2: AI runs one-shot queries
samply query hotspots --limit 20
samply query callers malloc --depth 3
samply query callees dispatch
samply query summary

# Step 3: When done
samply analyze stop
```

## CLI Commands

### Starting the Analysis Server

```bash
samply analyze serve <profile.json> [options]

Options:
  --port <PORT>       Server port (default: 3000+)
  --address <ADDR>    Server address (default: 127.0.0.1)
  --foreground        Run in foreground (default)
  --no-open           Don't open browser
```

### Querying the Server

```bash
# Get hottest functions
samply query hotspots [--limit N] [--thread NAME]

# Find callers of a function
samply query callers FUNCTION [--depth N]

# Find callees of a function
samply query callees FUNCTION [--depth N]

# Get profile summary
samply query summary
```

### Stopping the Server

```bash
samply analyze stop
```

## HTTP API Endpoints

When the analysis server is running, these endpoints are available:

- `GET /{token}/query/hotspots?limit=20` - Get hottest functions
- `GET /{token}/query/callers?function=NAME&depth=5` - Find callers
- `GET /{token}/query/callees?function=NAME&depth=5` - Find callees
- `GET /{token}/query/summary` - Get profile summary

## Output Format

All queries return JSON:

```json
{
  "success": true,
  "query": "hotspots",
  "data": [
    {
      "rank": 1,
      "function": {
        "name": "Interpreter::dispatch",
        "file_path": "src/interpreter.rs",
        "line_number": 234
      },
      "self_samples": 1523,
      "total_samples": 4521,
      "self_percent": 15.2,
      "total_percent": 45.2
    }
  ]
}
```

## Implementation Details

### Files Added

| File | Purpose |
|------|---------|
| `samply/src/session.rs` | Session file management (~/.samply/session.json) |
| `samply/src/profile_analysis.rs` | Core analysis algorithms (hotspots, callers, callees) |
| `samply/src/query_client.rs` | HTTP client for CLI queries |

### Files Modified

| File | Changes |
|------|---------|
| `samply/src/cli.rs` | Added `Analyze` and `Query` subcommands |
| `samply/src/main.rs` | Added command handlers |
| `samply/src/server.rs` | Added `/query/*` endpoints and `start_analysis_server` |
| `samply/Cargo.toml` | Added `url` dependency |

### Session File Format

```json
{
  "server_url": "http://127.0.0.1:3000/abc123token",
  "profile_path": "/path/to/profile.json",
  "pid": 12345,
  "started_at": "2025-01-15T10:30:00Z"
}
```

## Use Case: Interpreter Optimization

This feature was designed for optimizing interpreters. Typical workflow:

1. Profile the interpreter: `samply record ./my_interpreter test.script`
2. Start analysis server: `samply analyze serve profile.json.gz`
3. AI queries hotspots: `samply query hotspots --limit 10`
4. AI investigates hot function: `samply query callers dispatch --depth 3`
5. AI suggests optimization
6. Repeat

## Design Decisions

### Why Client-Server?

AI assistants like Claude Code can only run one-shot commands. An interactive REPL would require persistent terminal sessions which aren't supported. The client-server model allows:
- Server holds parsed profile in memory (fast queries)
- Each query is a simple HTTP GET
- Session file enables automatic server discovery

### Why Session File?

The session file (`~/.samply/session.json`) solves the server discovery problem:
- Query commands don't need to specify server URL
- Multiple terminals can query the same server
- Stale sessions are detected and cleaned up

### Why JSON Output?

JSON output is machine-readable and easy for AI assistants to parse. The structured format includes:
- Success/error status
- Query type
- Structured data with type-safe fields

## Future Improvements

- [ ] Add `--with-source` flag to include source snippets in hotspot output
- [ ] Add `--with-asm` flag to include assembly in hotspot output
- [ ] Add source code query endpoint
- [ ] Add assembly query endpoint
- [ ] Add time range filtering
- [ ] Add diff/comparison between profiles

## Status

**Implementation Status: MVP Complete**

Core functionality is implemented:
- [x] Session management
- [x] CLI subcommands
- [x] Profile analysis engine
- [x] Server query endpoints
- [x] HTTP client
- [x] Command handlers

Not yet implemented:
- [ ] Source code snippets in output
- [ ] Assembly in output
- [ ] Background/daemon mode
