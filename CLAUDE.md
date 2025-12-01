# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Claude Code Inspector is a PowerShell script that scans and reports on all Claude Code configuration files, generating an interactive HTML dashboard with a PowerShell terminal-inspired design. It includes comprehensive analytics, cost estimation, and maintenance features.

## Running the Script

```powershell
# Run and open report in browser
.\claude-inspector.ps1

# Generate without opening browser
.\claude-inspector.ps1 -NoOpen

# Inspect a different project
.\claude-inspector.ps1 -ProjectPath "C:\path\to\project"
```

**Global Command:** Use `/inspect` from any Claude Code session (requires global command setup).

## Architecture

**Single-file PowerShell script** (`claude-inspector.ps1`) with:
- Data collection functions (`Get-*Info`) that scan configuration paths
- Session analysis function (`Get-SessionStats`) that parses tokens, models, tools, errors
- Analytics function (`Get-GlobalAnalytics`) for cross-project insights
- Permission conflict detection (`Get-PermissionConflicts`)
- `New-HtmlReport` function that generates the HTML dashboard
- Main execution block that orchestrates collection and output

**Configuration paths scanned:**
- Global: `$env:USERPROFILE\.claude\` (settings.json, settings.local.json, CLAUDE.md, agents/, commands/, skills/, projects/)
- Project: `$ProjectPath\.claude\` and `$ProjectPath\.mcp.json`
- Enterprise: `C:\ProgramData\ClaudeCode\` (managed-settings.json, managed-mcp.json, CLAUDE.md)

**Session data analyzed:**
- Token usage: `input_tokens` and `output_tokens` from session `.jsonl` files
- Duration: Calculated from first to last `timestamp` in each session
- Model usage: Extracted from `model` field
- Tool calls: Extracted from `tool_use` content blocks
- Errors: Extracted from error messages and `is_error` fields
- Agent sessions: Parsed from `agent-*.jsonl` files

**Output:** Self-contained HTML file with embedded CSS and JavaScript, no external dependencies.

## HTML Dashboard Sections

**Layout:** Sidebar navigation (with section groups) + main content area

### Overview & Projects
| Section | Description |
|---------|-------------|
| Analytics | Overview cards (projects, tokens, cost, disk usage, errors, agents), 14-day usage chart |
| Projects | All projects with sessions, tokens, cost, duration, sortable columns |

### Configuration
| Section | Description |
|---------|-------------|
| Settings | Global and project settings.json files with content preview |
| MCP Servers | Configured MCP servers from .mcp.json and settings |
| Memory | CLAUDE.md files (global, project root, project .claude/, project local) |
| Agents | Custom agent definitions with YAML frontmatter parsing |
| Commands | Custom slash commands |
| Skills | Agent skills (SKILL.md files) with description and allowed tools |
| Plugins | Configured plugins and marketplace sources |
| Hooks | Configured hooks from settings |
| Permissions | Tool permission rules (allow/deny/ask) |
| Enterprise | Managed settings for enterprise deployments (Windows) |

### Usage Data
| Section | Description |
|---------|-------------|
| Tool Usage | Bar chart and grid showing tool call distribution |
| Models | Model usage distribution chart |
| Errors | List of errors extracted from sessions |

### Maintenance
| Section | Description |
|---------|-------------|
| Cleanup | Orphan projects (deleted paths), stale projects (30+ days), corrupted files |
| Conflicts | Permission conflicts between settings levels |
| Recommendations | Configuration suggestions and cleanup recommendations |

### Projects Table Columns

| Column | Description |
|--------|-------------|
| Name | Project folder name |
| Path | Full path to project directory |
| Sessions | Number of conversation sessions (excludes agent-* files) |
| Tokens | Total tokens used (input + output), formatted as K/M |
| Cost | Estimated API cost based on token usage |
| Duration | Total session time, formatted as hours/minutes |
| Last Used | Date of most recent session activity |
| Configuration | Badges showing local config (Settings, Memory, MCP, etc.) |

**Sorting:** Click any column header to sort. Click again to toggle ascending/descending.

## Key Functions

| Function | Purpose |
|----------|---------|
| `Get-SessionStats` | Parses session .jsonl for tokens, models, tools, errors, duration |
| `Get-GlobalAnalytics` | Aggregates stats across all projects, finds orphans/stale |
| `Get-ProjectsInfo` | Scans ~/.claude/projects/, extracts cwd and session stats |
| `Get-SettingsInfo` | Collects settings.json from all locations |
| `Get-McpServersInfo` | Parses .mcp.json and settings for MCP server configs |
| `Get-MemoryInfo` | Finds CLAUDE.md files (including CLAUDE.local.md) |
| `Get-AgentsInfo` | Lists custom agents |
| `Get-CommandsInfo` | Lists custom commands |
| `Get-SkillsInfo` | Scans skills directories for SKILL.md files |
| `Get-PluginsInfo` | Collects plugin configurations and marketplaces |
| `Get-HooksInfo` | Collects hooks from settings |
| `Get-ToolPermissions` | Merges permission rules from all settings |
| `Get-PermissionConflicts` | Detects conflicting rules between settings levels |
| `Get-ManagedSettingsInfo` | Checks for enterprise managed settings |
| `Get-YamlFrontmatter` | Parses YAML frontmatter from markdown files |
| `Get-Recommendations` | Generates setup and cleanup suggestions |
| `Get-TokenCost` | Calculates API cost from tokens |
| `Format-FileSize` | Formats bytes as KB/MB/GB |
| `New-HtmlReport` | Assembles complete HTML dashboard |

## Cost Estimation

Uses predefined rates per 1M tokens (2025 pricing):
- Claude 3 Opus / Claude Opus 4 / Claude Opus 4.5: $15 input, $75 output
- Claude 3 Sonnet / Claude Sonnet 4 / Claude Sonnet 4.5: $3 input, $15 output
- Claude 3.5 Sonnet: $3 input, $15 output
- Claude 3 Haiku: $0.25 input, $1.25 output
- Claude 3.5 Haiku: $0.80 input, $4 output

## Design

**PowerShell terminal aesthetic:**
- Black background (#0c0c0c) with monospace font (Cascadia Code/Consolas)
- Terminal title bar with macOS-style colored dots
- `[OK]`/`[--]` status indicators, `[+]`/`[-]` expandable blocks
- Minimal color: white/gray text, blue accent for active states
- Green for success/allow, red for errors/deny, yellow for warnings/ask
- Analytics cards with highlight colors for key metrics
- Bar charts for tool and model usage distribution
- Time-series chart for daily token usage (last 14 days)

**Source badges:**
- Blue `Global` badge for user-wide configurations (~/.claude/)
- Green `Project` badge for project-specific configurations (.claude/)
- Gold `Enterprise` badge for managed/IT-controlled settings (ProgramData)

**JSON syntax highlighting:**
- Professional code-style colors in expandable JSON blocks
- Keys (blue), strings (orange), numbers (green), booleans/null (blue), brackets (purple)

## Implementation Details

- Uses `[System.Web.HttpUtility]::HtmlEncode()` for safe HTML output
- Writes UTF-8 without BOM via `[System.IO.File]::WriteAllText()` for proper browser rendering
- Extracts project paths from session file `cwd` field (not folder name decoding)
- Parses session `.jsonl` files line-by-line with regex for token/timestamp/model/tool extraction
- Validates JSON lines to detect corrupted session files
- Tracks daily usage for time-series visualization
- Expandable content blocks use inline `onclick` handlers to toggle `.open` class
- Sortable table uses CSS escape codes (`\25BC`, `\25B2`) for arrow icons
- JavaScript sorting preserves row-details pairing when reordering
- Progress output during report generation shows scanning status
