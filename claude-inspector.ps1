# Claude Code Configuration Inspector
# Generates an HTML dashboard showing all Claude Code configuration
# Enhanced with analytics, session parsing, and maintenance features

param(
    [string]$ProjectPath = (Get-Location).Path,
    [switch]$NoOpen
)

# Configuration paths
$globalPath = "$env:USERPROFILE\.claude"
$reportPath = Join-Path $ProjectPath "claude-inspector-report.html"
$projectName = Split-Path $ProjectPath -Leaf

# Cost rates per 1M tokens (as of 2025 pricing)
$script:CostRates = @{
    "claude-3-opus" = @{ Input = 15.00; Output = 75.00 }
    "claude-3-sonnet" = @{ Input = 3.00; Output = 15.00 }
    "claude-3-haiku" = @{ Input = 0.25; Output = 1.25 }
    "claude-3-5-sonnet" = @{ Input = 3.00; Output = 15.00 }
    "claude-3-5-haiku" = @{ Input = 0.80; Output = 4.00 }
    "claude-sonnet-4" = @{ Input = 3.00; Output = 15.00 }
    "claude-sonnet-4-5" = @{ Input = 3.00; Output = 15.00 }
    "claude-opus-4" = @{ Input = 15.00; Output = 75.00 }
    "claude-opus-4-5" = @{ Input = 15.00; Output = 75.00 }
    "default" = @{ Input = 3.00; Output = 15.00 }
}

# Helper function to safely read JSON
function Get-JsonContent {
    param([string]$Path)
    if (Test-Path $Path) {
        try {
            return Get-Content $Path -Raw | ConvertFrom-Json
        } catch {
            return $null
        }
    }
    return $null
}

# Helper function to get file content
function Get-FileContentSafe {
    param([string]$Path)
    if (Test-Path $Path) {
        return Get-Content $Path -Raw
    }
    return $null
}

# Helper function to HTML encode
function ConvertTo-HtmlEncoded {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Web.HttpUtility]::HtmlEncode($Text)
}

Add-Type -AssemblyName System.Web

# Helper function to format file size
function Format-FileSize {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

# Helper function to calculate cost
function Get-TokenCost {
    param(
        [int]$InputTokens,
        [int]$OutputTokens,
        [string]$Model = "default"
    )
    $rates = $script:CostRates[$Model]
    if (-not $rates) { $rates = $script:CostRates["default"] }
    $inputCost = ($InputTokens / 1000000) * $rates.Input
    $outputCost = ($OutputTokens / 1000000) * $rates.Output
    return @{
        InputCost = $inputCost
        OutputCost = $outputCost
        TotalCost = $inputCost + $outputCost
    }
}

# Collect Settings Information
function Get-SettingsInfo {
    $settings = @{
        Global = @{
            Path = "$globalPath\settings.json"
            Exists = Test-Path "$globalPath\settings.json"
            Content = Get-JsonContent "$globalPath\settings.json"
        }
        GlobalLocal = @{
            Path = "$globalPath\settings.local.json"
            Exists = Test-Path "$globalPath\settings.local.json"
            Content = Get-JsonContent "$globalPath\settings.local.json"
        }
        Project = @{
            Path = "$ProjectPath\.claude\settings.json"
            Exists = Test-Path "$ProjectPath\.claude\settings.json"
            Content = Get-JsonContent "$ProjectPath\.claude\settings.json"
        }
        ProjectLocal = @{
            Path = "$ProjectPath\.claude\settings.local.json"
            Exists = Test-Path "$ProjectPath\.claude\settings.local.json"
            Content = Get-JsonContent "$ProjectPath\.claude\settings.local.json"
        }
    }
    return $settings
}

# Collect MCP Servers Information
function Get-McpServersInfo {
    $mcpInfo = @{
        ProjectMcp = @{
            Path = "$ProjectPath\.mcp.json"
            Exists = Test-Path "$ProjectPath\.mcp.json"
            Content = Get-JsonContent "$ProjectPath\.mcp.json"
        }
        GlobalMcp = @{
            Path = "$globalPath\.mcp.json"
            Exists = Test-Path "$globalPath\.mcp.json"
            Content = Get-JsonContent "$globalPath\.mcp.json"
        }
        Servers = @()
    }

    # Get servers from global .mcp.json
    if ($mcpInfo.GlobalMcp.Content -and $mcpInfo.GlobalMcp.Content.mcpServers) {
        foreach ($server in $mcpInfo.GlobalMcp.Content.mcpServers.PSObject.Properties) {
            $mcpInfo.Servers += @{
                Name = $server.Name
                Source = "Global (.mcp.json)"
                Config = $server.Value
            }
        }
    }

    # Get servers from project .mcp.json
    if ($mcpInfo.ProjectMcp.Content -and $mcpInfo.ProjectMcp.Content.mcpServers) {
        foreach ($server in $mcpInfo.ProjectMcp.Content.mcpServers.PSObject.Properties) {
            $mcpInfo.Servers += @{
                Name = $server.Name
                Source = "Project (.mcp.json)"
                Config = $server.Value
            }
        }
    }

    # Get MCP servers from settings files (user scope)
    $allSettings = Get-SettingsInfo
    foreach ($settingType in @('Global', 'GlobalLocal', 'Project', 'ProjectLocal')) {
        $content = $allSettings[$settingType].Content
        if ($content) {
            # Check for mcpServers in settings
            if ($content.mcpServers) {
                foreach ($server in $content.mcpServers.PSObject.Properties) {
                    $mcpInfo.Servers += @{
                        Name = $server.Name
                        Source = "$settingType (settings.json)"
                        Config = $server.Value
                    }
                }
            }

            if ($content.enabledMcpjsonServers) {
                $mcpInfo.EnabledServers = $content.enabledMcpjsonServers
            }
            if ($content.disabledMcpjsonServers) {
                $mcpInfo.DisabledServers = $content.disabledMcpjsonServers
            }
        }
    }

    return $mcpInfo
}

# Collect Memory Information
function Get-MemoryInfo {
    $memory = @{
        Global = @{
            Path = "$globalPath\CLAUDE.md"
            Exists = Test-Path "$globalPath\CLAUDE.md"
            Content = Get-FileContentSafe "$globalPath\CLAUDE.md"
        }
        ProjectRoot = @{
            Path = "$ProjectPath\CLAUDE.md"
            Exists = Test-Path "$ProjectPath\CLAUDE.md"
            Content = Get-FileContentSafe "$ProjectPath\CLAUDE.md"
        }
        ProjectFolder = @{
            Path = "$ProjectPath\.claude\CLAUDE.md"
            Exists = Test-Path "$ProjectPath\.claude\CLAUDE.md"
            Content = Get-FileContentSafe "$ProjectPath\.claude\CLAUDE.md"
        }
        ProjectLocal = @{
            Path = "$ProjectPath\.claude\CLAUDE.local.md"
            Exists = Test-Path "$ProjectPath\.claude\CLAUDE.local.md"
            Content = Get-FileContentSafe "$ProjectPath\.claude\CLAUDE.local.md"
        }
    }
    return $memory
}

# Collect Agents Information
function Get-AgentsInfo {
    $agents = @{
        Global = @{
            Path = "$globalPath\agents"
            Exists = Test-Path "$globalPath\agents"
            Files = @()
        }
        Project = @{
            Path = "$ProjectPath\.claude\agents"
            Exists = Test-Path "$ProjectPath\.claude\agents"
            Files = @()
        }
    }

    if ($agents.Global.Exists) {
        $agents.Global.Files = Get-ChildItem "$globalPath\agents\*.md" -ErrorAction SilentlyContinue | ForEach-Object {
            @{
                Name = $_.BaseName
                Path = $_.FullName
                Content = Get-Content $_.FullName -Raw
            }
        }
    }

    if ($agents.Project.Exists) {
        $agents.Project.Files = Get-ChildItem "$ProjectPath\.claude\agents\*.md" -ErrorAction SilentlyContinue | ForEach-Object {
            @{
                Name = $_.BaseName
                Path = $_.FullName
                Content = Get-Content $_.FullName -Raw
            }
        }
    }

    return $agents
}

# Collect Commands Information
function Get-CommandsInfo {
    $commands = @{
        Global = @{
            Path = "$globalPath\commands"
            Exists = Test-Path "$globalPath\commands"
            Files = @()
        }
        Project = @{
            Path = "$ProjectPath\.claude\commands"
            Exists = Test-Path "$ProjectPath\.claude\commands"
            Files = @()
        }
    }

    if ($commands.Global.Exists) {
        $commands.Global.Files = Get-ChildItem "$globalPath\commands\*.md" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            @{
                Name = "/" + $_.BaseName
                Path = $_.FullName
                Content = Get-Content $_.FullName -Raw
            }
        }
    }

    if ($commands.Project.Exists) {
        $commands.Project.Files = Get-ChildItem "$ProjectPath\.claude\commands\*.md" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            @{
                Name = "/" + $_.BaseName
                Path = $_.FullName
                Content = Get-Content $_.FullName -Raw
            }
        }
    }

    return $commands
}

# Parse YAML frontmatter from markdown content
function Get-YamlFrontmatter {
    param([string]$Content)

    $metadata = @{
        Name = $null
        Description = $null
        Tools = @()
        Model = $null
        AllowedTools = @()
        Skills = @()
    }

    if ($null -eq $Content) { return $metadata }

    # Check for YAML frontmatter (starts with ---)
    if ($Content -match '(?s)^---\s*\r?\n(.+?)\r?\n---') {
        $yaml = $matches[1]

        # Parse name
        if ($yaml -match '(?m)^name:\s*(.+)$') {
            $metadata.Name = $matches[1].Trim().Trim('"', "'")
        }

        # Parse description
        if ($yaml -match '(?m)^description:\s*(.+)$') {
            $metadata.Description = $matches[1].Trim().Trim('"', "'")
        }

        # Parse model
        if ($yaml -match '(?m)^model:\s*(.+)$') {
            $metadata.Model = $matches[1].Trim().Trim('"', "'")
        }

        # Parse tools (comma-separated or array)
        if ($yaml -match '(?m)^tools:\s*\[([^\]]+)\]') {
            $metadata.Tools = $matches[1] -split ',' | ForEach-Object { $_.Trim().Trim('"', "'") }
        } elseif ($yaml -match '(?m)^tools:\s*(.+)$') {
            $metadata.Tools = $matches[1] -split ',' | ForEach-Object { $_.Trim().Trim('"', "'") }
        }

        # Parse allowed-tools (for skills)
        if ($yaml -match '(?m)^allowed-tools:\s*\[([^\]]+)\]') {
            $metadata.AllowedTools = $matches[1] -split ',' | ForEach-Object { $_.Trim().Trim('"', "'") }
        } elseif ($yaml -match '(?s)allowed-tools:\s*\r?\n((?:\s*-\s*.+\r?\n?)+)') {
            $metadata.AllowedTools = $matches[1] -split '\r?\n' | Where-Object { $_ -match '^\s*-\s*(.+)$' } | ForEach-Object {
                if ($_ -match '^\s*-\s*(.+)$') { $matches[1].Trim() }
            }
        }

        # Parse skills
        if ($yaml -match '(?m)^skills:\s*(.+)$') {
            $metadata.Skills = $matches[1] -split ',' | ForEach-Object { $_.Trim().Trim('"', "'") }
        }
    }

    return $metadata
}

# Collect Skills Information
function Get-SkillsInfo {
    $skills = @{
        Global = @{
            Path = "$globalPath\skills"
            Exists = Test-Path "$globalPath\skills"
            Items = @()
        }
        Project = @{
            Path = "$ProjectPath\.claude\skills"
            Exists = Test-Path "$ProjectPath\.claude\skills"
            Items = @()
        }
    }

    # Scan global skills
    if ($skills.Global.Exists) {
        $skillFolders = Get-ChildItem "$globalPath\skills" -Directory -ErrorAction SilentlyContinue
        foreach ($folder in $skillFolders) {
            $skillFile = Join-Path $folder.FullName "SKILL.md"
            if (Test-Path $skillFile) {
                $content = Get-Content $skillFile -Raw -ErrorAction SilentlyContinue
                $metadata = Get-YamlFrontmatter $content
                $skills.Global.Items += @{
                    Name = if ($metadata.Name) { $metadata.Name } else { $folder.Name }
                    FolderName = $folder.Name
                    Path = $skillFile
                    Description = $metadata.Description
                    AllowedTools = $metadata.AllowedTools
                    Content = $content
                }
            }
        }
    }

    # Scan project skills
    if ($skills.Project.Exists) {
        $skillFolders = Get-ChildItem "$ProjectPath\.claude\skills" -Directory -ErrorAction SilentlyContinue
        foreach ($folder in $skillFolders) {
            $skillFile = Join-Path $folder.FullName "SKILL.md"
            if (Test-Path $skillFile) {
                $content = Get-Content $skillFile -Raw -ErrorAction SilentlyContinue
                $metadata = Get-YamlFrontmatter $content
                $skills.Project.Items += @{
                    Name = if ($metadata.Name) { $metadata.Name } else { $folder.Name }
                    FolderName = $folder.Name
                    Path = $skillFile
                    Description = $metadata.Description
                    AllowedTools = $metadata.AllowedTools
                    Content = $content
                }
            }
        }
    }

    return $skills
}

# Collect Plugins Information
function Get-PluginsInfo {
    $plugins = @{
        Configured = @()
        Marketplaces = @()
    }

    # Check settings for plugin configuration
    $allSettings = Get-SettingsInfo
    foreach ($settingType in @('Global', 'GlobalLocal', 'Project', 'ProjectLocal')) {
        $content = $allSettings[$settingType].Content
        if ($content) {
            # Check for enabled/disabled plugins
            if ($content.plugins) {
                if ($content.plugins.enabled) {
                    foreach ($p in $content.plugins.enabled) {
                        $plugins.Configured += @{
                            Name = $p
                            Status = "Enabled"
                            Source = $settingType
                        }
                    }
                }
                if ($content.plugins.disabled) {
                    foreach ($p in $content.plugins.disabled) {
                        $plugins.Configured += @{
                            Name = $p
                            Status = "Disabled"
                            Source = $settingType
                        }
                    }
                }
            }

            # Check for marketplace configurations
            if ($content.extraKnownMarketplaces) {
                foreach ($market in $content.extraKnownMarketplaces.PSObject.Properties) {
                    $plugins.Marketplaces += @{
                        Name = $market.Name
                        Config = $market.Value
                        Source = $settingType
                    }
                }
            }
        }
    }

    return $plugins
}

# Collect Enterprise/Managed Settings
function Get-ManagedSettingsInfo {
    # Windows enterprise paths
    $managedPath = "C:\ProgramData\ClaudeCode"

    $managed = @{
        Path = $managedPath
        Exists = Test-Path $managedPath
        Settings = @{
            Path = "$managedPath\managed-settings.json"
            Exists = Test-Path "$managedPath\managed-settings.json"
            Content = Get-JsonContent "$managedPath\managed-settings.json"
        }
        Mcp = @{
            Path = "$managedPath\managed-mcp.json"
            Exists = Test-Path "$managedPath\managed-mcp.json"
            Content = Get-JsonContent "$managedPath\managed-mcp.json"
        }
        Memory = @{
            Path = "$managedPath\CLAUDE.md"
            Exists = Test-Path "$managedPath\CLAUDE.md"
            Content = Get-FileContentSafe "$managedPath\CLAUDE.md"
        }
    }

    return $managed
}

# Collect Hooks Information
function Get-HooksInfo {
    $hooks = @{
        ProjectFolder = @{
            Path = "$ProjectPath\.claude\hooks"
            Exists = Test-Path "$ProjectPath\.claude\hooks"
            Files = @()
        }
        FromSettings = @()
    }

    if ($hooks.ProjectFolder.Exists) {
        $hooks.ProjectFolder.Files = Get-ChildItem "$ProjectPath\.claude\hooks\*" -ErrorAction SilentlyContinue | ForEach-Object {
            @{
                Name = $_.Name
                Path = $_.FullName
            }
        }
    }

    # Get hooks from settings
    $allSettings = Get-SettingsInfo
    foreach ($settingType in @('Global', 'GlobalLocal', 'Project', 'ProjectLocal')) {
        $content = $allSettings[$settingType].Content
        if ($content -and $content.hooks) {
            $hooks.FromSettings += @{
                Source = $settingType
                Hooks = $content.hooks
            }
        }
    }

    return $hooks
}

# Collect Tool Permissions
function Get-ToolPermissions {
    $permissions = @{
        Allow = @()
        Deny = @()
        Ask = @()
    }

    $allSettings = Get-SettingsInfo

    # Merge permissions from all settings (later settings override earlier)
    foreach ($settingType in @('Global', 'GlobalLocal', 'Project', 'ProjectLocal')) {
        $content = $allSettings[$settingType].Content
        if ($content -and $content.permissions) {
            if ($content.permissions.allow) {
                $permissions.Allow += $content.permissions.allow | ForEach-Object { @{ Rule = $_; Source = $settingType } }
            }
            if ($content.permissions.deny) {
                $permissions.Deny += $content.permissions.deny | ForEach-Object { @{ Rule = $_; Source = $settingType } }
            }
            if ($content.permissions.ask) {
                $permissions.Ask += $content.permissions.ask | ForEach-Object { @{ Rule = $_; Source = $settingType } }
            }
        }
    }

    return $permissions
}

# Detect permission conflicts between settings levels
function Get-PermissionConflicts {
    $conflicts = @()
    $allSettings = Get-SettingsInfo
    $permissionsByLevel = @{}

    foreach ($settingType in @('Global', 'GlobalLocal', 'Project', 'ProjectLocal')) {
        $content = $allSettings[$settingType].Content
        if ($content -and $content.permissions) {
            $permissionsByLevel[$settingType] = @{
                Allow = @($content.permissions.allow)
                Deny = @($content.permissions.deny)
                Ask = @($content.permissions.ask)
            }
        }
    }

    # Check for conflicts: same rule in different categories at different levels
    $levels = @('Global', 'GlobalLocal', 'Project', 'ProjectLocal')
    for ($i = 0; $i -lt $levels.Count; $i++) {
        for ($j = $i + 1; $j -lt $levels.Count; $j++) {
            $level1 = $levels[$i]
            $level2 = $levels[$j]

            if (-not $permissionsByLevel.ContainsKey($level1) -or -not $permissionsByLevel.ContainsKey($level2)) {
                continue
            }

            $perms1 = $permissionsByLevel[$level1]
            $perms2 = $permissionsByLevel[$level2]

            # Check allow vs deny conflicts
            foreach ($rule in $perms1.Allow) {
                if ($perms2.Deny -contains $rule) {
                    $conflicts += @{
                        Rule = $rule
                        Level1 = $level1
                        Category1 = "Allow"
                        Level2 = $level2
                        Category2 = "Deny"
                        Resolution = "$level2 Deny overrides $level1 Allow"
                    }
                }
                if ($perms2.Ask -contains $rule) {
                    $conflicts += @{
                        Rule = $rule
                        Level1 = $level1
                        Category1 = "Allow"
                        Level2 = $level2
                        Category2 = "Ask"
                        Resolution = "$level2 Ask overrides $level1 Allow"
                    }
                }
            }

            # Check deny vs allow conflicts
            foreach ($rule in $perms1.Deny) {
                if ($perms2.Allow -contains $rule) {
                    $conflicts += @{
                        Rule = $rule
                        Level1 = $level1
                        Category1 = "Deny"
                        Level2 = $level2
                        Category2 = "Allow"
                        Resolution = "$level2 Allow overrides $level1 Deny"
                    }
                }
            }
        }
    }

    return $conflicts
}

# Get global analytics across all projects
function Get-GlobalAnalytics {
    $projectsPath = "$globalPath\projects"
    $analytics = @{
        TotalProjects = 0
        TotalSessions = 0
        TotalInputTokens = 0
        TotalOutputTokens = 0
        TotalCost = 0.0
        TotalDiskUsage = 0
        ModelUsage = @{}
        ToolUsage = @{}
        DailyUsage = @{}
        Errors = @()
        OrphanProjects = @()
        StaleProjects = @()
        CorruptedFiles = @()
        AgentSessionCount = 0
        AgentTokens = 0
    }

    if (-not (Test-Path $projectsPath)) {
        return $analytics
    }

    $thirtyDaysAgo = (Get-Date).AddDays(-30)

    foreach ($folder in Get-ChildItem $projectsPath -Directory -ErrorAction SilentlyContinue) {
        $analytics.TotalProjects++
        $analytics.TotalDiskUsage += (Get-ChildItem $folder.FullName -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum

        # Get project path from session files
        $decodedPath = $null
        $fileToRead = Get-ChildItem "$($folder.FullName)\*.jsonl" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($fileToRead) {
            try {
                $lines = Get-Content $fileToRead.FullName -First 10 -ErrorAction SilentlyContinue
                foreach ($line in $lines) {
                    if ($line -match '"cwd"\s*:\s*"([^"]+)"') {
                        $decodedPath = $matches[1] -replace '\\\\', '\'
                        break
                    }
                }
            } catch { }
        }

        # Check if orphan (project path doesn't exist)
        if ($decodedPath -and -not (Test-Path $decodedPath)) {
            $folderSize = (Get-ChildItem $folder.FullName -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
            $analytics.OrphanProjects += @{
                EncodedName = $folder.Name
                OriginalPath = $decodedPath
                SessionCount = @(Get-ChildItem "$($folder.FullName)\*.jsonl" -ErrorAction SilentlyContinue).Count
                DiskUsage = $folderSize
            }
        }

        # Get session stats with full analysis
        $sessionStats = Get-SessionStats -FolderPath $folder.FullName -IncludeAgentSessions

        $analytics.TotalSessions += $sessionStats.FileCount
        $analytics.TotalInputTokens += $sessionStats.TotalInputTokens
        $analytics.TotalOutputTokens += $sessionStats.TotalOutputTokens
        $analytics.TotalCost += $sessionStats.TotalCost

        # Check for stale projects (no activity in 30 days)
        $lastActivity = $null
        if ($sessionStats.SessionDetails.Count -gt 0) {
            $lastActivity = ($sessionStats.SessionDetails | Where-Object { $_.EndTime } | Sort-Object EndTime -Descending | Select-Object -First 1).EndTime
        }
        if ($lastActivity -and $lastActivity -lt $thirtyDaysAgo -and $decodedPath -and (Test-Path $decodedPath)) {
            $analytics.StaleProjects += @{
                Name = Split-Path $decodedPath -Leaf
                Path = $decodedPath
                LastActivity = $lastActivity
                DaysSinceActivity = [Math]::Round(((Get-Date) - $lastActivity).TotalDays)
                TokensUsed = $sessionStats.TotalInputTokens + $sessionStats.TotalOutputTokens
            }
        }

        # Merge model usage
        foreach ($model in $sessionStats.ModelUsage.Keys) {
            if (-not $analytics.ModelUsage.ContainsKey($model)) {
                $analytics.ModelUsage[$model] = @{ Calls = 0; InputTokens = 0; OutputTokens = 0 }
            }
            $analytics.ModelUsage[$model].Calls += $sessionStats.ModelUsage[$model].Calls
            $analytics.ModelUsage[$model].InputTokens += $sessionStats.ModelUsage[$model].InputTokens
            $analytics.ModelUsage[$model].OutputTokens += $sessionStats.ModelUsage[$model].OutputTokens
        }

        # Merge tool usage
        foreach ($tool in $sessionStats.ToolUsage.Keys) {
            if (-not $analytics.ToolUsage.ContainsKey($tool)) {
                $analytics.ToolUsage[$tool] = 0
            }
            $analytics.ToolUsage[$tool] += $sessionStats.ToolUsage[$tool]
        }

        # Merge daily usage
        foreach ($date in $sessionStats.DailyUsage.Keys) {
            if (-not $analytics.DailyUsage.ContainsKey($date)) {
                $analytics.DailyUsage[$date] = @{ InputTokens = 0; OutputTokens = 0; Sessions = 0; Cost = 0.0 }
            }
            $analytics.DailyUsage[$date].InputTokens += $sessionStats.DailyUsage[$date].InputTokens
            $analytics.DailyUsage[$date].OutputTokens += $sessionStats.DailyUsage[$date].OutputTokens
            $analytics.DailyUsage[$date].Sessions += $sessionStats.DailyUsage[$date].Sessions
            $analytics.DailyUsage[$date].Cost += $sessionStats.DailyUsage[$date].Cost
        }

        # Collect errors
        $analytics.Errors += $sessionStats.Errors

        # Collect corrupted files
        $analytics.CorruptedFiles += $sessionStats.CorruptedFiles

        # Agent sessions
        $analytics.AgentSessionCount += $sessionStats.AgentSessions.Count
        foreach ($agent in $sessionStats.AgentSessions) {
            $analytics.AgentTokens += $agent.InputTokens + $agent.OutputTokens
        }
    }

    return $analytics
}

# Calculate comprehensive session statistics (tokens, duration, models, tools, errors, conversations)
function Get-SessionStats {
    param(
        [string]$FolderPath,
        [switch]$IncludeConversations,
        [switch]$IncludeAgentSessions
    )

    $stats = @{
        TotalInputTokens = 0
        TotalOutputTokens = 0
        TotalDurationMinutes = 0
        TotalCost = 0.0
        SessionDetails = @()
        ModelUsage = @{}
        ToolUsage = @{}
        Errors = @()
        DailyUsage = @{}
        FileSize = 0
        FileCount = 0
        CorruptedFiles = @()
        AgentSessions = @()
    }

    # Get all session files
    $sessionFiles = @(Get-ChildItem "$FolderPath\*.jsonl" -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike "agent-*" })
    $agentFiles = @(Get-ChildItem "$FolderPath\agent-*.jsonl" -ErrorAction SilentlyContinue)

    $stats.FileCount = $sessionFiles.Count

    foreach ($file in $sessionFiles) {
        $stats.FileSize += $file.Length
        $sessionInput = 0
        $sessionOutput = 0
        $firstTimestamp = $null
        $lastTimestamp = $null
        $sessionModels = @{}
        $sessionTools = @{}
        $sessionErrors = @()
        $sessionMessages = @()
        $isCorrupted = $false
        $lastSeenModel = $null  # Track last model for token attribution
        $lineCount = 0

        try {
            $lines = Get-Content $file.FullName -ErrorAction SilentlyContinue
            foreach ($line in $lines) {
                $lineCount++

                # Try to parse as JSON to detect corruption
                try {
                    $jsonObj = $line | ConvertFrom-Json -ErrorAction Stop
                } catch {
                    $isCorrupted = $true
                    continue
                }

                # Extract model information and track it for token attribution
                if ($line -match '"model"\s*:\s*"([^"]+)"') {
                    $lastSeenModel = $matches[1]
                    if (-not $sessionModels.ContainsKey($lastSeenModel)) {
                        $sessionModels[$lastSeenModel] = @{ InputTokens = 0; OutputTokens = 0; Calls = 0 }
                    }
                    $sessionModels[$lastSeenModel].Calls++
                }

                # Extract tokens from usage object (including cache tokens)
                $lineInputTokens = 0
                $lineOutputTokens = 0

                # Standard input_tokens
                if ($line -match '"input_tokens"\s*:\s*(\d+)') {
                    $lineInputTokens += [int]$matches[1]
                }
                # Cache creation input tokens (counts as input)
                if ($line -match '"cache_creation_input_tokens"\s*:\s*(\d+)') {
                    $lineInputTokens += [int]$matches[1]
                }
                # Cache read input tokens (counts as input)
                if ($line -match '"cache_read_input_tokens"\s*:\s*(\d+)') {
                    $lineInputTokens += [int]$matches[1]
                }
                # Output tokens
                if ($line -match '"output_tokens"\s*:\s*(\d+)') {
                    $lineOutputTokens = [int]$matches[1]
                }

                # Add to session totals
                if ($lineInputTokens -gt 0) {
                    $sessionInput += $lineInputTokens
                }
                if ($lineOutputTokens -gt 0) {
                    $sessionOutput += $lineOutputTokens
                }

                # Attribute tokens to model (model and tokens are on same line in JSONL)
                if ($lastSeenModel -and ($lineInputTokens -gt 0 -or $lineOutputTokens -gt 0)) {
                    $sessionModels[$lastSeenModel].InputTokens += $lineInputTokens
                    $sessionModels[$lastSeenModel].OutputTokens += $lineOutputTokens
                }

                # Extract tool usage
                if ($line -match '"tool"\s*:\s*"([^"]+)"' -or $line -match '"name"\s*:\s*"(Bash|Read|Write|Edit|Glob|Grep|Task|WebFetch|WebSearch|TodoWrite|NotebookEdit)"') {
                    $tool = $matches[1]
                    if (-not $sessionTools.ContainsKey($tool)) {
                        $sessionTools[$tool] = 0
                    }
                    $sessionTools[$tool]++
                }

                # Extract tool calls from content blocks
                if ($line -match '"type"\s*:\s*"tool_use"') {
                    if ($line -match '"name"\s*:\s*"([^"]+)"') {
                        $tool = $matches[1]
                        if (-not $sessionTools.ContainsKey($tool)) {
                            $sessionTools[$tool] = 0
                        }
                        $sessionTools[$tool]++
                    }
                }

                # Extract errors
                if ($line -match '"error"' -or $line -match '"type"\s*:\s*"error"' -or $line -match '"is_error"\s*:\s*true') {
                    $errorMsg = ""
                    if ($line -match '"message"\s*:\s*"([^"]+)"') {
                        $errorMsg = $matches[1]
                    } elseif ($line -match '"error"\s*:\s*\{[^}]*"message"\s*:\s*"([^"]+)"') {
                        $errorMsg = $matches[1]
                    } elseif ($line -match '"error"\s*:\s*"([^"]+)"') {
                        $errorMsg = $matches[1]
                    }
                    if ($errorMsg) {
                        $sessionErrors += @{
                            Message = $errorMsg
                            Timestamp = $null
                            File = $file.Name
                        }
                    }
                }

                # Extract timestamps
                if ($line -match '"timestamp"\s*:\s*"([^"]+)"') {
                    $ts = $matches[1]
                    try {
                        $parsedTime = [DateTime]::Parse($ts)
                        if ($null -eq $firstTimestamp -or $parsedTime -lt $firstTimestamp) {
                            $firstTimestamp = $parsedTime
                        }
                        if ($null -eq $lastTimestamp -or $parsedTime -gt $lastTimestamp) {
                            $lastTimestamp = $parsedTime
                        }

                        # Track daily usage
                        $dateKey = $parsedTime.ToString("yyyy-MM-dd")
                        if (-not $stats.DailyUsage.ContainsKey($dateKey)) {
                            $stats.DailyUsage[$dateKey] = @{ InputTokens = 0; OutputTokens = 0; Sessions = 0; Cost = 0.0 }
                        }

                        # Update error timestamp
                        if ($sessionErrors.Count -gt 0 -and $null -eq $sessionErrors[-1].Timestamp) {
                            $sessionErrors[-1].Timestamp = $parsedTime
                        }
                    } catch { }
                }

                # Extract conversation messages for viewer (limited)
                if ($IncludeConversations -and $sessionMessages.Count -lt 50) {
                    if ($line -match '"role"\s*:\s*"(user|assistant)"') {
                        $role = $matches[1]
                        $content = ""
                        if ($line -match '"text"\s*:\s*"([^"]{0,500})') {
                            $content = $matches[1]
                        } elseif ($line -match '"content"\s*:\s*"([^"]{0,500})') {
                            $content = $matches[1]
                        }
                        if ($content) {
                            $sessionMessages += @{
                                Role = $role
                                Content = $content.Substring(0, [Math]::Min(200, $content.Length))
                            }
                        }
                    }
                }
            }
        } catch {
            $isCorrupted = $true
        }

        if ($isCorrupted -and $lineCount -eq 0) {
            $stats.CorruptedFiles += @{
                Name = $file.Name
                Path = $file.FullName
                Size = $file.Length
            }
        }

        $sessionDuration = 0
        if ($firstTimestamp -and $lastTimestamp) {
            $sessionDuration = ($lastTimestamp - $firstTimestamp).TotalMinutes
        }

        # Calculate cost for this session
        $sessionCost = Get-TokenCost -InputTokens $sessionInput -OutputTokens $sessionOutput

        # Update daily usage
        if ($firstTimestamp) {
            $dateKey = $firstTimestamp.ToString("yyyy-MM-dd")
            if ($stats.DailyUsage.ContainsKey($dateKey)) {
                $stats.DailyUsage[$dateKey].InputTokens += $sessionInput
                $stats.DailyUsage[$dateKey].OutputTokens += $sessionOutput
                $stats.DailyUsage[$dateKey].Sessions++
                $stats.DailyUsage[$dateKey].Cost += $sessionCost.TotalCost
            }
        }

        $stats.TotalInputTokens += $sessionInput
        $stats.TotalOutputTokens += $sessionOutput
        $stats.TotalDurationMinutes += $sessionDuration
        $stats.TotalCost += $sessionCost.TotalCost

        # Merge model usage
        foreach ($model in $sessionModels.Keys) {
            if (-not $stats.ModelUsage.ContainsKey($model)) {
                $stats.ModelUsage[$model] = @{ InputTokens = 0; OutputTokens = 0; Calls = 0 }
            }
            $stats.ModelUsage[$model].Calls += $sessionModels[$model].Calls
            $stats.ModelUsage[$model].InputTokens += $sessionModels[$model].InputTokens
            $stats.ModelUsage[$model].OutputTokens += $sessionModels[$model].OutputTokens
        }

        # Merge tool usage
        foreach ($tool in $sessionTools.Keys) {
            if (-not $stats.ToolUsage.ContainsKey($tool)) {
                $stats.ToolUsage[$tool] = 0
            }
            $stats.ToolUsage[$tool] += $sessionTools[$tool]
        }

        # Add errors
        $stats.Errors += $sessionErrors

        # Add session details
        $stats.SessionDetails += @{
            FileName = $file.Name
            InputTokens = $sessionInput
            OutputTokens = $sessionOutput
            Duration = $sessionDuration
            StartTime = $firstTimestamp
            EndTime = $lastTimestamp
            Cost = $sessionCost.TotalCost
            Messages = $sessionMessages
            Errors = $sessionErrors
            ToolsUsed = $sessionTools.Keys
        }
    }

    # Process agent sessions if requested
    if ($IncludeAgentSessions) {
        foreach ($file in $agentFiles) {
            $agentInput = 0
            $agentOutput = 0
            $agentTimestamp = $null

            try {
                $lines = Get-Content $file.FullName -First 50 -ErrorAction SilentlyContinue
                foreach ($line in $lines) {
                    if ($line -match '"input_tokens"\s*:\s*(\d+)') {
                        $agentInput += [int]$matches[1]
                    }
                    if ($line -match '"output_tokens"\s*:\s*(\d+)') {
                        $agentOutput += [int]$matches[1]
                    }
                    if ($line -match '"timestamp"\s*:\s*"([^"]+)"') {
                        try {
                            $agentTimestamp = [DateTime]::Parse($matches[1])
                        } catch { }
                    }
                }
            } catch { }

            $stats.AgentSessions += @{
                FileName = $file.Name
                InputTokens = $agentInput
                OutputTokens = $agentOutput
                Timestamp = $agentTimestamp
                Size = $file.Length
            }
        }
    }

    return $stats
}

# Collect Projects Information
function Get-ProjectsInfo {
    $projectsPath = "$globalPath\projects"
    $projects = @()

    if (-not (Test-Path $projectsPath)) {
        return $projects
    }

    foreach ($folder in Get-ChildItem $projectsPath -Directory -ErrorAction SilentlyContinue) {
        # Get session files (exclude agent-* files)
        $sessions = @(Get-ChildItem "$($folder.FullName)\*.jsonl" -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike "agent-*" })

        # Also check agent files for cwd if no regular sessions
        $allJsonl = @(Get-ChildItem "$($folder.FullName)\*.jsonl" -ErrorAction SilentlyContinue)

        # Get most recent session
        $lastSession = $sessions | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $lastUsed = if ($lastSession) { $lastSession.LastWriteTime } else { $null }

        # Try to extract cwd from session file
        $decodedPath = $null
        $fileToRead = if ($lastSession) { $lastSession } else { $allJsonl | Select-Object -First 1 }
        if ($fileToRead) {
            try {
                # Read first few lines to find cwd
                $lines = Get-Content $fileToRead.FullName -First 10 -ErrorAction SilentlyContinue
                foreach ($line in $lines) {
                    if ($line -match '"cwd"\s*:\s*"([^"]+)"') {
                        $decodedPath = $matches[1] -replace '\\\\', '\'
                        break
                    }
                }
            } catch { }
        }

        # Fallback to folder name decoding if cwd not found
        if (-not $decodedPath) {
            $decodedPath = $folder.Name -replace '--', ':\'
            $decodedPath = $decodedPath -replace '-', '\'
        }

        # Check if project path still exists
        $projectExists = Test-Path $decodedPath

        # Scan project for local Claude settings (only if project exists)
        $localSettings = @{
            HasSettings = $false
            HasSettingsLocal = $false
            HasMemory = $false
            HasMcp = $false
            HasAgents = $false
            HasCommands = $false
            HasHooks = $false
            SettingsContent = $null
            McpContent = $null
            MemoryContent = $null
            AgentsList = @()
            CommandsList = @()
        }

        if ($projectExists) {
            $localSettings.HasSettings = Test-Path "$decodedPath\.claude\settings.json"
            $localSettings.HasSettingsLocal = Test-Path "$decodedPath\.claude\settings.local.json"
            $localSettings.HasMemory = (Test-Path "$decodedPath\CLAUDE.md") -or (Test-Path "$decodedPath\.claude\CLAUDE.md")
            $localSettings.HasMcp = Test-Path "$decodedPath\.mcp.json"
            $localSettings.HasAgents = Test-Path "$decodedPath\.claude\agents"
            $localSettings.HasCommands = Test-Path "$decodedPath\.claude\commands"
            $localSettings.HasHooks = Test-Path "$decodedPath\.claude\hooks"

            # Get content for details view
            if ($localSettings.HasSettings) {
                $localSettings.SettingsContent = Get-JsonContent "$decodedPath\.claude\settings.json"
            }
            if ($localSettings.HasMcp) {
                $localSettings.McpContent = Get-JsonContent "$decodedPath\.mcp.json"
            }
            if (Test-Path "$decodedPath\CLAUDE.md") {
                $localSettings.MemoryContent = Get-FileContentSafe "$decodedPath\CLAUDE.md"
            } elseif (Test-Path "$decodedPath\.claude\CLAUDE.md") {
                $localSettings.MemoryContent = Get-FileContentSafe "$decodedPath\.claude\CLAUDE.md"
            }
            if ($localSettings.HasAgents) {
                $localSettings.AgentsList = @(Get-ChildItem "$decodedPath\.claude\agents\*.md" -ErrorAction SilentlyContinue | ForEach-Object { $_.BaseName })
            }
            if ($localSettings.HasCommands) {
                $localSettings.CommandsList = @(Get-ChildItem "$decodedPath\.claude\commands\*.md" -Recurse -ErrorAction SilentlyContinue | ForEach-Object { "/" + $_.BaseName })
            }
        }

        # Get session statistics (tokens and duration) with full analysis
        $sessionStats = Get-SessionStats -FolderPath $folder.FullName -IncludeAgentSessions

        $projects += @{
            Name = Split-Path $decodedPath -Leaf
            Path = $decodedPath
            EncodedName = $folder.Name
            SessionCount = $sessions.Count
            LastUsed = $lastUsed
            Exists = $projectExists
            LocalSettings = $localSettings
            TotalTokens = $sessionStats.TotalInputTokens + $sessionStats.TotalOutputTokens
            InputTokens = $sessionStats.TotalInputTokens
            OutputTokens = $sessionStats.TotalOutputTokens
            TotalDurationMinutes = $sessionStats.TotalDurationMinutes
            TotalCost = $sessionStats.TotalCost
            ModelUsage = $sessionStats.ModelUsage
            ToolUsage = $sessionStats.ToolUsage
            Errors = $sessionStats.Errors
            DiskUsage = $sessionStats.FileSize
            AgentSessions = $sessionStats.AgentSessions
            CorruptedFiles = $sessionStats.CorruptedFiles
        }
    }

    return $projects | Sort-Object { $_.LastUsed } -Descending
}

# Get Recommendations (including cleanup recommendations)
function Get-Recommendations {
    param(
        [hashtable]$Analytics = $null
    )

    $recommendations = @()

    $settings = Get-SettingsInfo
    $memory = Get-MemoryInfo
    $agents = Get-AgentsInfo
    $commands = Get-CommandsInfo
    $mcp = Get-McpServersInfo
    $permConflicts = Get-PermissionConflicts

    if (-not $settings.Global.Exists) {
        $recommendations += @{
            Type = "Settings"
            Priority = "Medium"
            Message = "Create global settings.json for defaults across all projects"
            Command = "Create file: $globalPath\settings.json"
        }
    }

    if (-not $memory.Global.Exists -and -not $memory.ProjectRoot.Exists -and -not $memory.ProjectFolder.Exists) {
        $recommendations += @{
            Type = "Memory"
            Priority = "High"
            Message = "Create CLAUDE.md to store project conventions and frequently used commands"
            Command = "Use /init command or create $ProjectPath\CLAUDE.md"
        }
    }

    if (-not $agents.Global.Exists -and -not $agents.Project.Exists) {
        $recommendations += @{
            Type = "Agents"
            Priority = "Low"
            Message = "Create custom agents for specialized tasks"
            Command = "Use /agents command or create files in $globalPath\agents\"
        }
    }

    if (-not $commands.Global.Exists -and -not $commands.Project.Exists) {
        $recommendations += @{
            Type = "Commands"
            Priority = "Medium"
            Message = "Create custom slash commands for reusable workflows"
            Command = "Use /commands command or create files in $globalPath\commands\"
        }
    }

    if ($mcp.Servers.Count -eq 0) {
        $recommendations += @{
            Type = "MCP"
            Priority = "Medium"
            Message = "Add MCP servers to connect to external tools (GitHub, databases, APIs)"
            Command = "Run: claude mcp add --transport http <name> <url>"
        }
    }

    # Permission conflict recommendations
    if ($permConflicts.Count -gt 0) {
        $recommendations += @{
            Type = "Permissions"
            Priority = "High"
            Message = "$($permConflicts.Count) permission conflict(s) detected between settings levels"
            Command = "Review Permissions section for details on conflicting rules"
        }
    }

    # Cleanup recommendations based on analytics
    if ($Analytics) {
        # Orphan projects
        if ($Analytics.OrphanProjects.Count -gt 0) {
            $totalOrphanSize = ($Analytics.OrphanProjects | Measure-Object -Property DiskUsage -Sum).Sum
            $recommendations += @{
                Type = "Cleanup"
                Priority = "Medium"
                Message = "$($Analytics.OrphanProjects.Count) orphan project(s) found ($(Format-FileSize $totalOrphanSize)) - original paths no longer exist"
                Command = "Delete folders in $globalPath\projects\ for projects you no longer need"
            }
        }

        # Stale projects
        if ($Analytics.StaleProjects.Count -gt 0) {
            $recommendations += @{
                Type = "Cleanup"
                Priority = "Low"
                Message = "$($Analytics.StaleProjects.Count) project(s) have not been used in 30+ days"
                Command = "Consider archiving old session data to free up space"
            }
        }

        # Corrupted files
        if ($Analytics.CorruptedFiles.Count -gt 0) {
            $recommendations += @{
                Type = "Maintenance"
                Priority = "High"
                Message = "$($Analytics.CorruptedFiles.Count) corrupted session file(s) detected"
                Command = "Review Maintenance section - corrupted files may need to be deleted"
            }
        }

        # High disk usage warning
        if ($Analytics.TotalDiskUsage -gt 500MB) {
            $recommendations += @{
                Type = "Cleanup"
                Priority = "Medium"
                Message = "Session data is using $(Format-FileSize $Analytics.TotalDiskUsage) of disk space"
                Command = "Consider cleaning up old session files in $globalPath\projects\"
            }
        }

        # High error count
        if ($Analytics.Errors.Count -gt 50) {
            $recommendations += @{
                Type = "Review"
                Priority = "Medium"
                Message = "$($Analytics.Errors.Count) errors detected across all sessions"
                Command = "Review Errors section to identify recurring issues"
            }
        }
    }

    return $recommendations
}

# Generate HTML Report
function New-HtmlReport {
    Write-Host "  Collecting settings..." -ForegroundColor Gray
    $settings = Get-SettingsInfo
    Write-Host "  Collecting MCP servers..." -ForegroundColor Gray
    $mcp = Get-McpServersInfo
    Write-Host "  Collecting memory files..." -ForegroundColor Gray
    $memory = Get-MemoryInfo
    Write-Host "  Collecting agents..." -ForegroundColor Gray
    $agents = Get-AgentsInfo
    Write-Host "  Collecting commands..." -ForegroundColor Gray
    $commands = Get-CommandsInfo
    Write-Host "  Collecting skills..." -ForegroundColor Gray
    $skills = Get-SkillsInfo
    Write-Host "  Collecting plugins..." -ForegroundColor Gray
    $plugins = Get-PluginsInfo
    Write-Host "  Collecting hooks..." -ForegroundColor Gray
    $hooks = Get-HooksInfo
    Write-Host "  Collecting permissions..." -ForegroundColor Gray
    $permissions = Get-ToolPermissions
    Write-Host "  Detecting permission conflicts..." -ForegroundColor Gray
    $permConflicts = Get-PermissionConflicts
    Write-Host "  Checking enterprise settings..." -ForegroundColor Gray
    $managed = Get-ManagedSettingsInfo
    Write-Host "  Analyzing all projects (this may take a moment)..." -ForegroundColor Gray
    $projects = Get-ProjectsInfo
    Write-Host "  Computing global analytics..." -ForegroundColor Gray
    $analytics = Get-GlobalAnalytics
    Write-Host "  Generating recommendations..." -ForegroundColor Gray
    $recommendations = Get-Recommendations -Analytics $analytics

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Count items for menu badges
    $settingsCount = @($settings.Global, $settings.GlobalLocal, $settings.Project, $settings.ProjectLocal | Where-Object { $_.Exists }).Count
    $mcpCount = $mcp.Servers.Count
    $memoryCount = @($memory.Global, $memory.ProjectRoot, $memory.ProjectFolder, $memory.ProjectLocal | Where-Object { $_.Exists }).Count
    $agentsCount = $agents.Global.Files.Count + $agents.Project.Files.Count
    $commandsCount = $commands.Global.Files.Count + $commands.Project.Files.Count
    $skillsCount = $skills.Global.Items.Count + $skills.Project.Items.Count
    $pluginsCount = $plugins.Configured.Count + $plugins.Marketplaces.Count
    $hooksCount = $hooks.FromSettings.Count + $hooks.ProjectFolder.Files.Count
    $permissionsCount = $permissions.Allow.Count + $permissions.Deny.Count + $permissions.Ask.Count
    $conflictsCount = $permConflicts.Count
    $managedCount = @($managed.Settings, $managed.Mcp, $managed.Memory | Where-Object { $_.Exists }).Count
    $recommendationsCount = $recommendations.Count
    $projectsCount = $projects.Count
    $errorsCount = $analytics.Errors.Count
    $toolsCount = $analytics.ToolUsage.Keys.Count
    $modelsCount = $analytics.ModelUsage.Keys.Count
    $maintenanceCount = $analytics.OrphanProjects.Count + $analytics.StaleProjects.Count + $analytics.CorruptedFiles.Count

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Claude Code Inspector - $projectName</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
            background: #0c0c0c;
            min-height: 100vh;
            color: #cccccc;
            display: flex;
        }

        /* Sidebar Menu */
        .sidebar {
            width: 280px;
            background: linear-gradient(180deg, #1a1a1a 0%, #141414 100%);
            border-right: 1px solid #2a2a2a;
            height: 100vh;
            position: fixed;
            overflow-y: auto;
            overflow-x: hidden;
            scrollbar-width: thin;
            scrollbar-color: #333 transparent;
        }
        .sidebar::-webkit-scrollbar {
            width: 6px;
        }
        .sidebar::-webkit-scrollbar-track {
            background: transparent;
        }
        .sidebar::-webkit-scrollbar-thumb {
            background: #333;
            border-radius: 3px;
        }
        .sidebar::-webkit-scrollbar-thumb:hover {
            background: #444;
        }
        .sidebar-header {
            padding: 24px 20px;
            border-bottom: 1px solid #2a2a2a;
            background: linear-gradient(180deg, #1e1e1e 0%, #1a1a1a 100%);
            position: sticky;
            top: 0;
            z-index: 10;
        }
        .sidebar-header h1 {
            font-size: 13px;
            color: #e0e0e0;
            font-weight: 500;
            margin-bottom: 6px;
            letter-spacing: 0.3px;
        }
        .sidebar-header .prompt {
            color: #666;
            font-size: 11px;
            letter-spacing: 0.2px;
        }
        .sidebar-header .project {
            color: #4da6ff;
            font-size: 12px;
            margin-top: 10px;
            word-break: break-all;
            padding: 8px 10px;
            background: rgba(0, 120, 212, 0.08);
            border-radius: 6px;
            border: 1px solid rgba(0, 120, 212, 0.15);
        }

        .menu { list-style: none; padding: 8px 0; }
        .menu-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 11px 20px;
            margin: 2px 8px;
            color: #888;
            cursor: pointer;
            border-radius: 8px;
            border-left: 3px solid transparent;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
        }
        .menu-item:hover {
            background: rgba(255, 255, 255, 0.04);
            color: #e0e0e0;
            transform: translateX(2px);
        }
        .menu-item.active {
            background: linear-gradient(90deg, rgba(0, 120, 212, 0.15) 0%, rgba(0, 120, 212, 0.05) 100%);
            color: #fff;
            border-left-color: #0078d4;
            box-shadow: 0 2px 8px rgba(0, 120, 212, 0.1);
        }
        .menu-item.active::before {
            content: '';
            position: absolute;
            left: 0;
            top: 50%;
            transform: translateY(-50%);
            width: 3px;
            height: 60%;
            background: #0078d4;
            border-radius: 0 2px 2px 0;
        }
        .menu-item .label {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 12.5px;
            font-weight: 400;
        }
        .menu-item .prefix {
            color: #555;
            font-size: 11px;
            transition: color 0.2s;
        }
        .menu-item:hover .prefix,
        .menu-item.active .prefix {
            color: #0078d4;
        }
        .menu-item .badge {
            background: #252525;
            color: #666;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: 500;
            letter-spacing: 0.3px;
            border: 1px solid #333;
            transition: all 0.2s;
        }
        .menu-item:hover .badge {
            background: #2a2a2a;
            color: #888;
        }
        .menu-item.active .badge {
            background: linear-gradient(135deg, #0078d4 0%, #005a9e 100%);
            color: #fff;
            border-color: transparent;
            box-shadow: 0 2px 4px rgba(0, 120, 212, 0.3);
        }
        .menu-item.has-items .badge {
            background: linear-gradient(135deg, #2d5016 0%, #1e3a0f 100%);
            color: #7ec850;
            border-color: rgba(126, 200, 80, 0.2);
        }

        .menu-divider {
            height: 1px;
            background: linear-gradient(90deg, transparent 0%, #333 50%, transparent 100%);
            margin: 12px 20px;
        }

        /* Main Content */
        .main {
            margin-left: 280px;
            flex: 1;
            padding: 0;
        }

        .terminal-bar {
            background: #323232;
            padding: 8px 16px;
            display: flex;
            align-items: center;
            gap: 12px;
            border-bottom: 1px solid #333;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        .terminal-bar .dots { display: flex; gap: 6px; }
        .terminal-bar .dot { width: 12px; height: 12px; border-radius: 50%; }
        .terminal-bar .dot.red { background: #ff5f56; }
        .terminal-bar .dot.yellow { background: #ffbd2e; }
        .terminal-bar .dot.green { background: #27ca40; }
        .terminal-bar .title { color: #888; font-size: 12px; flex: 1; text-align: center; }
        .terminal-bar .timestamp { color: #555; font-size: 11px; }

        .content {
            padding: 20px 30px;
        }

        .section {
            display: none;
            animation: fadeIn 0.2s ease;
        }
        .section.active { display: block; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

        .section-title {
            color: #fff;
            font-size: 16px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #333;
        }
        .section-title .count { color: #666; font-weight: normal; }

        .subsection-title {
            color: #888;
            font-size: 13px;
            margin: 20px 0 10px 0;
            padding-bottom: 6px;
            border-bottom: 1px solid #2a2a2a;
        }

        .section-description {
            color: #888;
            font-size: 12px;
            margin: -10px 0 20px 0;
            padding: 12px 15px;
            background: rgba(255, 255, 255, 0.02);
            border-left: 3px solid #333;
            border-radius: 0 4px 4px 0;
        }
        .section-description a {
            color: #4da6ff;
            text-decoration: none;
        }
        .section-description a:hover {
            text-decoration: underline;
        }
        .section-description code {
            background: #252525;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 11px;
        }

        /* Terminal Output Style */
        .output-line {
            padding: 6px 0;
            border-bottom: 1px solid #1a1a1a;
            display: flex;
            align-items: flex-start;
            gap: 12px;
        }
        .output-line:hover { background: #1a1a1a; }
        .output-line .key { color: #666; min-width: 180px; }
        .output-line .value { color: #cccccc; flex: 1; }
        .output-line .value.ok { color: #7ec850; }
        .output-line .value.missing { color: #666; }
        .output-line .value.warn { color: #dcdcaa; }

        .output-block {
            background: #1a1a1a;
            border: 1px solid #333;
            margin: 15px 0;
            overflow: hidden;
        }
        .output-block-header {
            background: #252525;
            padding: 8px 12px;
            color: #888;
            font-size: 12px;
            border-bottom: 1px solid #333;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
        }
        .output-block-header:hover { background: #2a2a2a; }
        .output-block-header .toggle { color: #555; }
        .output-block-content {
            padding: 12px;
            max-height: 300px;
            overflow-y: auto;
            display: none;
        }
        .output-block.open .output-block-content { display: block; }
        .output-block.open .toggle::before { content: '[-]'; }
        .output-block .toggle::before { content: '[+]'; }

        pre {
            color: #9cdcfe;
            font-size: 12px;
            line-height: 1.5;
            white-space: pre-wrap;
            word-break: break-all;
        }

        /* Permissions Grid */
        .perm-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-top: 15px;
        }
        .perm-col h4 {
            font-size: 12px;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid #333;
        }
        .perm-col.allow h4 { color: #7ec850; }
        .perm-col.deny h4 { color: #f14c4c; }
        .perm-col.ask h4 { color: #dcdcaa; }
        .perm-col ul { list-style: none; }
        .perm-col li {
            padding: 4px 0;
            font-size: 12px;
            color: #999;
        }
        .perm-col li .src { color: #555; margin-left: 8px; }
        .perm-col .empty { color: #444; font-style: italic; }

        /* Recommendations */
        .rec-item {
            background: #1a1a1a;
            border-left: 3px solid #333;
            padding: 12px 16px;
            margin-bottom: 10px;
        }
        .rec-item.high { border-left-color: #f14c4c; }
        .rec-item.medium { border-left-color: #dcdcaa; }
        .rec-item.low { border-left-color: #7ec850; }
        .rec-item .rec-header {
            display: flex;
            gap: 10px;
            margin-bottom: 8px;
        }
        .rec-item .rec-priority {
            font-size: 10px;
            padding: 2px 6px;
            background: #333;
        }
        .rec-item.high .rec-priority { background: #5c1d1d; color: #f14c4c; }
        .rec-item.medium .rec-priority { background: #4d4017; color: #dcdcaa; }
        .rec-item.low .rec-priority { background: #2d5016; color: #7ec850; }
        .rec-item .rec-type { color: #666; font-size: 11px; }
        .rec-item .rec-msg { color: #ccc; margin-bottom: 8px; }
        .rec-item .rec-cmd {
            background: #0c0c0c;
            padding: 8px 10px;
            color: #888;
            font-size: 11px;
        }

        .empty-state {
            color: #444;
            padding: 40px;
            text-align: center;
        }
        .empty-state .prompt { color: #666; margin-top: 10px; font-size: 12px; }

        /* Item list */
        .item-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #1a1a1a;
        }
        .item-row:hover { background: #1a1a1a; margin: 0 -10px; padding: 8px 10px; }
        .item-row .name { color: #9cdcfe; }
        .item-row .source { color: #555; font-size: 11px; }
        .item-row .source.badge-global,
        .output-block-header .source.badge-global {
            background: rgba(78, 154, 241, 0.15);
            color: #4e9af1;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 10px;
        }
        .item-row .source.badge-project,
        .output-block-header .source.badge-project {
            background: rgba(126, 200, 80, 0.15);
            color: #7ec850;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 10px;
        }
        .item-row .source.badge-enterprise,
        .output-block-header .source.badge-enterprise {
            background: rgba(220, 170, 80, 0.15);
            color: #dcaa50;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 10px;
        }
        .item-row .status { font-size: 11px; }
        .item-row .status.ok { color: #7ec850; }
        .item-row .status.warn { color: #dcdcaa; }

        /* JSON Syntax Highlighting */
        .json-view {
            background: #0c0c0c;
            border: 1px solid #252525;
            border-radius: 4px;
            padding: 12px;
            overflow-x: auto;
            font-family: 'Cascadia Code', 'Consolas', monospace;
            font-size: 12px;
            line-height: 1.5;
        }
        .json-key { color: #9cdcfe; }
        .json-string { color: #ce9178; }
        .json-number { color: #b5cea8; }
        .json-boolean { color: #569cd6; }
        .json-null { color: #569cd6; }
        .json-bracket { color: #da70d6; }
        .json-colon { color: #cccccc; }
        .json-comma { color: #cccccc; }

        /* Project Rows */
        .project-row {
            display: grid;
            grid-template-columns: 150px minmax(120px, 1fr) 60px 80px 70px 90px minmax(100px, 250px);
            padding: 10px 0;
            border-bottom: 1px solid #1a1a1a;
            font-size: 12px;
            align-items: center;
            cursor: pointer;
            gap: 8px;
        }
        .project-row:hover { background: #1a1a1a; margin: 0 -10px; padding: 10px; }
        .project-row .project-name { color: #9cdcfe; font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .project-row .project-path {
            color: #666;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .project-row .project-sessions { color: #888; text-align: center; }
        .project-row .project-tokens { color: #dcdcaa; text-align: right; font-size: 11px; }
        .project-row .project-duration { color: #888; text-align: right; font-size: 11px; }
        .project-row .project-last { color: #555; text-align: center; font-size: 11px; }
        .project-row .project-config { display: flex; gap: 4px; flex-wrap: wrap; justify-content: flex-end; }
        .project-row .project-config span {
            display: inline-block;
            padding: 2px 6px;
            font-size: 10px;
            border-radius: 2px;
            white-space: nowrap;
        }
        .project-row .project-config .cfg-ok { background: #2d5016; color: #7ec850; }
        .project-row .project-config .cfg-missing { color: #333; }
        .project-row.missing .project-name { color: #f14c4c; text-decoration: line-through; }
        .project-row.missing .project-path { color: #444; }

        .project-header {
            display: grid;
            grid-template-columns: 150px minmax(120px, 1fr) 60px 80px 70px 90px minmax(100px, 250px);
            padding: 8px 0;
            border-bottom: 2px solid #333;
            font-size: 11px;
            color: #666;
            text-transform: uppercase;
            gap: 8px;
        }
        .project-header span { cursor: pointer; user-select: none; white-space: nowrap; }
        .project-header span:hover { color: #fff; }
        .project-header span.sorted { color: #0078d4; }
        .project-header span.sorted::after { content: ' \25BC'; font-size: 8px; vertical-align: middle; }
        .project-header span.sorted.asc::after { content: ' \25B2'; }
        .project-header span:nth-child(3) { text-align: center; }
        .project-header span:nth-child(4),
        .project-header span:nth-child(5) { text-align: right; }
        .project-header span:nth-child(6) { text-align: center; }
        .project-header span:nth-child(7) { text-align: right; }

        .project-details {
            display: none;
            background: #141414;
            border: 1px solid #252525;
            margin: 5px 0 15px 0;
            padding: 15px;
        }
        .project-details.open { display: block; }
        .project-details h4 {
            color: #888;
            font-size: 11px;
            margin: 15px 0 8px 0;
            text-transform: uppercase;
        }
        .project-details h4:first-child { margin-top: 0; }
        .project-details .config-status {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 8px;
        }
        .project-details .config-item {
            display: flex;
            justify-content: space-between;
            padding: 6px 10px;
            background: #1a1a1a;
        }
        .project-details .config-item .label { color: #888; }
        .project-details .config-item .status { color: #7ec850; }
        .project-details .config-item .status.no { color: #555; }

        /* Analytics Cards */
        .analytics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }
        .analytics-card {
            background: #1a1a1a;
            border: 1px solid #333;
            padding: 15px;
        }
        .analytics-card .card-label { color: #666; font-size: 11px; text-transform: uppercase; margin-bottom: 8px; }
        .analytics-card .card-value { color: #fff; font-size: 24px; font-weight: 500; }
        .analytics-card .card-sub { color: #888; font-size: 11px; margin-top: 4px; }
        .analytics-card.highlight .card-value { color: #7ec850; }
        .analytics-card.cost .card-value { color: #dcdcaa; }
        .analytics-card.warning .card-value { color: #f14c4c; }

        /* Chart Container */
        .chart-container {
            background: #1a1a1a;
            border: 1px solid #333;
            padding: 20px;
            margin: 20px 0;
        }
        .chart-title { color: #888; font-size: 12px; margin-bottom: 15px; text-transform: uppercase; }
        .bar-chart { display: flex; flex-direction: column; gap: 8px; }
        .bar-row { display: flex; align-items: center; gap: 10px; }
        .bar-label { color: #888; font-size: 11px; min-width: 180px; max-width: 180px; text-align: right; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .bar-track { flex: 1; height: 20px; background: #252525; position: relative; min-width: 100px; }
        .bar-fill { height: 100%; background: #0078d4; transition: width 0.3s; }
        .bar-fill.green { background: #7ec850; }
        .bar-fill.yellow { background: #dcdcaa; }
        .bar-fill.red { background: #f14c4c; }
        .bar-value { color: #666; font-size: 11px; min-width: 80px; text-align: right; }

        /* Usage Chart (Time-based) */
        .usage-chart { height: 150px; display: flex; align-items: flex-end; gap: 2px; padding-top: 20px; }
        .usage-bar { flex: 1; min-width: 8px; background: #0078d4; position: relative; transition: height 0.3s; }
        .usage-bar:hover { background: #1a8cff; }
        .usage-bar::after {
            content: attr(data-tooltip);
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            background: #333;
            color: #fff;
            padding: 4px 8px;
            font-size: 10px;
            white-space: nowrap;
            border-radius: 3px;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.2s;
        }
        .usage-bar:hover::after { opacity: 1; }
        .chart-axis { display: flex; justify-content: space-between; color: #555; font-size: 10px; margin-top: 8px; }

        /* Error List */
        .error-item {
            background: #1a1a1a;
            border-left: 3px solid #f14c4c;
            padding: 10px 15px;
            margin-bottom: 8px;
        }
        .error-item .error-msg { color: #f14c4c; font-size: 12px; }
        .error-item .error-meta { color: #555; font-size: 10px; margin-top: 4px; }

        /* Tool Usage Grid */
        .tool-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            gap: 10px;
        }
        .tool-item {
            background: #1a1a1a;
            padding: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .tool-item .tool-name { color: #9cdcfe; font-size: 12px; }
        .tool-item .tool-count { color: #dcdcaa; font-size: 14px; font-weight: 500; }

        /* Model Token Usage Grid */
        .model-tokens-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 10px;
            margin-top: 15px;
        }
        .model-token-item {
            background: #1a1a1a;
            padding: 10px 12px;
            display: flex;
            align-items: center;
            gap: 12px;
            border: 1px solid #252525;
        }
        .model-token-item .model-name {
            color: #9cdcfe;
            font-size: 11px;
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .model-token-item .token-in {
            color: #7ec850;
            font-size: 11px;
            min-width: 70px;
        }
        .model-token-item .token-out {
            color: #dcdcaa;
            font-size: 11px;
            min-width: 70px;
        }
        .model-token-item .token-calls {
            color: #666;
            font-size: 10px;
            min-width: 60px;
        }

        /* Maintenance Items */
        .maint-item {
            background: #1a1a1a;
            border: 1px solid #333;
            padding: 12px 15px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .maint-item .maint-info { flex: 1; }
        .maint-item .maint-name { color: #9cdcfe; font-size: 12px; }
        .maint-item .maint-detail { color: #666; font-size: 11px; margin-top: 2px; }
        .maint-item .maint-size { color: #dcdcaa; font-size: 11px; }
        .maint-item.orphan { border-left: 3px solid #f14c4c; }
        .maint-item.stale { border-left: 3px solid #dcdcaa; }
        .maint-item.corrupted { border-left: 3px solid #f14c4c; }

        /* Conflict Items */
        .conflict-item {
            background: #1a1a1a;
            border-left: 3px solid #dcdcaa;
            padding: 12px 15px;
            margin-bottom: 10px;
        }
        .conflict-item .conflict-rule { color: #9cdcfe; font-size: 12px; font-weight: 500; }
        .conflict-item .conflict-levels { color: #888; font-size: 11px; margin-top: 6px; }
        .conflict-item .conflict-resolution { color: #7ec850; font-size: 11px; margin-top: 4px; }

        /* Menu Section Header */
        .menu-section-title {
            color: #4a4a4a;
            font-size: 9px;
            text-transform: uppercase;
            padding: 18px 20px 8px 20px;
            letter-spacing: 1.5px;
            font-weight: 600;
            position: relative;
        }
        .menu-section-title::after {
            content: '';
            position: absolute;
            bottom: 4px;
            left: 20px;
            width: 24px;
            height: 2px;
            background: linear-gradient(90deg, #333 0%, transparent 100%);
            border-radius: 1px;
        }

        /* Subsection */
        .subsection {
            margin: 20px 0;
            padding-top: 15px;
            border-top: 1px solid #252525;
        }
        .subsection-title {
            color: #888;
            font-size: 13px;
            margin-bottom: 15px;
        }

        @media (max-width: 900px) {
            .sidebar { width: 100%; height: auto; position: relative; }
            .main { margin-left: 0; }
            .perm-grid { grid-template-columns: 1fr; }
            .project-row { grid-template-columns: 1fr; gap: 5px; }
            .project-header { display: none; }
            .analytics-grid { grid-template-columns: 1fr 1fr; }
        }
    </style>
</head>
<body>
    <nav class="sidebar">
        <div class="sidebar-header">
            <h1>PS C:\&gt; claude-inspector</h1>
            <div class="prompt">Claude Code Configuration Inspector</div>
            <div class="project">$projectName</div>
        </div>
        <ul class="menu">
            <li class="menu-item active has-items" data-section="analytics">
                <span class="label"><span class="prefix">&gt;</span> Analytics</span>
                <span class="badge">Overview</span>
            </li>
            <li class="menu-item $(if($projectsCount -gt 0){'has-items'})" data-section="projects">
                <span class="label"><span class="prefix">&gt;</span> Projects</span>
                <span class="badge">$projectsCount</span>
            </li>
            <li class="menu-divider"></li>
            <li class="menu-section-title">Configuration</li>
            <li class="menu-item " data-section="settings">
                <span class="label"><span class="prefix">&gt;</span> Settings</span>
                <span class="badge">$settingsCount/4</span>
            </li>
            <li class="menu-item $(if($mcpCount -gt 0){'has-items'})" data-section="mcp">
                <span class="label"><span class="prefix">&gt;</span> MCP Servers</span>
                <span class="badge">$mcpCount</span>
            </li>
            <li class="menu-item $(if($memoryCount -gt 0){'has-items'})" data-section="memory">
                <span class="label"><span class="prefix">&gt;</span> Memory</span>
                <span class="badge">$memoryCount/4</span>
            </li>
            <li class="menu-item $(if($agentsCount -gt 0){'has-items'})" data-section="agents">
                <span class="label"><span class="prefix">&gt;</span> Agents</span>
                <span class="badge">$agentsCount</span>
            </li>
            <li class="menu-item $(if($commandsCount -gt 0){'has-items'})" data-section="commands">
                <span class="label"><span class="prefix">&gt;</span> Commands</span>
                <span class="badge">$commandsCount</span>
            </li>
            <li class="menu-item $(if($skillsCount -gt 0){'has-items'})" data-section="skills">
                <span class="label"><span class="prefix">&gt;</span> Skills</span>
                <span class="badge">$skillsCount</span>
            </li>
            <li class="menu-item $(if($pluginsCount -gt 0){'has-items'})" data-section="plugins">
                <span class="label"><span class="prefix">&gt;</span> Plugins</span>
                <span class="badge">$pluginsCount</span>
            </li>
            <li class="menu-item $(if($hooksCount -gt 0){'has-items'})" data-section="hooks">
                <span class="label"><span class="prefix">&gt;</span> Hooks</span>
                <span class="badge">$hooksCount</span>
            </li>
            <li class="menu-item $(if($permissionsCount -gt 0){'has-items'})" data-section="permissions">
                <span class="label"><span class="prefix">&gt;</span> Permissions</span>
                <span class="badge">$permissionsCount</span>
            </li>
            <li class="menu-item $(if($managedCount -gt 0){'has-items'})" data-section="enterprise">
                <span class="label"><span class="prefix">&gt;</span> Enterprise</span>
                <span class="badge">$managedCount/3</span>
            </li>
            <li class="menu-divider"></li>
            <li class="menu-section-title">Usage Data</li>
            <li class="menu-item $(if($toolsCount -gt 0){'has-items'})" data-section="tools">
                <span class="label"><span class="prefix">&gt;</span> Tool Usage</span>
                <span class="badge">$toolsCount</span>
            </li>
            <li class="menu-item $(if($modelsCount -gt 0){'has-items'})" data-section="models">
                <span class="label"><span class="prefix">&gt;</span> Models</span>
                <span class="badge">$modelsCount</span>
            </li>
            <li class="menu-item $(if($errorsCount -gt 0){'has-items'})" data-section="errors">
                <span class="label"><span class="prefix">&gt;</span> Errors</span>
                <span class="badge">$errorsCount</span>
            </li>
            <li class="menu-divider"></li>
            <li class="menu-section-title">Maintenance</li>
            <li class="menu-item $(if($maintenanceCount -gt 0){'has-items'})" data-section="maintenance">
                <span class="label"><span class="prefix">&gt;</span> Cleanup</span>
                <span class="badge">$maintenanceCount</span>
            </li>
            <li class="menu-item $(if($conflictsCount -gt 0){'has-items'})" data-section="conflicts">
                <span class="label"><span class="prefix">&gt;</span> Conflicts</span>
                <span class="badge">$conflictsCount</span>
            </li>
            <li class="menu-item $(if($recommendationsCount -gt 0){'has-items'})" data-section="recommendations">
                <span class="label"><span class="prefix">&gt;</span> Recommendations</span>
                <span class="badge">$recommendationsCount</span>
            </li>
        </ul>
    </nav>

    <main class="main">
        <div class="terminal-bar">
            <div class="dots">
                <span class="dot red"></span>
                <span class="dot yellow"></span>
                <span class="dot green"></span>
            </div>
            <span class="title">PowerShell - claude-inspector.ps1</span>
            <span class="timestamp">$timestamp</span>
        </div>

        <div class="content">
            <!-- Analytics Section -->
            <div id="analytics" class="section active">
                <h2 class="section-title">Analytics Overview</h2>
                <div class="analytics-grid">
                    <div class="analytics-card">
                        <div class="card-label">Total Projects</div>
                        <div class="card-value">$($analytics.TotalProjects)</div>
                        <div class="card-sub">$($analytics.TotalSessions) sessions</div>
                    </div>
                    <div class="analytics-card highlight">
                        <div class="card-label">Total Tokens</div>
                        <div class="card-value">$(if($analytics.TotalInputTokens + $analytics.TotalOutputTokens -ge 1000000){"{0:N1}M" -f (($analytics.TotalInputTokens + $analytics.TotalOutputTokens)/1000000)}else{"{0:N0}K" -f (($analytics.TotalInputTokens + $analytics.TotalOutputTokens)/1000)})</div>
                        <div class="card-sub">In: $(if($analytics.TotalInputTokens -ge 1000000){"{0:N1}M" -f ($analytics.TotalInputTokens/1000000)}else{"{0:N0}K" -f ($analytics.TotalInputTokens/1000)}) / Out: $(if($analytics.TotalOutputTokens -ge 1000000){"{0:N1}M" -f ($analytics.TotalOutputTokens/1000000)}else{"{0:N0}K" -f ($analytics.TotalOutputTokens/1000)})</div>
                    </div>
                    <div class="analytics-card cost">
                        <div class="card-label">Estimated Cost</div>
                        <div class="card-value">`$$("{0:N2}" -f $analytics.TotalCost)</div>
                        <div class="card-sub">Based on default rates</div>
                    </div>
                    <div class="analytics-card">
                        <div class="card-label">Disk Usage</div>
                        <div class="card-value">$(Format-FileSize $analytics.TotalDiskUsage)</div>
                        <div class="card-sub">Session data</div>
                    </div>
                    <div class="analytics-card $(if($errorsCount -gt 0){'warning'})">
                        <div class="card-label">Errors</div>
                        <div class="card-value">$errorsCount</div>
                        <div class="card-sub">Across all sessions</div>
                    </div>
                    <div class="analytics-card">
                        <div class="card-label">Agent Sessions</div>
                        <div class="card-value">$($analytics.AgentSessionCount)</div>
                        <div class="card-sub">$(if($analytics.AgentTokens -ge 1000){"{0:N0}K tokens" -f ($analytics.AgentTokens/1000)}else{"$($analytics.AgentTokens) tokens"})</div>
                    </div>
                </div>
"@

    # Generate daily usage chart data (last 14 days)
    $chartDays = 14
    $today = Get-Date
    $chartData = @()
    $maxTokens = 1
    for ($i = $chartDays - 1; $i -ge 0; $i--) {
        $date = $today.AddDays(-$i).ToString("yyyy-MM-dd")
        $dayData = $analytics.DailyUsage[$date]
        $tokens = if ($dayData) { $dayData.InputTokens + $dayData.OutputTokens } else { 0 }
        if ($tokens -gt $maxTokens) { $maxTokens = $tokens }
        $chartData += @{ Date = $date; Tokens = $tokens; Sessions = if ($dayData) { $dayData.Sessions } else { 0 }; Cost = if ($dayData) { $dayData.Cost } else { 0 } }
    }

    $html += @"
                <div class="chart-container">
                    <div class="chart-title">Token Usage (Last 14 Days)</div>
                    <div class="usage-chart">
"@

    foreach ($day in $chartData) {
        $heightPct = if ($maxTokens -gt 0) { [Math]::Max(2, [Math]::Round(($day.Tokens / $maxTokens) * 100)) } else { 2 }
        $tooltip = "$($day.Date): $(if($day.Tokens -ge 1000){"{0:N0}K" -f ($day.Tokens/1000)}else{$day.Tokens}) tokens, $($day.Sessions) sessions"
        $html += "                        <div class='usage-bar' style='height: ${heightPct}%' data-tooltip='$tooltip'></div>`n"
    }

    $html += @"
                    </div>
                    <div class="chart-axis">
                        <span>$($chartData[0].Date)</span>
                        <span>$($chartData[-1].Date)</span>
                    </div>
                </div>
"@

    # Generate Token Usage per Model chart
    if ($analytics.ModelUsage.Keys.Count -gt 0) {
        $sortedModelsByTokens = $analytics.ModelUsage.GetEnumerator() |
            ForEach-Object { @{ Name = $_.Key; Total = $_.Value.InputTokens + $_.Value.OutputTokens; Input = $_.Value.InputTokens; Output = $_.Value.OutputTokens; Calls = $_.Value.Calls } } |
            Sort-Object { $_.Total } -Descending
        $maxModelTokens = ($sortedModelsByTokens | Select-Object -First 1).Total
        if ($maxModelTokens -eq 0) { $maxModelTokens = 1 }

        $html += @"
                <div class="chart-container">
                    <div class="chart-title">Token Usage by Model</div>
                    <div class="bar-chart">
"@
        foreach ($modelData in $sortedModelsByTokens) {
            $modelName = ConvertTo-HtmlEncoded $modelData.Name
            $totalTokens = $modelData.Total
            $inputTokens = $modelData.Input
            $outputTokens = $modelData.Output
            $widthPct = [Math]::Round(($totalTokens / $maxModelTokens) * 100)

            # Format token display
            $totalDisplay = if ($totalTokens -ge 1000000) { "{0:N1}M" -f ($totalTokens / 1000000) } elseif ($totalTokens -ge 1000) { "{0:N0}K" -f ($totalTokens / 1000) } else { "$totalTokens" }
            $inputDisplay = if ($inputTokens -ge 1000000) { "{0:N1}M" -f ($inputTokens / 1000000) } elseif ($inputTokens -ge 1000) { "{0:N0}K" -f ($inputTokens / 1000) } else { "$inputTokens" }
            $outputDisplay = if ($outputTokens -ge 1000000) { "{0:N1}M" -f ($outputTokens / 1000000) } elseif ($outputTokens -ge 1000) { "{0:N0}K" -f ($outputTokens / 1000) } else { "$outputTokens" }

            # Color based on model type
            $barClass = if ($modelName -match "opus") { "yellow" } elseif ($modelName -match "haiku") { "green" } else { "" }

            $html += @"
                        <div class="bar-row">
                            <span class="bar-label" title="$modelName">$modelName</span>
                            <div class="bar-track"><div class="bar-fill $barClass" style="width: ${widthPct}%"></div></div>
                            <span class="bar-value">$totalDisplay</span>
                        </div>
"@
        }
        $html += @"
                    </div>
                </div>
                <div class="model-tokens-grid">
"@
        foreach ($modelData in $sortedModelsByTokens) {
            $modelName = ConvertTo-HtmlEncoded $modelData.Name
            $inputTokens = $modelData.Input
            $outputTokens = $modelData.Output
            $inputDisplay = if ($inputTokens -ge 1000000) { "{0:N1}M" -f ($inputTokens / 1000000) } elseif ($inputTokens -ge 1000) { "{0:N0}K" -f ($inputTokens / 1000) } else { "$inputTokens" }
            $outputDisplay = if ($outputTokens -ge 1000000) { "{0:N1}M" -f ($outputTokens / 1000000) } elseif ($outputTokens -ge 1000) { "{0:N0}K" -f ($outputTokens / 1000) } else { "$outputTokens" }

            $html += @"
                    <div class="model-token-item">
                        <span class="model-name" title="$modelName">$modelName</span>
                        <span class="token-in">In: $inputDisplay</span>
                        <span class="token-out">Out: $outputDisplay</span>
                    </div>
"@
        }
        $html += "                </div>`n"
    }

    $html += @"
            </div>

            <!-- Projects Section -->
            <div id="projects" class="section">
                <h2 class="section-title">All Projects <span class="count">($projectsCount found)</span></h2>
                <div class="project-header" id="project-header" style="grid-template-columns: 140px minmax(100px, 1fr) 55px 70px 60px 60px 80px minmax(80px, 200px);">
                    <span data-sort="name">Name</span>
                    <span data-sort="path">Path</span>
                    <span data-sort="sessions">Sessions</span>
                    <span data-sort="tokens">Tokens</span>
                    <span data-sort="cost">Cost</span>
                    <span data-sort="duration">Duration</span>
                    <span data-sort="lastused" class="sorted">Last Used</span>
                    <span>Configuration</span>
                </div>
                <div id="project-list">
"@

    if ($projects.Count -gt 0) {
        $projectIndex = 0
        foreach ($proj in $projects) {
            $projName = ConvertTo-HtmlEncoded $proj.Name
            $projPath = ConvertTo-HtmlEncoded $proj.Path
            $projSessions = $proj.SessionCount
            $projMissing = if (-not $proj.Exists) { "missing" } else { "" }
            $ls = $proj.LocalSettings

            # Format tokens (e.g., 1.2M, 450K, 5K)
            $totalTokens = $proj.TotalTokens
            $tokensDisplay = if ($totalTokens -ge 1000000) {
                "{0:N1}M" -f ($totalTokens / 1000000)
            } elseif ($totalTokens -ge 1000) {
                "{0:N0}K" -f ($totalTokens / 1000)
            } else {
                "$totalTokens"
            }

            # Format duration (e.g., 2h 30m, 45m, 5m)
            $totalMinutes = [Math]::Round($proj.TotalDurationMinutes)
            $durationDisplay = if ($totalMinutes -ge 60) {
                $hours = [Math]::Floor($totalMinutes / 60)
                $mins = $totalMinutes % 60
                if ($mins -gt 0) { "${hours}h ${mins}m" } else { "${hours}h" }
            } elseif ($totalMinutes -gt 0) {
                "${totalMinutes}m"
            } else {
                "--"
            }

            # Format last used date
            $projLastUsed = if ($proj.LastUsed) { $proj.LastUsed.ToString("yyyy-MM-dd") } else { "N/A" }
            $projLastUsedSort = if ($proj.LastUsed) { $proj.LastUsed.ToString("yyyy-MM-dd HH:mm:ss") } else { "1900-01-01" }

            # Format cost
            $projCost = if ($proj.TotalCost) { $proj.TotalCost } else { 0 }
            $costDisplay = "`${0:N2}" -f $projCost

            # Config badges
            $cfgBadges = ""
            $cfgCount = 0
            if ($ls.HasSettings) { $cfgBadges += "<span class='cfg-ok'>Settings</span>"; $cfgCount++ }
            if ($ls.HasSettingsLocal) { $cfgBadges += "<span class='cfg-ok'>Local</span>"; $cfgCount++ }
            if ($ls.HasMemory) { $cfgBadges += "<span class='cfg-ok'>Memory</span>"; $cfgCount++ }
            if ($ls.HasMcp) { $cfgBadges += "<span class='cfg-ok'>MCP</span>"; $cfgCount++ }
            if ($ls.HasAgents) { $cfgBadges += "<span class='cfg-ok'>Agents</span>"; $cfgCount++ }
            if ($ls.HasCommands) { $cfgBadges += "<span class='cfg-ok'>Commands</span>"; $cfgCount++ }
            if ($ls.HasHooks) { $cfgBadges += "<span class='cfg-ok'>Hooks</span>"; $cfgCount++ }
            if ($cfgBadges -eq "") { $cfgBadges = "<span class='cfg-missing'>--</span>" }

            $html += @"
                <div class="project-row $projMissing" style="grid-template-columns: 140px minmax(100px, 1fr) 55px 70px 60px 60px 80px minmax(80px, 200px);" data-name="$projName" data-path="$projPath" data-sessions="$projSessions" data-tokens="$totalTokens" data-cost="$projCost" data-duration="$totalMinutes" data-lastused="$projLastUsedSort" data-config="$cfgCount" onclick="document.getElementById('proj-details-$projectIndex').classList.toggle('open')">
                    <span class="project-name">$projName</span>
                    <span class="project-path" title="$projPath">$projPath</span>
                    <span class="project-sessions">$projSessions</span>
                    <span class="project-tokens" title="Input: $($proj.InputTokens) / Output: $($proj.OutputTokens)">$tokensDisplay</span>
                    <span class="project-tokens">$costDisplay</span>
                    <span class="project-duration">$durationDisplay</span>
                    <span class="project-last">$projLastUsed</span>
                    <span class="project-config">$cfgBadges</span>
                </div>
                <div id="proj-details-$projectIndex" class="project-details">
                    <h4>Local Configuration</h4>
                    <div class="config-status">
                        <div class="config-item"><span class="label">Settings</span><span class="status $(if(-not $ls.HasSettings){'no'})">$(if($ls.HasSettings){'[OK]'}else{'[--]'})</span></div>
                        <div class="config-item"><span class="label">Settings Local</span><span class="status $(if(-not $ls.HasSettingsLocal){'no'})">$(if($ls.HasSettingsLocal){'[OK]'}else{'[--]'})</span></div>
                        <div class="config-item"><span class="label">Memory (CLAUDE.md)</span><span class="status $(if(-not $ls.HasMemory){'no'})">$(if($ls.HasMemory){'[OK]'}else{'[--]'})</span></div>
                        <div class="config-item"><span class="label">MCP Servers</span><span class="status $(if(-not $ls.HasMcp){'no'})">$(if($ls.HasMcp){'[OK]'}else{'[--]'})</span></div>
                        <div class="config-item"><span class="label">Agents</span><span class="status $(if(-not $ls.HasAgents){'no'})">$(if($ls.HasAgents){'[OK]'}else{'[--]'})</span></div>
                        <div class="config-item"><span class="label">Commands</span><span class="status $(if(-not $ls.HasCommands){'no'})">$(if($ls.HasCommands){'[OK]'}else{'[--]'})</span></div>
                        <div class="config-item"><span class="label">Hooks</span><span class="status $(if(-not $ls.HasHooks){'no'})">$(if($ls.HasHooks){'[OK]'}else{'[--]'})</span></div>
                    </div>
"@
            # Add content previews if available
            if ($ls.HasMemory -and $ls.MemoryContent) {
                $memPreview = ConvertTo-HtmlEncoded ($ls.MemoryContent.Substring(0, [Math]::Min(500, $ls.MemoryContent.Length)))
                if ($ls.MemoryContent.Length -gt 500) { $memPreview += "..." }
                $html += @"
                    <h4>CLAUDE.md Preview</h4>
                    <div class="output-block open">
                        <div class="output-block-content"><pre>$memPreview</pre></div>
                    </div>
"@
            }
            if ($ls.HasMcp -and $ls.McpContent) {
                $mcpJson = ConvertTo-HtmlEncoded ($ls.McpContent | ConvertTo-Json -Depth 5)
                $html += @"
                    <h4>MCP Configuration</h4>
                    <div class="output-block open">
                        <div class="output-block-content"><pre>$mcpJson</pre></div>
                    </div>
"@
            }
            if ($ls.AgentsList.Count -gt 0) {
                $agentList = ($ls.AgentsList | ForEach-Object { ConvertTo-HtmlEncoded $_ }) -join ", "
                $html += @"
                    <h4>Agents ($($ls.AgentsList.Count))</h4>
                    <div style="color: #888; padding: 8px 0;">$agentList</div>
"@
            }
            if ($ls.CommandsList.Count -gt 0) {
                $cmdList = ($ls.CommandsList | ForEach-Object { ConvertTo-HtmlEncoded $_ }) -join ", "
                $html += @"
                    <h4>Commands ($($ls.CommandsList.Count))</h4>
                    <div style="color: #888; padding: 8px 0;">$cmdList</div>
"@
            }

            $html += "                </div>`n"
            $projectIndex++
        }
        $html += "                </div>`n"  # Close project-list div
    } else {
        $html += @"
                </div>
                <div class="empty-state">
                    <div>No projects found</div>
                    <div class="prompt">Start using Claude Code in your projects to see them here</div>
                </div>
"@
    }

    $html += @"
            </div>

            <!-- Settings Section -->
            <div id="settings" class="section">
                <h2 class="section-title">Settings <span class="count">($settingsCount configured)</span></h2>
                <div class="section-description">
                    Configure Claude Code behavior via JSON files. <strong>Global</strong> settings apply to all projects, <strong>Project</strong> settings override for specific projects. Files ending in <code>.local.json</code> are machine-specific and git-ignored.
                    <br><a href="https://docs.anthropic.com/en/docs/claude-code/settings" target="_blank">View Settings Documentation &rarr;</a>
                </div>
                <div class="output-line">
                    <span class="key">Global</span>
                    <span class="value $(if($settings.Global.Exists){'ok'}else{'missing'})">$(if($settings.Global.Exists){'[OK] ' + $settings.Global.Path}else{'[--] Not configured'})</span>
                </div>
                <div class="output-line">
                    <span class="key">User Local</span>
                    <span class="value $(if($settings.GlobalLocal.Exists){'ok'}else{'missing'})">$(if($settings.GlobalLocal.Exists){'[OK] ' + $settings.GlobalLocal.Path}else{'[--] Not configured'})</span>
                </div>
                <div class="output-line">
                    <span class="key">Project</span>
                    <span class="value $(if($settings.Project.Exists){'ok'}else{'missing'})">$(if($settings.Project.Exists){'[OK] ' + $settings.Project.Path}else{'[--] Not configured'})</span>
                </div>
                <div class="output-line">
                    <span class="key">Project Local</span>
                    <span class="value $(if($settings.ProjectLocal.Exists){'ok'}else{'missing'})">$(if($settings.ProjectLocal.Exists){'[OK] ' + $settings.ProjectLocal.Path}else{'[--] Not configured'})</span>
                </div>
"@

    # Add settings content blocks
    foreach ($type in @('Global', 'GlobalLocal', 'Project', 'ProjectLocal')) {
        if ($settings[$type].Exists -and $settings[$type].Content) {
            $jsonContent = ConvertTo-HtmlEncoded ($settings[$type].Content | ConvertTo-Json -Depth 10)
            $badgeClass = if ($type -like 'Global*') { 'badge-global' } else { 'badge-project' }
            $badgeText = if ($type -like 'Global*') { 'Global' } else { 'Project' }
            $html += @"
                <div class="output-block">
                    <div class="output-block-header" onclick="this.parentElement.classList.toggle('open')">
                        <span>[+] $type settings</span>
                        <span class="source $badgeClass">$badgeText</span>
                    </div>
                    <div class="output-block-content"><pre class="json-view">$jsonContent</pre></div>
                </div>
"@
        }
    }

    $html += @"
            </div>

            <!-- MCP Section -->
            <div id="mcp" class="section">
                <h2 class="section-title">MCP Servers <span class="count">($mcpCount configured)</span></h2>
                <div class="section-description">
                    Model Context Protocol (MCP) servers extend Claude's capabilities with external tools and data sources. Configure in <code>.mcp.json</code> (project-scoped, shared via git) or <code>settings.json</code> (user-scoped).
                    <br><a href="https://docs.anthropic.com/en/docs/claude-code/mcp" target="_blank">View MCP Documentation &rarr;</a>
                </div>
"@

    if ($mcp.Servers.Count -gt 0) {
        foreach ($server in $mcp.Servers) {
            $serverName = ConvertTo-HtmlEncoded $server.Name
            $serverSource = $server.Source
            # Determine badge class based on source
            $badgeClass = if ($serverSource -match 'Global|settings\.json') { 'badge-global' } else { 'badge-project' }
            $badgeText = if ($serverSource -match 'Global|settings\.json') { 'Global' } else { 'Project' }
            $html += @"
                <div class="item-row">
                    <span class="name">$serverName</span>
                    <span class="source $badgeClass">$badgeText</span>
                </div>
"@
        }
        if ($mcp.ProjectMcp.Exists) {
            $mcpContent = ConvertTo-HtmlEncoded ($mcp.ProjectMcp.Content | ConvertTo-Json -Depth 10)
            $html += @"
                <div class="output-block">
                    <div class="output-block-header" onclick="this.parentElement.classList.toggle('open')">
                        <span>[+] .mcp.json content</span>
                        <span class="source badge-project">Project</span>
                    </div>
                    <div class="output-block-content"><pre class="json-view">$mcpContent</pre></div>
                </div>
"@
        }
    } else {
        $html += @"
                <div class="empty-state">
                    <div>No MCP servers configured</div>
                    <div class="prompt">Run: claude mcp add --transport http &lt;name&gt; &lt;url&gt;</div>
                </div>
"@
    }

    $html += @"
            </div>

            <!-- Memory Section -->
            <div id="memory" class="section">
                <h2 class="section-title">Memory (CLAUDE.md) <span class="count">($memoryCount configured)</span></h2>
                <div class="section-description">
                    CLAUDE.md files provide persistent context and instructions. <strong>Global</strong> (~/.claude/) applies everywhere, <strong>Project</strong> files are shared with your team via git. Use <code>CLAUDE.local.md</code> for personal notes (git-ignored).
                    <br><a href="https://docs.anthropic.com/en/docs/claude-code/memory" target="_blank">View Memory Documentation &rarr;</a>
                </div>
                <div class="output-line">
                    <span class="key">Global</span>
                    <span class="value $(if($memory.Global.Exists){'ok'}else{'missing'})">$(if($memory.Global.Exists){'[OK] ' + $memory.Global.Path}else{'[--] Not configured'})</span>
                </div>
                <div class="output-line">
                    <span class="key">Project Root</span>
                    <span class="value $(if($memory.ProjectRoot.Exists){'ok'}else{'missing'})">$(if($memory.ProjectRoot.Exists){'[OK] ' + $memory.ProjectRoot.Path}else{'[--] Not configured'})</span>
                </div>
                <div class="output-line">
                    <span class="key">Project .claude/</span>
                    <span class="value $(if($memory.ProjectFolder.Exists){'ok'}else{'missing'})">$(if($memory.ProjectFolder.Exists){'[OK] ' + $memory.ProjectFolder.Path}else{'[--] Not configured'})</span>
                </div>
                <div class="output-line">
                    <span class="key">Project Local</span>
                    <span class="value $(if($memory.ProjectLocal.Exists){'ok'}else{'missing'})">$(if($memory.ProjectLocal.Exists){'[OK] ' + $memory.ProjectLocal.Path}else{'[--] Not configured'})</span>
                </div>
"@

    foreach ($type in @('Global', 'ProjectRoot', 'ProjectFolder', 'ProjectLocal')) {
        if ($memory[$type].Exists -and $memory[$type].Content) {
            $memContent = ConvertTo-HtmlEncoded $memory[$type].Content
            $html += @"
                <div class="output-block">
                    <div class="output-block-header" onclick="this.parentElement.classList.toggle('open')">
                        <span>$type CLAUDE.md content</span>
                        <span class="toggle"></span>
                    </div>
                    <div class="output-block-content"><pre>$memContent</pre></div>
                </div>
"@
        }
    }

    $html += @"
            </div>

            <!-- Agents Section -->
            <div id="agents" class="section">
                <h2 class="section-title">Custom Agents <span class="count">($agentsCount configured)</span></h2>
                <div class="section-description">
                    Subagents are specialized AI assistants for specific tasks. <strong>Global</strong> agents (~/.claude/agents/) work across all projects, <strong>Project</strong> agents (.claude/agents/) are team-shared. Define with markdown files containing YAML frontmatter.
                    <br><a href="https://docs.anthropic.com/en/docs/claude-code/sub-agents" target="_blank">View Subagents Documentation &rarr;</a>
                </div>
"@

    if ($agentsCount -gt 0) {
        foreach ($agent in $agents.Global.Files) {
            $agentName = ConvertTo-HtmlEncoded $agent.Name
            $html += @"
                <div class="item-row">
                    <span class="name">$agentName</span>
                    <span class="source badge-global">Global</span>
                </div>
"@
        }
        foreach ($agent in $agents.Project.Files) {
            $agentName = ConvertTo-HtmlEncoded $agent.Name
            $html += @"
                <div class="item-row">
                    <span class="name">$agentName</span>
                    <span class="source badge-project">Project</span>
                </div>
"@
        }
    } else {
        $html += @"
                <div class="empty-state">
                    <div>No custom agents configured</div>
                    <div class="prompt">Create .md files in ~/.claude/agents/ or .claude/agents/</div>
                </div>
"@
    }

    $html += @"
            </div>

            <!-- Commands Section -->
            <div id="commands" class="section">
                <h2 class="section-title">Custom Commands <span class="count">($commandsCount configured)</span></h2>
                <div class="section-description">
                    Slash commands are reusable prompts invoked with <code>/command-name</code>. <strong>Global</strong> commands (~/.claude/commands/) work everywhere, <strong>Project</strong> commands (.claude/commands/) are team-shared via git.
                    <br><a href="https://docs.anthropic.com/en/docs/claude-code/slash-commands" target="_blank">View Slash Commands Documentation &rarr;</a>
                </div>
"@

    if ($commandsCount -gt 0) {
        foreach ($cmd in $commands.Global.Files) {
            $cmdName = ConvertTo-HtmlEncoded $cmd.Name
            $html += @"
                <div class="item-row">
                    <span class="name">$cmdName</span>
                    <span class="source badge-global">Global</span>
                </div>
"@
        }
        foreach ($cmd in $commands.Project.Files) {
            $cmdName = ConvertTo-HtmlEncoded $cmd.Name
            $html += @"
                <div class="item-row">
                    <span class="name">$cmdName</span>
                    <span class="source badge-project">Project</span>
                </div>
"@
        }
    } else {
        $html += @"
                <div class="empty-state">
                    <div>No custom commands configured</div>
                    <div class="prompt">Create .md files in ~/.claude/commands/ or .claude/commands/</div>
                </div>
"@
    }

    $html += @"
            </div>

            <!-- Skills Section -->
            <div id="skills" class="section">
                <h2 class="section-title">Agent Skills <span class="count">($skillsCount configured)</span></h2>
                <div class="section-description">
                    Skills package expertise that Claude autonomously activates when relevant (unlike commands that require explicit invocation). <strong>Global</strong> skills (~/.claude/skills/) work everywhere, <strong>Project</strong> skills (.claude/skills/) are team-shared.
                    <br><a href="https://docs.anthropic.com/en/docs/claude-code/skills" target="_blank">View Skills Documentation &rarr;</a>
                </div>
"@

    if ($skillsCount -gt 0) {
        foreach ($skill in $skills.Global.Items) {
            $skillName = ConvertTo-HtmlEncoded $skill.Name
            $skillDesc = if ($skill.Description) { ConvertTo-HtmlEncoded $skill.Description } else { "<em>No description</em>" }
            $skillTools = if ($skill.AllowedTools.Count -gt 0) { ($skill.AllowedTools -join ", ") } else { "All tools" }
            $html += @"
                <div class="output-block">
                    <div class="output-block-header" onclick="this.parentElement.classList.toggle('open')">
                        <span>[+] $skillName</span>
                        <span class="source badge-global">Global</span>
                    </div>
                    <div class="output-block-content">
                        <div class="output-line"><span class="key">Description</span><span class="value">$skillDesc</span></div>
                        <div class="output-line"><span class="key">Allowed Tools</span><span class="value">$skillTools</span></div>
                        <div class="output-line"><span class="key">Path</span><span class="value">$(ConvertTo-HtmlEncoded $skill.Path)</span></div>
                    </div>
                </div>
"@
        }
        foreach ($skill in $skills.Project.Items) {
            $skillName = ConvertTo-HtmlEncoded $skill.Name
            $skillDesc = if ($skill.Description) { ConvertTo-HtmlEncoded $skill.Description } else { "<em>No description</em>" }
            $skillTools = if ($skill.AllowedTools.Count -gt 0) { ($skill.AllowedTools -join ", ") } else { "All tools" }
            $html += @"
                <div class="output-block">
                    <div class="output-block-header" onclick="this.parentElement.classList.toggle('open')">
                        <span>[+] $skillName</span>
                        <span class="source badge-project">Project</span>
                    </div>
                    <div class="output-block-content">
                        <div class="output-line"><span class="key">Description</span><span class="value">$skillDesc</span></div>
                        <div class="output-line"><span class="key">Allowed Tools</span><span class="value">$skillTools</span></div>
                        <div class="output-line"><span class="key">Path</span><span class="value">$(ConvertTo-HtmlEncoded $skill.Path)</span></div>
                    </div>
                </div>
"@
        }
    } else {
        $html += @"
                <div class="empty-state">
                    <div>No skills configured</div>
                    <div class="prompt">Create folders with SKILL.md in ~/.claude/skills/ or .claude/skills/</div>
                </div>
"@
    }

    $html += @"
            </div>

            <!-- Plugins Section -->
            <div id="plugins" class="section">
                <h2 class="section-title">Plugins <span class="count">($pluginsCount configured)</span></h2>
                <div class="section-description">
                    Plugins bundle commands, agents, skills, and hooks into shareable packages. Install from marketplaces or create custom plugins. Configure in <code>settings.json</code> with enabled/disabled lists.
                    <br><a href="https://docs.anthropic.com/en/docs/claude-code/plugins" target="_blank">View Plugins Documentation &rarr;</a>
                </div>
"@

    if ($plugins.Configured.Count -gt 0) {
        $html += @"
                <h3 class="subsection-title">Configured Plugins</h3>
"@
        foreach ($plugin in $plugins.Configured) {
            $pluginName = ConvertTo-HtmlEncoded $plugin.Name
            $pluginStatus = $plugin.Status
            $statusClass = if ($plugin.Status -eq "Enabled") { "ok" } else { "warn" }
            $badgeClass = if ($plugin.Source -match 'Global') { 'badge-global' } else { 'badge-project' }
            $badgeText = if ($plugin.Source -match 'Global') { 'Global' } else { 'Project' }
            $html += @"
                <div class="item-row">
                    <span class="name">$pluginName</span>
                    <span class="status $statusClass">$pluginStatus</span>
                    <span class="source $badgeClass">$badgeText</span>
                </div>
"@
        }
    }

    if ($plugins.Marketplaces.Count -gt 0) {
        $html += @"
                <h3 class="subsection-title">Plugin Marketplaces</h3>
"@
        foreach ($market in $plugins.Marketplaces) {
            $marketName = ConvertTo-HtmlEncoded $market.Name
            $badgeClass = if ($market.Source -match 'Global') { 'badge-global' } else { 'badge-project' }
            $badgeText = if ($market.Source -match 'Global') { 'Global' } else { 'Project' }
            $html += @"
                <div class="item-row">
                    <span class="name">$marketName</span>
                    <span class="source $badgeClass">$badgeText</span>
                </div>
"@
        }
    }

    if ($pluginsCount -eq 0) {
        $html += @"
                <div class="empty-state">
                    <div>No plugins configured</div>
                    <div class="prompt">Configure plugins in settings.json with the plugins key</div>
                </div>
"@
    }

    $html += @"
            </div>

            <!-- Hooks Section -->
            <div id="hooks" class="section">
                <h2 class="section-title">Hooks <span class="count">($hooksCount configured)</span></h2>
                <div class="section-description">
                    Hooks execute shell commands at lifecycle events (before/after tool calls, notifications, etc.). Define in <code>settings.json</code> under the <code>hooks</code> key. Useful for logging, validation, or custom integrations.
                    <br><a href="https://docs.anthropic.com/en/docs/claude-code/hooks" target="_blank">View Hooks Documentation &rarr;</a>
                </div>
"@

    if ($hooksCount -gt 0) {
        foreach ($hookSet in $hooks.FromSettings) {
            $hookSource = $hookSet.Source
            $badgeClass = if ($hookSource -match 'Global') { 'badge-global' } else { 'badge-project' }
            $badgeText = if ($hookSource -match 'Global') { 'Global' } else { 'Project' }
            $html += @"
                <div class="item-row">
                    <span class="name">Hooks defined in settings</span>
                    <span class="source $badgeClass">$badgeText</span>
                </div>
"@
        }
        foreach ($hookFile in $hooks.ProjectFolder.Files) {
            $hookName = ConvertTo-HtmlEncoded $hookFile.Name
            $html += @"
                <div class="item-row">
                    <span class="name">$hookName</span>
                    <span class="source badge-project">Project</span>
                </div>
"@
        }
    } else {
        $html += @"
                <div class="empty-state">
                    <div>No hooks configured</div>
                    <div class="prompt">Add hooks in settings.json or .claude/hooks/</div>
                </div>
"@
    }

    $html += @"
            </div>

            <!-- Permissions Section -->
            <div id="permissions" class="section">
                <h2 class="section-title">Tool Permissions <span class="count">($permissionsCount rules)</span></h2>
                <div class="section-description">
                    Control which tools Claude can use. <strong>Allow</strong> permits without asking, <strong>Deny</strong> blocks completely, <strong>Ask</strong> prompts for confirmation. Rules cascade from Global &rarr; Project, with later rules overriding.
                    <br><a href="https://docs.anthropic.com/en/docs/claude-code/settings#tool-permissions" target="_blank">View Permissions Documentation &rarr;</a>
                </div>
                <div class="perm-grid">
                    <div class="perm-col allow">
                        <h4>[ALLOW] ($($permissions.Allow.Count))</h4>
                        <ul>
"@

    if ($permissions.Allow.Count -gt 0) {
        foreach ($perm in $permissions.Allow) {
            $rule = ConvertTo-HtmlEncoded $perm.Rule
            $source = ConvertTo-HtmlEncoded $perm.Source
            $html += "                            <li>$rule<span class='src'>($source)</span></li>`n"
        }
    } else {
        $html += '                            <li class="empty">None</li>'
    }

    $html += @"
                        </ul>
                    </div>
                    <div class="perm-col deny">
                        <h4>[DENY] ($($permissions.Deny.Count))</h4>
                        <ul>
"@

    if ($permissions.Deny.Count -gt 0) {
        foreach ($perm in $permissions.Deny) {
            $rule = ConvertTo-HtmlEncoded $perm.Rule
            $source = ConvertTo-HtmlEncoded $perm.Source
            $html += "                            <li>$rule<span class='src'>($source)</span></li>`n"
        }
    } else {
        $html += '                            <li class="empty">None</li>'
    }

    $html += @"
                        </ul>
                    </div>
                    <div class="perm-col ask">
                        <h4>[ASK] ($($permissions.Ask.Count))</h4>
                        <ul>
"@

    if ($permissions.Ask.Count -gt 0) {
        foreach ($perm in $permissions.Ask) {
            $rule = ConvertTo-HtmlEncoded $perm.Rule
            $source = ConvertTo-HtmlEncoded $perm.Source
            $html += "                            <li>$rule<span class='src'>($source)</span></li>`n"
        }
    } else {
        $html += '                            <li class="empty">None</li>'
    }

    $html += @"
                        </ul>
                    </div>
                </div>
            </div>

            <!-- Enterprise Section -->
            <div id="enterprise" class="section">
                <h2 class="section-title">Enterprise Settings <span class="count">($managedCount/3 configured)</span></h2>
                <div class="section-description">
                    Organization-wide policies managed by IT administrators. Located in <code>C:\ProgramData\ClaudeCode\</code> (Windows). These settings have highest priority and cannot be overridden by users.
                    <br><a href="https://docs.anthropic.com/en/docs/claude-code/settings#enterprise-settings" target="_blank">View Enterprise Documentation &rarr;</a>
                </div>
"@

    if ($managed.Exists) {
        $html += @"
                <div class="output-line">
                    <span class="key">Enterprise Path</span>
                    <span class="value ok">$(ConvertTo-HtmlEncoded $managed.Path)</span>
                </div>
"@

        if ($managed.Settings.Exists) {
            $settingsJson = if ($managed.Settings.Content) {
                $managed.Settings.Content | ConvertTo-Json -Depth 10
            } else { "{}" }
            $html += @"
                <div class="output-block">
                    <div class="output-block-header" onclick="this.parentElement.classList.toggle('open')">
                        <span>[+] managed-settings.json</span>
                        <span class="source badge-enterprise">Enterprise</span>
                    </div>
                    <div class="output-block-content">
                        <pre class="json-view">$(ConvertTo-HtmlEncoded $settingsJson)</pre>
                    </div>
                </div>
"@
        } else {
            $html += @"
                <div class="output-line">
                    <span class="key">managed-settings.json</span>
                    <span class="value missing">[--] Not configured</span>
                </div>
"@
        }

        if ($managed.Mcp.Exists) {
            $mcpJson = if ($managed.Mcp.Content) {
                $managed.Mcp.Content | ConvertTo-Json -Depth 10
            } else { "{}" }
            $html += @"
                <div class="output-block">
                    <div class="output-block-header" onclick="this.parentElement.classList.toggle('open')">
                        <span>[+] managed-mcp.json</span>
                        <span class="source badge-enterprise">Enterprise</span>
                    </div>
                    <div class="output-block-content">
                        <pre class="json-view">$(ConvertTo-HtmlEncoded $mcpJson)</pre>
                    </div>
                </div>
"@
        } else {
            $html += @"
                <div class="output-line">
                    <span class="key">managed-mcp.json</span>
                    <span class="value missing">[--] Not configured</span>
                </div>
"@
        }

        if ($managed.Memory.Exists) {
            $memoryContent = if ($managed.Memory.Content) { $managed.Memory.Content } else { "" }
            $html += @"
                <div class="output-block">
                    <div class="output-block-header" onclick="this.parentElement.classList.toggle('open')">
                        <span>[+] CLAUDE.md</span>
                        <span class="source badge-enterprise">Enterprise</span>
                    </div>
                    <div class="output-block-content">
                        <pre>$(ConvertTo-HtmlEncoded $memoryContent)</pre>
                    </div>
                </div>
"@
        } else {
            $html += @"
                <div class="output-line">
                    <span class="key">CLAUDE.md</span>
                    <span class="value missing">[--] Not configured</span>
                </div>
"@
        }
    } else {
        $html += @"
                <div class="empty-state">
                    <div>No enterprise settings detected</div>
                    <div class="prompt">Enterprise settings are stored in C:\ProgramData\ClaudeCode\</div>
                </div>
"@
    }

    $html += @"
            </div>

            <!-- Tool Usage Section -->
            <div id="tools" class="section">
                <h2 class="section-title">Tool Usage <span class="count">($toolsCount tools used)</span></h2>
"@

    if ($analytics.ToolUsage.Keys.Count -gt 0) {
        # Sort tools by usage count
        $sortedTools = $analytics.ToolUsage.GetEnumerator() | Sort-Object Value -Descending
        $maxToolCount = ($sortedTools | Select-Object -First 1).Value
        if ($maxToolCount -eq 0) { $maxToolCount = 1 }

        $html += @"
                <div class="chart-container">
                    <div class="chart-title">Tool Call Distribution</div>
                    <div class="bar-chart">
"@
        foreach ($tool in $sortedTools) {
            $toolName = ConvertTo-HtmlEncoded $tool.Key
            $toolCount = $tool.Value
            $widthPct = [Math]::Round(($toolCount / $maxToolCount) * 100)
            $html += @"
                        <div class="bar-row">
                            <span class="bar-label">$toolName</span>
                            <div class="bar-track"><div class="bar-fill" style="width: ${widthPct}%"></div></div>
                            <span class="bar-value">$toolCount</span>
                        </div>
"@
        }
        $html += @"
                    </div>
                </div>
                <div class="tool-grid">
"@
        foreach ($tool in $sortedTools) {
            $toolName = ConvertTo-HtmlEncoded $tool.Key
            $html += @"
                    <div class="tool-item">
                        <span class="tool-name">$toolName</span>
                        <span class="tool-count">$($tool.Value)</span>
                    </div>
"@
        }
        $html += "                </div>`n"
    } else {
        $html += @"
                <div class="empty-state">
                    <div>No tool usage data available</div>
                    <div class="prompt">Tool usage is tracked from session data</div>
                </div>
"@
    }

    $html += @"
            </div>

            <!-- Models Section -->
            <div id="models" class="section">
                <h2 class="section-title">Model Usage <span class="count">($modelsCount models)</span></h2>
"@

    if ($analytics.ModelUsage.Keys.Count -gt 0) {
        # Sort by total tokens (input + output)
        $sortedModels = $analytics.ModelUsage.GetEnumerator() |
            ForEach-Object { @{ Key = $_.Key; Value = $_.Value; TotalTokens = $_.Value.InputTokens + $_.Value.OutputTokens } } |
            Sort-Object { $_.TotalTokens } -Descending
        $maxModelTokens = ($sortedModels | Select-Object -First 1).TotalTokens
        if ($maxModelTokens -eq 0) { $maxModelTokens = 1 }

        $html += @"
                <div class="chart-container">
                    <div class="chart-title">Model Token Distribution</div>
                    <div class="bar-chart">
"@
        foreach ($model in $sortedModels) {
            $modelName = ConvertTo-HtmlEncoded $model.Key
            $totalTokens = $model.TotalTokens
            $inputTokens = $model.Value.InputTokens
            $outputTokens = $model.Value.OutputTokens
            $widthPct = [Math]::Round(($totalTokens / $maxModelTokens) * 100)
            $barClass = if ($modelName -match "opus") { "yellow" } elseif ($modelName -match "haiku") { "green" } else { "" }

            # Format token display
            $totalDisplay = if ($totalTokens -ge 1000000) { "{0:N1}M" -f ($totalTokens / 1000000) } elseif ($totalTokens -ge 1000) { "{0:N0}K" -f ($totalTokens / 1000) } else { "$totalTokens" }

            $html += @"
                        <div class="bar-row">
                            <span class="bar-label">$modelName</span>
                            <div class="bar-track"><div class="bar-fill $barClass" style="width: ${widthPct}%"></div></div>
                            <span class="bar-value">$totalDisplay</span>
                        </div>
"@
        }
        $html += @"
                    </div>
                </div>
                <div class="model-tokens-grid">
"@
        foreach ($model in $sortedModels) {
            $modelName = ConvertTo-HtmlEncoded $model.Key
            $inputTokens = $model.Value.InputTokens
            $outputTokens = $model.Value.OutputTokens
            $calls = $model.Value.Calls
            $inputDisplay = if ($inputTokens -ge 1000000) { "{0:N1}M" -f ($inputTokens / 1000000) } elseif ($inputTokens -ge 1000) { "{0:N0}K" -f ($inputTokens / 1000) } else { "$inputTokens" }
            $outputDisplay = if ($outputTokens -ge 1000000) { "{0:N1}M" -f ($outputTokens / 1000000) } elseif ($outputTokens -ge 1000) { "{0:N0}K" -f ($outputTokens / 1000) } else { "$outputTokens" }

            $html += @"
                    <div class="model-token-item">
                        <span class="model-name" title="$modelName">$modelName</span>
                        <span class="token-in">In: $inputDisplay</span>
                        <span class="token-out">Out: $outputDisplay</span>
                        <span class="token-calls">$calls calls</span>
                    </div>
"@
        }
        $html += "                </div>`n"
    } else {
        $html += @"
                <div class="empty-state">
                    <div>No model usage data available</div>
                    <div class="prompt">Model information is extracted from session data</div>
                </div>
"@
    }

    $html += @"
            </div>

            <!-- Errors Section -->
            <div id="errors" class="section">
                <h2 class="section-title">Errors <span class="count">($errorsCount found)</span></h2>
"@

    if ($analytics.Errors.Count -gt 0) {
        # Show most recent 50 errors
        $recentErrors = $analytics.Errors | Select-Object -Last 50
        foreach ($err in $recentErrors) {
            $errorMsg = ConvertTo-HtmlEncoded $err.Message
            $errorFile = ConvertTo-HtmlEncoded $err.File
            $errorTime = if ($err.Timestamp) { $err.Timestamp.ToString("yyyy-MM-dd HH:mm") } else { "Unknown time" }
            $html += @"
                <div class="error-item">
                    <div class="error-msg">$errorMsg</div>
                    <div class="error-meta">$errorFile - $errorTime</div>
                </div>
"@
        }
        if ($analytics.Errors.Count -gt 50) {
            $html += @"
                <div style="color: #666; padding: 15px; text-align: center;">
                    Showing 50 of $($analytics.Errors.Count) errors
                </div>
"@
        }
    } else {
        $html += @"
                <div class="empty-state">
                    <div>No errors found</div>
                    <div class="prompt">Great! Your sessions are running without errors.</div>
                </div>
"@
    }

    $html += @"
            </div>

            <!-- Maintenance Section -->
            <div id="maintenance" class="section">
                <h2 class="section-title">Cleanup &amp; Maintenance <span class="count">($maintenanceCount items)</span></h2>
"@

    # Orphan Projects
    if ($analytics.OrphanProjects.Count -gt 0) {
        $html += @"
                <div class="subsection">
                    <h3 class="subsection-title">Orphan Projects ($($analytics.OrphanProjects.Count))</h3>
                    <p style="color: #888; font-size: 12px; margin-bottom: 15px;">Projects whose original paths no longer exist on disk</p>
"@
        foreach ($orphan in $analytics.OrphanProjects) {
            $orphanPath = ConvertTo-HtmlEncoded $orphan.OriginalPath
            $orphanFolder = ConvertTo-HtmlEncoded $orphan.EncodedName
            $orphanSize = Format-FileSize $orphan.DiskUsage
            $html += @"
                    <div class="maint-item orphan">
                        <div class="maint-info">
                            <div class="maint-name">$orphanPath</div>
                            <div class="maint-detail">Folder: $orphanFolder | $($orphan.SessionCount) sessions</div>
                        </div>
                        <div class="maint-size">$orphanSize</div>
                    </div>
"@
        }
        $html += "                </div>`n"
    }

    # Stale Projects
    if ($analytics.StaleProjects.Count -gt 0) {
        $html += @"
                <div class="subsection">
                    <h3 class="subsection-title">Stale Projects ($($analytics.StaleProjects.Count))</h3>
                    <p style="color: #888; font-size: 12px; margin-bottom: 15px;">Projects not used in 30+ days</p>
"@
        foreach ($stale in $analytics.StaleProjects) {
            $staleName = ConvertTo-HtmlEncoded $stale.Name
            $stalePath = ConvertTo-HtmlEncoded $stale.Path
            $staleTokens = if ($stale.TokensUsed -ge 1000) { "{0:N0}K" -f ($stale.TokensUsed/1000) } else { $stale.TokensUsed }
            $html += @"
                    <div class="maint-item stale">
                        <div class="maint-info">
                            <div class="maint-name">$staleName</div>
                            <div class="maint-detail">$stalePath | $staleTokens tokens used</div>
                        </div>
                        <div class="maint-size">$($stale.DaysSinceActivity) days ago</div>
                    </div>
"@
        }
        $html += "                </div>`n"
    }

    # Corrupted Files
    if ($analytics.CorruptedFiles.Count -gt 0) {
        $html += @"
                <div class="subsection">
                    <h3 class="subsection-title">Corrupted Files ($($analytics.CorruptedFiles.Count))</h3>
                    <p style="color: #888; font-size: 12px; margin-bottom: 15px;">Session files that could not be parsed properly</p>
"@
        foreach ($corrupt in $analytics.CorruptedFiles) {
            $corruptName = ConvertTo-HtmlEncoded $corrupt.Name
            $corruptSize = Format-FileSize $corrupt.Size
            $html += @"
                    <div class="maint-item corrupted">
                        <div class="maint-info">
                            <div class="maint-name">$corruptName</div>
                            <div class="maint-detail">$($corrupt.Path)</div>
                        </div>
                        <div class="maint-size">$corruptSize</div>
                    </div>
"@
        }
        $html += "                </div>`n"
    }

    if ($maintenanceCount -eq 0) {
        $html += @"
                <div class="empty-state">
                    <div>No cleanup needed</div>
                    <div class="prompt">All projects are healthy and accessible.</div>
                </div>
"@
    }

    $html += @"
            </div>

            <!-- Conflicts Section -->
            <div id="conflicts" class="section">
                <h2 class="section-title">Permission Conflicts <span class="count">($conflictsCount found)</span></h2>
"@

    if ($permConflicts.Count -gt 0) {
        $html += @"
                <p style="color: #888; font-size: 12px; margin-bottom: 15px;">Conflicting permission rules between different settings levels</p>
"@
        foreach ($conflict in $permConflicts) {
            $conflictRule = ConvertTo-HtmlEncoded $conflict.Rule
            $conflictResolution = ConvertTo-HtmlEncoded $conflict.Resolution
            $html += @"
                <div class="conflict-item">
                    <div class="conflict-rule">$conflictRule</div>
                    <div class="conflict-levels">$($conflict.Level1) [$($conflict.Category1)] vs $($conflict.Level2) [$($conflict.Category2)]</div>
                    <div class="conflict-resolution">Resolution: $conflictResolution</div>
                </div>
"@
        }
    } else {
        $html += @"
                <div class="empty-state">
                    <div>No conflicts detected</div>
                    <div class="prompt">Your permission rules are consistent across all settings levels.</div>
                </div>
"@
    }

    $html += @"
            </div>

            <!-- Recommendations Section -->
            <div id="recommendations" class="section">
                <h2 class="section-title">Recommendations <span class="count">($recommendationsCount items)</span></h2>
"@

    if ($recommendations.Count -gt 0) {
        foreach ($rec in $recommendations) {
            $recPriority = $rec.Priority.ToLower()
            $recMessage = ConvertTo-HtmlEncoded $rec.Message
            $recCommand = ConvertTo-HtmlEncoded $rec.Command
            $html += @"
                <div class="rec-item $recPriority">
                    <div class="rec-header">
                        <span class="rec-priority">$($rec.Priority.ToUpper())</span>
                        <span class="rec-type">$($rec.Type)</span>
                    </div>
                    <div class="rec-msg">$recMessage</div>
                    <div class="rec-cmd">$recCommand</div>
                </div>
"@
        }
    } else {
        $html += @"
                <div class="empty-state">
                    <div>All configurations are set up!</div>
                    <div class="prompt">No recommendations at this time.</div>
                </div>
"@
    }

    $html += @"
            </div>
        </div>
    </main>

    <script>
        // JSON Syntax Highlighter
        function highlightJson(json) {
            if (typeof json !== 'string') json = JSON.stringify(json, null, 2);
            json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            return json.replace(
                /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?|[\[\]{}]|,|:)/g,
                function(match) {
                    let cls = 'json-number';
                    if (/^"/.test(match)) {
                        if (/:$/.test(match)) {
                            cls = 'json-key';
                            match = match.slice(0, -1) + '<span class="json-colon">:</span>';
                        } else {
                            cls = 'json-string';
                        }
                    } else if (/true|false/.test(match)) {
                        cls = 'json-boolean';
                    } else if (/null/.test(match)) {
                        cls = 'json-null';
                    } else if (/[\[\]{}]/.test(match)) {
                        cls = 'json-bracket';
                    } else if (match === ',') {
                        cls = 'json-comma';
                    }
                    return '<span class="' + cls + '">' + match + '</span>';
                }
            );
        }

        // Apply syntax highlighting to all json-view elements
        document.querySelectorAll('.json-view').forEach(el => {
            el.innerHTML = highlightJson(el.textContent);
        });

        // Menu navigation
        document.querySelectorAll('.menu-item').forEach(item => {
            item.addEventListener('click', function() {
                document.querySelectorAll('.menu-item').forEach(i => i.classList.remove('active'));
                document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
                this.classList.add('active');
                document.getElementById(this.dataset.section).classList.add('active');
            });
        });

        // Project table sorting
        (function() {
            const header = document.getElementById('project-header');
            const list = document.getElementById('project-list');
            if (!header || !list) return;

            let currentSort = 'lastused';
            let currentDir = 'desc';

            header.querySelectorAll('span[data-sort]').forEach(col => {
                col.addEventListener('click', function(e) {
                    e.stopPropagation();
                    const sortKey = this.dataset.sort;

                    // Toggle direction if same column
                    if (sortKey === currentSort) {
                        currentDir = currentDir === 'asc' ? 'desc' : 'asc';
                    } else {
                        currentSort = sortKey;
                        currentDir = 'desc';
                    }

                    // Update header styles
                    header.querySelectorAll('span').forEach(s => s.classList.remove('sorted', 'asc'));
                    this.classList.add('sorted');
                    if (currentDir === 'asc') this.classList.add('asc');

                    // Get rows with their details
                    const rows = Array.from(list.querySelectorAll('.project-row'));
                    const rowPairs = rows.map(row => {
                        const detailsId = row.getAttribute('onclick').match(/proj-details-(\d+)/);
                        const details = detailsId ? document.getElementById('proj-details-' + detailsId[1]) : null;
                        return { row, details };
                    });

                    // Sort rows
                    rowPairs.sort((a, b) => {
                        let aVal = a.row.dataset[sortKey] || '';
                        let bVal = b.row.dataset[sortKey] || '';

                        // Numeric sort for these columns
                        if (['sessions', 'tokens', 'cost', 'duration', 'config'].includes(sortKey)) {
                            aVal = parseFloat(aVal) || 0;
                            bVal = parseFloat(bVal) || 0;
                        } else {
                            aVal = aVal.toLowerCase();
                            bVal = bVal.toLowerCase();
                        }

                        let result = 0;
                        if (aVal < bVal) result = -1;
                        if (aVal > bVal) result = 1;

                        return currentDir === 'asc' ? result : -result;
                    });

                    // Re-append in sorted order
                    rowPairs.forEach(pair => {
                        list.appendChild(pair.row);
                        if (pair.details) list.appendChild(pair.details);
                    });
                });
            });
        })();
    </script>
</body>
</html>
"@

    return $html
}

# Main execution
Write-Host "Claude Code Inspector" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Scanning configuration for: $projectName" -ForegroundColor Yellow
Write-Host "Project Path: $ProjectPath" -ForegroundColor Gray
Write-Host "Global Path: $globalPath" -ForegroundColor Gray
Write-Host ""

$html = New-HtmlReport
# Use .NET to write UTF-8 without BOM for proper browser rendering
[System.IO.File]::WriteAllText($reportPath, $html, [System.Text.UTF8Encoding]::new($false))

Write-Host "Report generated: $reportPath" -ForegroundColor Green

if (-not $NoOpen) {
    Write-Host "Opening in browser..." -ForegroundColor Gray
    Start-Process $reportPath
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Cyan
