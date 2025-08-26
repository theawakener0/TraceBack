# traceback.nvim

TraceBack is a fast, privacy-first time machine for your current buffer, capture lightweight, throttled snapshots as you edit (no git commits), browse a visual timeline, replay edits as an animation, and restore any point instantly. It was built to stop security and quality from being an afterthought in today’s rapid, AI-driven workflows by surfacing issues early with rich, contextual lenses.

Why use it?
- Instant safety net: recover from mistakes or experiments without touching your VCS.
- Security-first: the Security Lens highlights high‑entropy secrets, insecure patterns, and common CWE-class issues so you can fix problems before they escape the editor.
- Actionable insights: Code and Debug lenses reveal complexity hotspots, diagnostics, and quick fixes — plus contextual suggestions to refactor or harden code.
- Actionable insights: Code and LSP lenses reveal complexity hotspots, diagnostics, and quick fixes — plus contextual suggestions to refactor or harden code.
- Low friction: in-memory snapshots, Telescope timeline browser, configurable keymaps, and minimal performance overhead.

Install, open the timeline, and let TraceBack keep your edits safe, your code cleaner, and security visible while you code.

## Features

- ⚡ Configurable, throttled automatic snapshots on buffer changes (default throttle_ms = 5000)  
- 🔄 Per-buffer ring buffer of snapshots with instant restore (default max_snapshots = 1000)  
- 🔭 Timeline browser (Telescope) with live preview and snapshot counts  
- ▶️ Replay snapshots as animated diffs with adjustable delay (under testing & developmet)  
- 🧩 Language support: C, C++, Python, Lua, JavaScript, Go (Treesitter-aware)  
- 🔍 Lenses with rich visual indicators:
  - 💡 Code Lens — inline complexity and structure hints (color-coded)
  - 🧰 LSP Lens — inline diagnostics from your LSP with summary (E/W/I/H)
  - 🔒 Security Lens — flags common insecure patterns and high-entropy secrets
- 🌲 Treesitter integration when available for more accurate function detection and to ignore matches inside strings/comments  
- ⚙️ Lightweight, in-memory snapshots (no VCS commits), minimal performance overhead, and fully configurable behavior
- 🔧 Easy to customize defaults (snapshot size, throttle, lenses, keymaps, and Telescope integration)
- 🔁 Non-persistent by default — snapshots reset per session unless explicitly persisted by user tooling
- 🔒 Privacy-first design — snapshots remain local and scoped to the current buffer
- 🛠️ Designed for low friction workflows: quick capture, browse, replay, and restore without leaving the editor

## Visual Enhancements
- ✨ Professional Nerd Font icons throughout the interface
- 🎨 Color-coded complexity indicators (low/medium/high)
- 📌 Enhanced timeline with visual markers for latest snapshots
- 📝 Informative command descriptions with contextual help
- 💬 Rich notifications with icons and status updates

## Install
Use your plugin manager. Examples below show how to install with `lazy.nvim` and with `packer.nvim`.

lazy.nvim:

```lua
-- in your plugins spec (e.g. lua/plugins.lua)
{
  'theawakener0/TraceBack',
  dependencies = { 'nvim-lua/plenary.nvim', 'nvim-telescope/telescope.nvim' },
  config = function()
    require('traceback').setup({})
  end,
}
```

packer.nvim:

```lua
-- in your packer startup function (e.g. init.lua or lua/plugins.lua)
return require('packer').startup(function(use)
  use {
    'theawakener0/TraceBack',
    requires = { 'nvim-lua/plenary.nvim', 'nvim-telescope/telescope.nvim' },
    config = function()
      require('traceback').setup({})
    end,
  }
  -- other plugins...
end)
```

## Commands

All commands now include descriptive help text with visual icons:

- 📜 `:TracebackTimeline` – Open Telescope timeline browser with snapshot preview
- 📸 `:TracebackCapture` – Force capture current buffer state  
- ⏪ `:TracebackRestore {idx}` – Restore buffer to snapshot index (supports tab completion)
- ▶️ `:TracebackReplay {from} {to} {delay_ms}` – Replay snapshot sequence with animation
- 🔍 `:TracebackLenses` – Render all active lenses with annotation count
- 🧼 `:TracebackLensesClear` – Clear all lens annotations in the current buffer
- 🩺 `:TracebackLensesHealth` – Run a lenses health check and show diagnostics
- ⚙️ `:TracebackLensesToggle {code|lsp|security}` – Toggle specific lens types with status feedback
- 🔒 `:TracebackSecurityAllow {pattern}` – Add pattern to security allowlist
- ⚙️ `:TracebackSecuritySet {key} {value}` – Configure lens settings

## Usage & Keymaps

Default keymaps (can be overridden via setup):

### Core Features
- `<Leader>tt` — 🔭 Open timeline picker with enhanced UI
- `<Leader>tc` — 📸 Force capture with confirmation
- `<Leader>tr` — ⏪ Restore last snapshot (maps to `:TracebackRestore 1` by default)
- `<Leader>tp` — ▶️ Replay a short range of snapshots (maps to `:TracebackReplay 1 2 100` by default)  
- `<Leader>ts` — 🔒 Toggle the security lens with status notification

### Actions & Suggestions (NEW)
- `<Leader>ta` — 💡 Show actions for annotation at cursor (fix, explain, allowlist, etc.)
- `<Leader>tf` — 🔧 Apply quick fix for annotation at cursor
- `<Leader>te` — 📖 Explain annotation at cursor with detailed information
- `<Leader>tS` — 🧠 Show buffer-wide improvement suggestions (Telescope picker)
  

### Example Action Workflow
1. **Navigate to annotated code** - lenses highlight issues automatically
2. **Press `<Leader>ta`** - see available actions (fix, explain, allowlist)
3. **Choose an action** - apply fix, get explanation, or suppress false positive
4. **Use `<Leader>tS`** - get buffer-wide suggestions for improvements
5. Optionally review diagnostics inline from the LSP lens

You can keep using the commands above or rely on the default keymaps. All keymaps are non-recursive and silent by default.

## User Interface

The plugin provides rich visual feedback:

- **Timeline Browser**: 📜 Enhanced telescope picker with snapshot count and visual indicators
- **Status Messages**: 💬 Informative notifications show operation results and lens status
- **Code Annotations**: 💡 Function complexity with color-coded indicators (🟢🟡🔴)
- **LSP Diagnostics**: 🧰 Inline error/warn/info/hint messages with summary
- **Security Warnings**: 🔒 Security issues flagged with contextual messages

## Config
```lua
require('traceback').setup({
  snapshot = {
    max_snapshots = 1000,
    throttle_ms = 5000,
  },
  lenses = {
    code = true,
    lsp = true,
    security = true,
    auto_render = true,
    -- debounce and event tuning
    debounce_ms = 120,
    event_debounce = {
      DiagnosticChanged = 80,
      TextChanged = 300,
      WinScrolled = 120,
      CursorHold = 0,
      InsertLeave = 80,
      BufEnter = 100,
      LspAttach = 50,
    },
    max_annotations = 200, -- global cap on annotations per buffer
    scan_window = 400,     -- lines to scan around viewport for heavy work
    treesitter = true,     -- use Treesitter when available for better lenses
    -- lsp lens customization
    lsp_max_per_line = 1,
    lsp_truncate = 120,
    lsp_show_codes = true,
    lsp_show_source = false,
    -- code lens customization
    code_show_metrics = true, -- show params/LOC alongside complexity
    -- Enhanced security lens settings
    security_auto_render = true,
    security_context_analysis = true,
    security_smart_filtering = true,
  },
  -- Enhanced action system configuration
  actions = {
    auto_register_lens_providers = true,
    enable_smart_suggestions = true,
    enable_taint_analysis = true,
    enable_context_aware_fixes = true,
    enable_refactoring_suggestions = true,
    max_annotations_per_provider = 50,
    action_preview = true,
    timeout_ms = 1000,
    error_handling = true,
  },
  -- Advanced suggestion system configuration
  suggestions = {
    enable_complexity_analysis = true,
    enable_pattern_detection = true,
    enable_security_suggestions = true,
    enable_performance_hints = true,
    enable_comprehensive_scanning = true,
    suggestion_confidence_threshold = 0.7,
    max_suggestions_per_scan = 10,
    cache_enabled = true,
    cache_ttl_ms = 30000,
    timeout_ms = 1000,
    debug = false,
  },
  -- sensible default keymaps; users can override in setup()
  keymaps = {
    timeline = '<Leader>tt',    -- open timeline picker
    capture = '<Leader>tc',     -- force capture
    restore = '<Leader>tr',     -- restore last snapshot (or use :TracebackRestore {idx})
    replay = '<Leader>tp',      -- replay snapshots
    toggle_security = '<Leader>ts', -- toggle security lens
    -- Enhanced action keymaps
    actions = '<Leader>ta',     -- show actions for annotation at cursor
    quick_fix = '<Leader>tf',   -- apply quick fix
    explain = '<Leader>te',     -- explain annotation
    allowlist = '<Leader>tw',   -- add to allowlist
    suggest_improvements = '<Leader>tS', -- show buffer suggestions (capital S to avoid conflict)
    suggest_function = '<Leader>tF',     -- show function suggestions
    refactor = '<Leader>tR',    -- show refactoring suggestions
    scan_comprehensive = '<Leader>tC',   -- comprehensive buffer scan
    quickfix_captures = '<Leader>tq', -- populate quickfix with stack traces
  },
  telescope = true,
  notifications = {
    enabled = true,
  },
})
```

### Auto-render behavior

TraceBack coalesces frequent events and re-renders lenses on:
- DiagnosticChanged, TextChanged, CursorHold, BufEnter, WinScrolled, InsertLeave, and LspAttach

You can tune per-event debounce with `lenses.event_debounce` and a fallback `lenses.debounce_ms`.

### LSP lens options
- `lsp_max_per_line`: show up to N diagnostics per line (default 1)
- `lsp_truncate`: max characters for a message before adding an ellipsis (default 120)
- `lsp_show_codes`: append diagnostic codes like [unused-var] when provided (default true)
- `lsp_show_source`: append diagnostic source like (eslint) (default false)

### Code lens options
- `code_show_metrics`: include parameter count and function LOC when Treesitter is available (default true)

## Code Actions & Systematic Suggestions

TraceBack now includes a powerful code actions and systematic suggestion system that provides intelligent, context-aware recommendations for improving your code. The system analyzes complexity, security patterns, performance characteristics, and code quality to offer actionable insights.

### 🚀 Smart Suggestion Engine

The suggestion engine uses advanced heuristics to analyze your code and provide:

- **🔍 Complexity Analysis**: Identifies overly complex functions and suggests refactoring strategies
- **🔒 Security Improvements**: Detects security vulnerabilities and provides secure alternatives  
- **⚡ Performance Optimizations**: Finds performance bottlenecks and suggests optimizations
- **📝 Code Quality**: Recommends modern patterns and best practices
- **🛠️ Contextual Actions**: Provides quick fixes, explanations, and automated improvements

### 💡 Features

#### Intelligent Code Analysis
- **Function Complexity**: Analyzes cyclomatic complexity, parameter count, and nesting depth
- **Pattern Detection**: Identifies code smells and anti-patterns specific to your language
- **Security Scanning**: Detects CWE-mapped vulnerabilities with confidence scoring
- **Performance Profiling**: Identifies inefficient patterns, especially in loops

#### Contextual Actions
- **Quick Fixes**: One-click application of secure alternatives and optimizations
- **Refactoring Suggestions**: Detailed guidance for breaking down complex functions
- **Security Upgrades**: Automatic replacement of insecure patterns with safe alternatives
- **Code Modernization**: Suggestions to update code to modern language features

#### Advanced Action Types
- 🛡️ **Add to Allowlist**: Suppress false positives in security scanning
- 📝 **Ignore Inline**: Add language-specific ignore comments
- 💾 **Ignore Virtual**: Add virtual text markers without modifying code
- 📖 **Show Explanation**: Detailed explanations with CWE references and examples
- 🔧 **Apply Suggested Fix**: Automatic code transformation to secure/optimized versions
- 🏗️ **Refactor Guidance**: Step-by-step refactoring recommendations
- 📚 **Quick Documentation**: Links to relevant security and best practice documentation
- 📋 **Copy Secure Snippet**: Copy secure code alternatives to clipboard

### 🎯 Commands

#### Core Actions
- `:TracebackActions` — Show available actions for annotation at cursor
- `:TracebackQuickFix` — Apply the best available quick fix
- `:TracebackExplain` — Show detailed explanation for current annotation
- `:TracebackAllowlist [pattern]` — Add pattern to security allowlist

#### Smart Suggestions  
- `:TracebackSuggest [scope]` — Show suggestions (scope: cursor/function/buffer)
- `:TracebackSuggestBuffer` — Analyze entire buffer for improvements
- `:TracebackSuggestFunction` — Analyze current function for refactoring opportunities
- `:TracebackRefactor` — Show refactoring suggestions for current location

#### Utility Commands
- `:TracebackAnnotations` — List all annotations at cursor position

### ⌨️ Default Keymaps

```lua
-- Action keymaps (can be customized in setup)
'<Leader>ta'  -- Show actions for annotation at cursor
'<Leader>tf'  -- Apply quick fix
'<Leader>te'  -- Explain annotation
'<Leader>tw'  -- Add to allowlist
'<Leader>ts'  -- Show buffer improvement suggestions  
'<Leader>tF'  -- Show function suggestions
```

### 🎨 Example Workflow

1. **Detect Issues**: Lenses automatically highlight security, complexity, and performance issues
2. **Get Suggestions**: Use `<Leader>ta` to see available actions for the issue at cursor
3. **Apply Fixes**: Choose from quick fixes, explanations, or allowlist additions  
4. **Bulk Analysis**: Use `<Leader>ts` to analyze the entire buffer for improvements
5. **Function Focus**: Use `<Leader>tF` to get specific suggestions for the current function

### 📊 Suggestion Types

#### Security Suggestions
- **High Confidence**: Direct CWE mappings with proven secure alternatives
- **Pattern-Based**: Language-specific vulnerability patterns  
- **Context-Aware**: Considers surrounding code for reduced false positives

#### Refactoring Suggestions  
- **Complexity Reduction**: Break down overly complex functions
- **Parameter Optimization**: Suggest parameter objects for functions with too many args
- **Nesting Reduction**: Recommend guard clauses and early returns

#### Performance Suggestions
- **Loop Optimization**: Detect inefficient patterns in loops with high impact scoring
- **Memory Efficiency**: Identify unnecessary allocations and suggest alternatives
- **Language-Specific**: Modern language features for better performance

### 🛡️ Security Integration

The actions system integrates deeply with the security lens to provide:

- **CVE/CWE Mapping**: Links security findings to official vulnerability databases
- **Confidence Scoring**: ML-inspired confidence ratings for security findings
- **Secure Alternatives**: Ready-to-use secure code snippets
- **Allowlist Management**: Project-specific suppression of false positives

### 🧠 Intelligence Features

- **Treesitter Integration**: Uses syntax trees for accurate code analysis
- **Context Awareness**: Considers function scope, loop context, and code patterns
- **Language-Specific**: Tailored suggestions for each supported language
- **Confidence Scoring**: Suggestions include confidence percentages to guide decisions
- **Impact Assessment**: Each suggestion shows its potential impact (security/performance/maintainability)

## Visual Features & Icons

TraceBack includes comprehensive visual enhancements with Nerd Font icons:

### 🔭 Timeline Interface
- **Timeline Entries**: 📌 Latest snapshot indicator, ⏰ historical snapshots
- **Empty State**: 📭 Friendly message when no snapshots exist
- **Snapshot Count**: Display total available snapshots in picker title
- **Restoration Feedback**: ⏪ Confirmation messages with snapshot numbers

### 💡 Code Lens Visual Indicators
- **Complexity Colors**: 
  - 🟢 Low complexity (1-5)
  - 🟡 Medium complexity (6-10) 
  - 🔴 High complexity (10+)
- **Function Detection**: Smart function naming with Treesitter support

### 🧰 LSP Lens Features  
- **Inline Diagnostics**: Render LSP messages with severity icons
- **Diagnostic Summary**: Real-time counts (E/W/I/H) at viewport top
- **Codes & Details**: Include diagnostic codes when provided by the server

### 🔒 Security Lens Capabilities
- **Threat Detection**: 🔒 Security warnings for sensitive patterns
- **Allowlist Management**: Easy suppression of false positives
- **Pattern Scoring**: Intelligent confidence-based highlighting

### 💬 Enhanced Notifications
- **Setup Messages**: 📜 Initialization status with active lens summary
- **Operation Feedback**: Status updates for captures, restores, and lens toggles
- **Error Handling**: Clear messaging for missing dependencies or issues

## Notes
- Snapshots are in-memory per-buffer; they do not persist across sessions.
- Performance: captures are throttled; snapshot size is the full buffer content.
- **Nerd Font Support**: The plugin uses Nerd Font icons for enhanced visual experience. Ensure your terminal/editor supports Nerd Fonts for optimal display.
- **Visual Feedback**: All operations provide informative notifications with appropriate icons and status updates.
  

## Security

The Traceback security lens performs heuristic checks across buffers to flag common insecure patterns and potential exposure of secrets. It is designed to help developers find issues early but is not a substitute for a full security review.

What the security lens detects (examples):
- Hardcoded credentials and API keys (AWS, GitHub, Stripe, etc.)
- Private key material and certificate blocks
- JWTs, bearer tokens, and other high-entropy secrets
- Insecure network/TLS usage (http://, disabled verification)
- Common CWE/CVE-related patterns (command injection, SQL injection, XSS, buffer issues, insecure deserialization)

Supported languages and lenses:
- C / C++
- Python
- Go
- JavaScript / Node.js
- lua

Data sources and heuristics:
- Pattern rules were informed by public vulnerability sources and advisories (Go vulnerability DB, Node.js advisories, Python security docs) and curated examples from security research. The lens uses regex and lightweight heuristics; it does not execute code.

Handling false positives:
- The security lens uses heuristics and can produce false positives. If a match is expected, you can:
  - Toggle the security lens off at runtime with the command `:TracebackLensesToggle security`.
  - Disable the lens globally in your config by setting `lenses.security = false` when calling `require('traceback').setup()` (example below).

Reporting issues or feature requests:
- If you find false positives, missing patterns, or have a suggestion for additional CVE/CWE coverage, please open an issue and follow the contribution guidelines in `CONTRIBUTING.md`.

Example configuration (disable security lens):

```lua
require('traceback').setup({
  lenses = { code = true, lsp = true, security = false },
})
```

Notes:
- The lens is intended as a lightweight helper. Do not rely on it for automated secret-scanning in CI or compliance workflows use dedicated secrets-detection tools for those use cases.
- Call `require('traceback').setup()` early in your config so providers and keymaps are registered.
- If you prefer lazy-loading, set `auto_register_lens_providers = true` so `traceback.actions` can register providers on demand.
- Make sure the buffer has a correct `filetype` (e.g. `:set filetype?`) — many providers are filetype-aware.

## Suggestions (how to use)

The suggestion engine provides scoped suggestions and actions. Use these commands and keymaps after enabling `enable_smart_suggestions` in the config above:

- `:TracebackSuggest` or `<Leader>ts` — Open a picker with buffer-wide suggestions (sorted by confidence).
- `:TracebackSuggestFunction` or `<Leader>tF` — Analyze the function under cursor and show targeted refactor suggestions.
- `:TracebackActions` or `<Leader>ta` — Show actions available for the annotation at the cursor (quick fix, explain, allowlist, etc.).

Troubleshooting:
- "No annotation at cursor": make sure `require('traceback').setup()` ran, `lenses.debug`/`lenses.security` are enabled, and that the cursor is on a line with a highlighted annotation. Use `:TracebackLenses` to render lenses and confirm annotations.
- If suggestions are empty or low-confidence, increase `max_suggestions_per_scan` or lower `suggestion_confidence_threshold` temporarily while tuning rules for your codebase.
- If providers fail silently, enable debug logging in your config (add `actions = { error_handling = true }`) to surface failures via `vim.notify`.

Examples
- Run a buffer scan and open suggestions picker:

```lua
-- call from Lua or a mapping
vim.cmd('TracebackSuggestBuffer')
```

- Show actions for the annotation under cursor:

```lua
vim.cmd('TracebackActions')
```

## License

This project is open source under the MIT License, see the `LICENSE` file for
details.

## Contributing

Contributions are welcome! See `CONTRIBUTING.md` for guidelines on reporting
issues, opening pull requests, and coding style.
