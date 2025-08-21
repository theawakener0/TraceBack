# traceback.nvim

Time-machine for your current buffer: capture snapshots as you edit (not git), browse a timeline, replay edits, and restore any point. Comes with multiple lenses: Code, Debug, and Security.

## Features
- 󰄄 Automatic throttled snapshots on changes
- 󰆼 Ring buffer of snapshots (default 200)
- 󰭎 Telescope picker to browse timeline with preview
- 󰐊 Replay snapshots as animation
- 󰍉 Lenses with Nerd Font icons:
  - 󰌵 Code Lens: inline complexity/structure hints with color-coded indicators
  - 󰃤 Debug Lens: highlight error/log patterns and summarize LSP diagnostics
  - 󰌾 Security Lens: flag common insecure patterns
  - Uses Treesitter when available for more accurate function detection and to ignore matches inside strings/comments.

## Visual Enhancements
- 󰇘 Professional Nerd Font icons throughout the interface
- 󰌵 Color-coded complexity indicators (󰝥 low, 󰝤 medium, 󰝣 high)
- 󰐃 Enhanced timeline with visual markers for latest snapshots
- 󰍉 Informative command descriptions with contextual help
- 󰙎 Rich notifications with icons and status updates

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

All commands now include descriptive help text with Nerd Font icons:

- 󰈙 `:TracebackTimeline` – Open Telescope timeline browser with snapshot preview
- 󰄄 `:TracebackCapture` – Force capture current buffer state  
- 󰒮 `:TracebackRestore {idx}` – Restore buffer to snapshot index (supports tab completion)
- 󰐊 `:TracebackReplay {from} {to} {delay_ms}` – Replay snapshot sequence with animation
- 󰍉 `:TracebackLenses` – Render all active lenses with annotation count
- 󰒓 `:TracebackLensesToggle {code|debug|security}` – Toggle specific lens types with status feedback
- 󰌾 `:TracebackSecurityAllow {pattern}` – Add pattern to security allowlist
- 󰒓 `:TracebackSecuritySet {key} {value}` – Configure lens settings

## Usage & Keymaps

Default keymaps (can be overridden via setup):

- `<Leader>tt` — 󰭎 Open timeline picker with enhanced UI
- `<Leader>tc` — 󰄄 Force capture with confirmation
- `<Leader>tr` — 󰒮 Restore last snapshot (maps to `:TracebackRestore 1` by default)
- `<Leader>tp` — 󰐊 Replay a short range of snapshots (maps to `:TracebackReplay 1 2 100` by default)  
- `<Leader>ts` — 󰌾 Toggle the security lens with status notification

You can keep using the commands above or rely on the default keymaps. All keymaps are non-recursive and silent by default.

## User Interface

The plugin provides rich visual feedback:

- **Timeline Browser**: 󰈙 Enhanced telescope picker with snapshot count and visual indicators
- **Status Messages**: 󰙎 Informative notifications show operation results and lens status
- **Code Annotations**: 󰌵 Function complexity with color-coded indicators (󰝥󰝤󰝣)
- **Debug Indicators**: 󰃤 Error and warning patterns highlighted inline
- **Security Warnings**: 󰌾 Security issues flagged with contextual messages

## Config
```lua
require('traceback').setup({
  snapshot = { max_snapshots = 200, throttle_ms = 500 },
  lenses = { code = true, debug = true, security = true, auto_render = true, max_annotations = 200, scan_window = 400, treesitter = true },
  -- customize default keymaps:
  keymaps = {
    timeline = '<Leader>tt',
    capture = '<Leader>tc',
    restore = '<Leader>tr',
    replay = '<Leader>tp',
    toggle_security = '<Leader>ts',
  },
  telescope = true,
})
```

## Visual Features & Icons

TraceBack includes comprehensive visual enhancements with Nerd Font icons:

### 󰭎 Timeline Interface
- **Timeline Entries**: 󰐃 Latest snapshot indicator, 󰥔 historical snapshots
- **Empty State**: 󰗌 Friendly message when no snapshots exist
- **Snapshot Count**: Display total available snapshots in picker title
- **Restoration Feedback**: 󰒮 Confirmation messages with snapshot numbers

### 󰌵 Code Lens Visual Indicators
- **Complexity Colors**: 
  - 󰝥 Low complexity (1-5)
  - 󰝤 Medium complexity (6-10) 
  - 󰝣 High complexity (10+)
- **Function Detection**: Smart function naming with Treesitter support

### 󰃤 Debug Lens Features  
- **Error Patterns**: Highlight exceptions, errors, and warnings
- **Diagnostic Summary**: 󰃤 Real-time LSP diagnostic counts (E/W format)
- **Pattern Recognition**: Context-aware detection avoiding false positives

### 󰌾 Security Lens Capabilities
- **Threat Detection**: 󰌾 Security warnings for sensitive patterns
- **Allowlist Management**: Easy suppression of false positives
- **Pattern Scoring**: Intelligent confidence-based highlighting

### 󰙎 Enhanced Notifications
- **Setup Messages**: 󰈙 Initialization status with active lens summary
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
  lenses = { code = true, debug = true, security = false },
})
```

Notes:
- The lens is intended as a lightweight helper. Do not rely on it for automated secret-scanning in CI or compliance workflows—use dedicated secrets-detection tools for those use cases.

## License

This project is open source under the MIT License — see the `LICENSE` file for
details.

## Contributing

Contributions are welcome! See `CONTRIBUTING.md` for guidelines on reporting
issues, opening pull requests, and coding style.
