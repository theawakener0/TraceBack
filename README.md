# traceback.nvim

TraceBack is a fast, privacy-first time machine for your current buffer, capture lightweight, throttled snapshots as you edit (no git commits), browse a visual timeline, replay edits as an animation, and restore any point instantly. It was built to stop security and quality from being an afterthought in today’s rapid, AI-driven workflows by surfacing issues early with rich, contextual lenses.

Why use it?
- Instant safety net: recover from mistakes or experiments without touching your VCS.
- Security-first: the Security Lens highlights high‑entropy secrets, insecure patterns, and common CWE-class issues so you can fix problems before they escape the editor.
- Actionable insights: Code and LSP lenses reveal complexity hotspots and diagnostics inline.
- Low friction: in-memory snapshots, Telescope timeline browser, configurable keymaps, and minimal performance overhead.

Install, open the timeline, and let TraceBack keep your edits safe, your code cleaner, and security visible while you code.

## Features

- ⚡ Configurable, throttled automatic snapshots on buffer changes (default throttle_ms = 5000)  
- 🔄 Per-buffer ring buffer of snapshots with instant restore (default max_snapshots = 1000)  
- 🔭 Timeline browser (Telescope or mini) with live preview and snapshot counts
- 🧬 Undotree integration — combine TraceBack timeline with Vim's undo tree for a unified history view (browse and restore snapshots alongside undo entries, map snapshots to undo points, and support side‑by‑side diffs/previews)
- ▶️ Replay snapshots as animated diffs with adjustable delay (with cancel)  
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
- 💬 Quiet-by-default notifications: only errors, LSP, and lens UX messages

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

All commands include descriptive help text with visual icons:

- 📜 `:TracebackTimeline` – Open timeline picker (Telescope, mini.pick, or fallback)
- 🕰️ `:TracebackHistory` – Open a combined view (TraceBack snapshots + Vim undo entries)
-  `:TracebackCapture` – Force capture current buffer state  
-  `:TracebackUndo` – Open undo-only tree browser
- ⏪ `:TracebackRestore {idx}` – Restore buffer to snapshot index (supports tab completion)
- ▶️ `:TracebackReplay {from} {to} {delay_ms}` – Replay snapshot sequence with animation
- ⏹️ `:TracebackReplayCancel` – Cancel an ongoing replay
- 🔍 `:TracebackLenses` – Render lenses now
- 🧼 `:TracebackLensesClear` – Clear all lens annotations in the current buffer
- 🩺 `:TracebackLensesHealth` – Lenses health check and diagnostics
- ⚙️ `:TracebackLensesToggle {code|lsp|security}` – Toggle a lens type
- 🔒 `:TracebackSecurityAllow {pattern}` – Add pattern to security allowlist
- ⚙️ `:TracebackSecuritySet {key} {value}` – Configure lens settings

## Usage & Keymaps

Default keymaps (can be overridden via setup):

- `<Leader>tt` — 🔭 Open timeline picker
- `<Leader>th` — 🕰️ Open combined History picker (snapshots + undo)
- `<Leader>tu` —  Open undo-only tree browser
- `<Leader>tc` — 📸 Force capture
- `<Leader>tr` — ⏪ Restore last snapshot (maps to `:TracebackRestore 1`)
- `<Leader>tp` — ▶️ Replay a short range (maps to `:TracebackReplay 1 2 100`)
- `<Leader>ts` — 🔒 Toggle the security lens

UI backends are chosen automatically:
- Telescope (if installed): rich picker with preview and diff mapping
- mini.pick (if installed): lightweight picker
- Otherwise: vim.ui.select fallback

Telescope details:
- Timeline: live preview, newest-first ordering, and quick restore.
- Diff mapping: in the timeline picker, `<C-d>` (insert) or `d` (normal) opens a vertical diff vs current buffer.
 - Lenses picker: `:Telescope traceback lenses` or `:TracebackLenses`.
 - Undo tree: `:Telescope traceback undo` or `:TracebackUndo`.
 - In History/Undo pickers: use `<C-d>` (insert) or `d` (normal) on an undo entry to diff that undo state vs current buffer.

## User Interface

The plugin provides rich visual feedback:

- **Timeline Browser**: 📜 Enhanced Telescope picker with snapshot count and visual indicators
- **History Browser**: 🕰️ Single place to browse TraceBack snapshots and Vim undo entries
- **Status Messages**: 💬 Informative lens and LSP notifications; general notifications are quiet by default
- **Code Annotations**: 💡 Function complexity with color-coded indicators (🟢🟡🔴)
- **LSP Diagnostics**: 🧰 Inline error/warn/info/hint messages with summary
- **Security Warnings**: 🔒 Security issues flagged with contextual messages

## Install

Telescope is optional (rich UI with preview/diff). If you prefer a lightweight UI, use mini.pick (`echasnovski/mini.nvim`). Without either, a simple fallback is used.

lazy.nvim (Telescope UI):

```lua
{
  'theawakener0/TraceBack',
  dependencies = {
    'nvim-lua/plenary.nvim',
    'nvim-telescope/telescope.nvim', -- optional but recommended
    -- 'echasnovski/mini.nvim',       -- optional alternative UI
  },
  config = function()
    require('traceback').setup({
      ui = { picker = 'telescope' },
      telescope = {
        enabled = true,
        theme = 'ivy',
        layout_config = { height = 0.4, preview_width = 0.6 },
      },
    })
  end,
}
```

lazy.nvim (MiniPick UI):

```lua
{
  'theawakener0/TraceBack',
  dependencies = { 'nvim-lua/plenary.nvim', 'echasnovski/mini.nvim' },
  config = function()
    require('mini.pick').setup()
    require('traceback').setup({ ui = { picker = 'mini' } })
  end,
}
```

packer.nvim (Telescope UI):

```lua
return require('packer').startup(function(use)
  use {
    'theawakener0/TraceBack',
    requires = {
      'nvim-lua/plenary.nvim',
      'nvim-telescope/telescope.nvim', -- optional but recommended
      -- 'echasnovski/mini.nvim',       -- optional alternative UI
    },
    config = function()
      require('traceback').setup({
        ui = { picker = 'telescope' },
        telescope = { theme = 'ivy', layout_config = { height = 0.4, preview_width = 0.6 } },
      })
    end,
  }
end)
```

packer.nvim (MiniPick UI):

```lua
return require('packer').startup(function(use)
  use { 'echasnovski/mini.nvim' }
  use {
    'theawakener0/TraceBack',
    requires = { 'nvim-lua/plenary.nvim' },
    config = function()
      require('mini.pick').setup()
      require('traceback').setup({ ui = { picker = 'mini' } })
    end,
  }
end)
```

## Configuration

Minimal setup:

```lua
require('traceback').setup({})
```

Full example with comments:

```lua
require('traceback').setup({
  -- UI preferences
  ui = {
    -- Picker backend: 'auto' (default) | 'telescope' | 'mini'
    picker = 'auto',
    -- Undo tree rendering (history/undo pickers): 'unicode' (default) or 'ascii'
    undo_tree = {
      style = 'unicode',   -- 'unicode' | 'ascii' connectors
      relative = true,     -- show relative time (e.g., 2m ago)
      show_depth = false,  -- show branch depth badge like [d:2]
    },
  },

  -- Snapshot timeline
  snapshot = {
    max_snapshots = 1000,
    throttle_ms = 5000,
  },

  -- Lenses
  lenses = {
    code = true,
    lsp = true,
    security = true,
    auto_render = true,
    -- Optional fine-grained tuning
    debounce_ms = 120,
    event_debounce = {
      DiagnosticChanged = 80,
      TextChanged = 300,
      TextChangedI = 300,
      WinScrolled = 120,
      CursorHold = 0,
      InsertLeave = 80,
      BufEnter = 100,
      BufWinEnter = 100,
      LspAttach = 50,
    },
    max_annotations = 200,
    scan_window = 400,
    treesitter = true,
    -- LSP lens customization
    lsp_max_per_line = 1,
    lsp_truncate = 120,
    lsp_show_codes = true,
    lsp_show_source = false,
    -- Code lens customization
    code_show_metrics = true,
    -- Security lens
    security_auto_render = true,
    security_context_analysis = true,
    security_smart_filtering = true,
  },

  -- Default keymaps (override as you like)
  keymaps = {
    timeline = '<Leader>tt',
    history = '<Leader>th',
    undo = '<Leader>tu',
    capture = '<Leader>tc',
    restore = '<Leader>tr',
    replay = '<Leader>tp',
    toggle_security = '<Leader>ts',
  },

  -- Telescope config when using Telescope UI
  telescope = {
    enabled = true,
    theme = 'ivy', -- or 'dropdown'
    layout_config = { height = 0.4, preview_width = 0.6 },
  },
})
```

### Auto-render behavior

TraceBack coalesces frequent events and re-renders lenses on:
- DiagnosticChanged, TextChanged, CursorHold, BufEnter, WinScrolled, InsertLeave, and LspAttach

You can tune per-event debounce with `lenses.event_debounce` and a fallback `lenses.debounce_ms`.

### UI options
- `ui.picker`: select the picker backend ('auto' | 'telescope' | 'mini')

### LSP lens options
- `lsp_max_per_line`: show up to N diagnostics per line (default 1)
    telescope = {
      enabled = true,
      theme = 'ivy',
      layout_config = { height = 0.4, preview_width = 0.6 },
    },
- `lsp_show_codes`: append diagnostic codes like [unused-var] when provided (default true)
- `lsp_show_source`: append diagnostic source like (eslint) (default false)

- `code_show_metrics`: include parameter count and function LOC when Treesitter is available (default true)



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

### 💬 Notification policy
- Errors always notify via Neovim's notification system.
- Lens and LSP actions may show informative notifications.
- General info/warn notifications are suppressed by default for a quieter UX.

Legacy note: Code actions and suggestions were removed. The old modules remain as stubs that error if required. Use lenses and the timeline/history instead.

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
- Make sure the buffer has a correct `filetype` (e.g. `:set filetype?`) — many providers are filetype-aware.

## License

This project is open source under the MIT License, see the `LICENSE` file for
details.

## Contributing

Contributions are welcome! See `CONTRIBUTING.md` for guidelines on reporting
issues, opening pull requests, and coding style.
