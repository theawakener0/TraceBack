# traceback.nvim

Time-machine for your current buffer: capture snapshots as you edit (not git), browse a timeline, replay edits, and restore any point. Comes with multiple lenses: Code, Debug, and Security.

## Features
- Automatic throttled snapshots on changes
- Ring buffer of snapshots (default 200)
- Telescope picker to browse timeline with preview
- Replay snapshots as animation
- Lenses:
  - Code Lens: inline complexity/structure hints
  - Debug Lens: highlight error/log patterns and summarize LSP diagnostics
  - Security Lens: flag common insecure patterns
  - Uses Treesitter when available for more accurate function detection and to ignore matches inside strings/comments.

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
- :TracebackTimeline – Open Telescope timeline
- :TracebackCapture – Force capture
- :TracebackRestore {idx} – Restore snapshot index
- :TracebackReplay {from} {to} {delay_ms} – Replay range
- :TracebackLenses – Render lenses now
- :TracebackLensesToggle {code|debug|security}

## Usage & Keymaps

Default keymaps (can be overridden via setup):

- `<Leader>tt` — Open timeline picker
- `<Leader>tc` — Force capture
- `<Leader>tr` — Restore last snapshot (maps to `:TracebackRestore 1` by default)
- `<Leader>tp` — Replay a short range of snapshots (maps to `:TracebackReplay 1 2 100` by default)
- `<Leader>ts` — Toggle the security lens

You can keep using the commands above or rely on the default keymaps. All keymaps are non-recursive and silent by default.

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

## Notes
- Snapshots are in-memory per-buffer; they do not persist across sessions.
- Performance: captures are throttled; snapshot size is the full buffer content.
  

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
