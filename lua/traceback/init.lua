local M = {}

local config = {
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
  -- UI preferences
  ui = {
    -- picker backend: 'auto' (try telescope, then mini.pick, then fallback), 'telescope', or 'mini'
    picker = 'auto',
  },
  -- sensible default keymaps; users can override in setup()
  keymaps = {
    timeline = '<Leader>tt',    -- open timeline picker
    history = '<Leader>th',     -- open combined history (timeline + undo)
    undo = '<Leader>tu',        -- open undo tree only
    capture = '<Leader>tc',     -- force capture
    restore = '<Leader>tr',     -- restore last snapshot (or use :TracebackRestore {idx})
    replay = '<Leader>tp',      -- replay snapshots
    toggle_security = '<Leader>ts', -- toggle security lens
    quickfix_captures = '<Leader>tq', -- populate quickfix with stack traces (if present)
  },
  telescope = { enabled = true, theme = 'ivy' },
}

M._config = config

function M.setup(user)
  M._config = vim.tbl_deep_extend('force', config, user or {})
  local U = require('traceback.utils')
  
  -- Initialize core components
  require('traceback.core').setup(M._config)
  
  -- Setup enhanced lenses with configuration
  pcall(function()
    require('traceback.lenses').set_config(M._config.lenses)
    local enabled_lenses = {}
    if M._config.lenses.code then table.insert(enabled_lenses, '󰌵 Code') end
    if M._config.lenses.lsp then table.insert(enabled_lenses, '󰒡 LSP') end
    if M._config.lenses.security then 
      table.insert(enabled_lenses, '󰌾 Security')
      -- Setup enhanced security lens features
      local security_lens = require('traceback.lenses.lens_security')
      if M._config.lenses.security_auto_render then
        security_lens.set_config({
          auto_render_enabled = true,
          context_analysis = M._config.lenses.security_context_analysis,
          smart_filtering = M._config.lenses.security_smart_filtering,
        })
      end
    end
    -- keep quiet by default per notification policy
  end)
  
  -- Load telescope extension if available and enabled
  if M._config.telescope and (M._config.telescope.enabled ~= false) then
    pcall(function()
      require('telescope').load_extension('traceback')
    end)
  end
  
  require('traceback.commands').setup(M._config.keymaps)
  
  -- Auto-enable security lens auto-rendering if configured
  if M._config.lenses.security and M._config.lenses.security_auto_render then
    vim.defer_fn(function()
      local bufnr = vim.api.nvim_get_current_buf()
      if vim.api.nvim_buf_is_valid(bufnr) then
        local security_lens = require('traceback.lenses.lens_security')
        security_lens.enable_auto_render(bufnr)
      end
    end, 500)
  end
  
  -- keep init silent by default
end

-- Enhanced API functions for external use
function M.trigger_security_scan(bufnr)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  local security_lens = require('traceback.lenses.lens_security')
  return security_lens.trigger_smart_render(bufnr, 'high')
end

function M.get_config()
  return M._config
end

function M.health_check()
  local health = {
    status = "ok",
    components = {},
    issues = {},
    suggestions = {}
  }
  
  -- Check core components
  local components = {
    'traceback.core',
    'traceback.lenses',
    'traceback.commands'
  }
  
  for _, component in ipairs(components) do
    local ok, module = pcall(require, component)
    health.components[component] = {
      available = ok,
      error = not ok and module or nil
    }
    if not ok then
      table.insert(health.issues, string.format("Component %s failed to load: %s", component, module))
      health.status = "degraded"
    end
  end
  
  -- Check Treesitter availability
  local ts_ok = pcall(require, 'nvim-treesitter')
  health.components.treesitter = { available = ts_ok }
  if not ts_ok and M._config.lenses.treesitter then
    table.insert(health.suggestions, "Consider installing nvim-treesitter for enhanced functionality")
  end
  
  -- Check telescope
  local telescope_ok = pcall(require, 'telescope')
  health.components.telescope = { available = telescope_ok }
  if not telescope_ok and M._config.telescope then
    table.insert(health.suggestions, "Install telescope.nvim for enhanced UI")
  end
  
  return health
end

return M
