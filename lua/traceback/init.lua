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
    max_annotations = 200, -- global cap on annotations per buffer
    scan_window = 400,     -- lines to scan around viewport for heavy work
    treesitter = true,     -- use Treesitter when available for better lenses
  },
  -- sensible default keymaps; users can override in setup()
  keymaps = {
    timeline = '<Leader>tt',    -- open timeline picker
    capture = '<Leader>tc',     -- force capture
    restore = '<Leader>tr',     -- restore last snapshot (or use :TracebackRestore {idx})
    replay = '<Leader>tp',      -- replay snapshots
    toggle_security = '<Leader>ts', -- toggle security lens
    -- Action keymaps
    actions = '<Leader>ta',     -- show actions for annotation at cursor
    quick_fix = '<Leader>tf',   -- apply quick fix
    explain = '<Leader>te',     -- explain annotation
    suggest = '<Leader>tS',     -- show buffer suggestions (capital S to avoid conflict)
    quickfix_captures = '<Leader>tq', -- populate quickfix with stack traces
  },
  telescope = true,
}

M._config = config

function M.setup(user)
  M._config = vim.tbl_deep_extend('force', config, user or {})
  
  -- Initialize core components
  require('traceback.core').setup(M._config)
  
  -- Setup lenses with configuration
  pcall(function()
    require('traceback.lenses').set_config(M._config.lenses)
    local enabled_lenses = {}
    if M._config.lenses.code then table.insert(enabled_lenses, '󰌵 Code') end
  if M._config.lenses.lsp then table.insert(enabled_lenses, '󰒡 LSP') end
    if M._config.lenses.security then table.insert(enabled_lenses, '󰌾 Security') end
    if #enabled_lenses > 0 then
      vim.notify('󰈙 TraceBack lenses active: ' .. table.concat(enabled_lenses, ', '), vim.log.levels.INFO)
    end
  end)
  
  -- Initialize actions system with code actions and systematic suggestions
  pcall(function()
    require('traceback.actions').setup({
      auto_register_lens_providers = true,
      enable_smart_suggestions = true,
      enable_taint_analysis = M._config.lenses.treesitter,
      keymaps = {
        show_actions = '<Leader>ta',
        quick_fix = '<Leader>tf',
        explain = '<Leader>te',
        allowlist = '<Leader>tw'
      }
    })
    vim.notify('󰒓 TraceBack actions system initialized', vim.log.levels.INFO)
  end)
  
  -- Load telescope extension if available and enabled
  if M._config.telescope then
    pcall(function()
      require('telescope').load_extension('traceback')
      vim.notify('󰭎 TraceBack telescope extension loaded', vim.log.levels.INFO)
    end)
  end
  
  require('traceback.commands').setup(M._config.keymaps)
  
  -- Show helpful setup info
  local snapshot_info = string.format('󰄄 Snapshots: max %d, throttle %dms', 
    M._config.snapshot.max_snapshots, M._config.snapshot.throttle_ms)
  vim.notify('󰈙 TraceBack initialized - ' .. snapshot_info, vim.log.levels.INFO)
end

return M
