local M = {}

local config = {
  snapshot = {
    max_snapshots = 200,
    throttle_ms = 500,
  },
  lenses = {
    code = true,
    debug = true,
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
  },
  telescope = true,
}

M._config = config

function M.setup(user)
  M._config = vim.tbl_deep_extend('force', config, user or {})
  require('traceback.core').setup(M._config)
  -- pass lens config
  pcall(function()
    require('traceback.lenses').set_config(M._config.lenses)
  end)
  -- load telescope extension if available and enabled
  if M._config.telescope then
    pcall(function()
      require('telescope').load_extension('traceback')
    end)
  end
  require('traceback.commands').setup(M._config.keymaps)
end

return M
