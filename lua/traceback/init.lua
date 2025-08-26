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
}

M._config = config

function M.setup(user)
  M._config = vim.tbl_deep_extend('force', config, user or {})
  -- propagate notifications toggle as a global for simple access
  vim.g.traceback_notifications_enabled = not (M._config.notifications and M._config.notifications.enabled == false) and true or false
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
    if #enabled_lenses > 0 then
      U.notify('󰈙 TraceBack enhanced lenses active: ' .. table.concat(enabled_lenses, ', '), vim.log.levels.INFO)
    end
  end)
  
  -- Initialize enhanced actions system
  pcall(function()
    local actions_config = vim.tbl_deep_extend('force', M._config.actions, {
      keymaps = {
        show_actions = M._config.keymaps.actions,
        quick_fix = M._config.keymaps.quick_fix,
        explain = M._config.keymaps.explain,
        allowlist = M._config.keymaps.allowlist,
        suggest_improvements = M._config.keymaps.suggest_improvements,
        suggest_function = M._config.keymaps.suggest_function,
      }
    })
    
  require('traceback.actions').setup(actions_config)
  U.notify('󰒓 TraceBack enhanced actions system initialized', vim.log.levels.INFO)
  end)
  
  -- Initialize advanced suggestion system
  pcall(function()
  require('traceback.suggestions').setup(M._config.suggestions)
  U.notify('󰧑 TraceBack advanced suggestions system initialized', vim.log.levels.INFO)
  end)
  
  -- Load telescope extension if available and enabled
  if M._config.telescope then
    pcall(function()
  require('telescope').load_extension('traceback')
  U.notify('󰭎 TraceBack telescope extension loaded', vim.log.levels.INFO)
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
  U.notify('󰌾 TraceBack security auto-rendering enabled', vim.log.levels.INFO)
      end
    end, 500)
  end
  
  -- Show comprehensive setup info
  local snapshot_info = string.format('󰄄 Snapshots: max %d, throttle %dms', 
    M._config.snapshot.max_snapshots, M._config.snapshot.throttle_ms)
  local features_info = {
    'Enhanced Security Analysis',
    'Context-Aware Code Actions', 
    'Advanced Suggestion Engine',
    'Intelligent Auto-Rendering'
  }
  
  U.notify('󰈙 TraceBack enhanced plugin initialized - ' .. snapshot_info, vim.log.levels.INFO)
  U.notify('󰪪 Enhanced features: ' .. table.concat(features_info, ', '), vim.log.levels.INFO)
end

-- Enhanced API functions for external use
function M.get_suggestions(bufnr, scope)
  local suggestions = require('traceback.suggestions')
  scope = scope or 'buffer'
  
  if scope == 'buffer' then
    return suggestions.get_suggestions_for_buffer(bufnr)
  elseif scope == 'function' then
    local cursor_pos = vim.api.nvim_win_get_cursor(0)
    return suggestions.get_suggestions_for_function_at_cursor(bufnr, cursor_pos)
  else
    return suggestions.analyze_and_suggest(bufnr)
  end
end

function M.scan_comprehensive(bufnr, options)
  local suggestions = require('traceback.suggestions')
  return suggestions.scan_buffer_comprehensive(bufnr, options)
end

function M.get_actions_at_cursor(bufnr, cursor_pos)
  local actions = require('traceback.actions')
  return actions.get_annotations_at_cursor(bufnr, cursor_pos)
end

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
    'traceback.actions', 
    'traceback.suggestions',
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
