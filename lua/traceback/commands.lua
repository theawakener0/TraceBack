local M = {}

function M.setup(keymaps)
  vim.api.nvim_create_user_command('TracebackTimeline', function()
    require('traceback.telescope').timeline_picker()
  end, { 
    desc = " 󰈙 Open TraceBack timeline browser - navigate through buffer snapshots with preview" 
  })

  vim.api.nvim_create_user_command('TracebackCapture', function()
    require('traceback.core').capture()
  end, { 
    desc = " 󰄄 Force capture current buffer state - create an immediate snapshot" 
  })

  vim.api.nvim_create_user_command('TracebackRestore', function(opts)
    require('traceback.core').restore(tonumber(opts.args))
  end, { 
    nargs = 1,
    desc = " 󰒮 Restore buffer to snapshot index - use :TracebackRestore 1 for most recent",
    complete = function()
      local core = require('traceback.core')
      local tl = core.timeline(vim.api.nvim_get_current_buf())
      local completions = {}
      for i = 1, #tl.snapshots do
        table.insert(completions, tostring(i))
      end
      return completions
    end
  })

  vim.api.nvim_create_user_command('TracebackReplay', function(opts)
    local args = vim.split(opts.args, ' ')
    local from = tonumber(args[1])
    local to = tonumber(args[2])
    local delay = tonumber(args[3])
    require('traceback.core').replay(from, to, delay)
  end, { 
    nargs = '+',
    desc = " 󰐊 Replay snapshot sequence - :TracebackReplay {from} {to} {delay_ms}"
  })

  -- Enhanced Actions and suggestions commands
  vim.api.nvim_create_user_command('TracebackActions', function()
    require('traceback.actions').show_actions()
  end, {
    desc = " 󰒓 Show TraceBack actions for annotation at cursor"
  })

  vim.api.nvim_create_user_command('TracebackSuggest', function(opts)
    local scope = opts.args or "buffer"
    if scope == "buffer" then
      require('traceback.actions').show_suggestions_for_buffer()
    elseif scope == "function" then
      require('traceback.actions').show_suggestions_for_function()
    else
      require('traceback.actions').show_actions()
    end
  end, {
    nargs = '?',
    complete = function() return {'cursor', 'function', 'buffer'} end,
    desc = " 󰧑 Show TraceBack suggestions - cursor/function/buffer scope"
  })

  vim.api.nvim_create_user_command('TracebackSuggestBuffer', function()
    require('traceback.actions').show_suggestions_for_buffer()
  end, {
    desc = " 󰧑 Show improvement suggestions for entire buffer"
  })

  vim.api.nvim_create_user_command('TracebackSuggestFunction', function()
    require('traceback.actions').show_suggestions_for_function()
  end, {
    desc = " 󰧑 Show suggestions for current function"
  })

  vim.api.nvim_create_user_command('TracebackQuickFix', function()
    require('traceback.actions').quick_fix_at_cursor()
  end, {
    desc = " 󰁨 Apply quick fix for annotation at cursor"
  })

  vim.api.nvim_create_user_command('TracebackExplain', function()
    require('traceback.actions').explain_at_cursor()
  end, {
    desc = " 󰋽 Explain annotation at cursor"
  })

  vim.api.nvim_create_user_command('TracebackAllowlist', function(opts)
    if opts.args and opts.args ~= '' then
      -- Add specific pattern to allowlist
      local security_lens = require('traceback.lenses.lens_security')
      security_lens.add_allow(opts.args)
      vim.notify(string.format("󰌾 Added '%s' to allowlist", opts.args), vim.log.levels.INFO)
    else
      -- Add current annotation to allowlist
      require('traceback.actions').allowlist_at_cursor()
    end
  end, {
    nargs = '?',
    desc = " 󰌾 Add pattern to allowlist"
  })

  vim.api.nvim_create_user_command('TracebackRefactor', function()
    local annotations = require('traceback.actions').get_annotations_at_cursor()
    for _, annotation in ipairs(annotations) do
      if annotation.type == "suggestion" and annotation.suggestion_data.type == "refactor" then
        require('traceback.actions')._handle_explain(annotation)
        return
      end
    end
    vim.notify("󰘖 No refactoring suggestions at cursor", vim.log.levels.INFO)
  end, {
    desc = " 󰖷 Show refactoring suggestions for current location"
  })

  -- Enhanced scanning commands
  vim.api.nvim_create_user_command('TracebackScan', function(opts)
    local scan_type = opts.args or "comprehensive"
    local bufnr = vim.api.nvim_get_current_buf()
    
    if scan_type == "comprehensive" then
      local suggestions = require('traceback.suggestions')
      local result = suggestions.scan_buffer_comprehensive(bufnr)
      
      -- Show scan results
      local summary = string.format(
        "󰋫 Buffer Scan Results:\n" ..
        "Quality Score: %d/100\n" ..
        "Maintainability Index: %d/100\n" ..
        "Suggestions: %d\n" ..
        "Security Issues: %d\n" ..
        "Performance Issues: %d",
        result.quality_score,
        result.maintainability_index,
        #result.suggestions,
        result.metrics.security and result.metrics.security.vulnerability_count or 0,
        result.metrics.performance and #result.metrics.performance.performance_issues or 0
      )
      
      vim.notify(summary, vim.log.levels.INFO)
      
      -- Optionally show detailed suggestions
      if #result.suggestions > 0 then
        require('traceback.actions')._show_suggestions_picker(result.suggestions, "Comprehensive Scan Results")
      end
    elseif scan_type == "security" then
      local init = require('traceback.init')
      local count = init.trigger_security_scan(bufnr)
      vim.notify(string.format("󰯳 Security scan complete: %d issues found", count), vim.log.levels.INFO)
    else
      vim.notify("󰘖 Unknown scan type. Use 'comprehensive' or 'security'", vim.log.levels.WARN)
    end
  end, {
    nargs = '?',
    complete = function() return {'comprehensive', 'security'} end,
    desc = " 󰋫 Perform comprehensive buffer analysis"
  })

  vim.api.nvim_create_user_command('TracebackHealth', function()
    local init = require('traceback.init')
    local health = init.health_check()
    
    local status_icon = health.status == "ok" and "󰗠" or "󰔶"
    local message = string.format("%s TraceBack Health: %s", status_icon, health.status)
    
    if #health.issues > 0 then
      message = message .. "\nIssues:\n" .. table.concat(health.issues, "\n")
    end
    
    if #health.suggestions > 0 then
      message = message .. "\nSuggestions:\n" .. table.concat(health.suggestions, "\n")
    end
    
    vim.notify(message, health.status == "ok" and vim.log.levels.INFO or vim.log.levels.WARN)
  end, {
    desc = " 🏥 Check TraceBack component health"
  })

  -- Security-specific commands
  vim.api.nvim_create_user_command('TracebackSecurityEnable', function()
    local bufnr = vim.api.nvim_get_current_buf()
    local security_lens = require('traceback.lenses.lens_security')
    security_lens.enable_auto_render(bufnr)
    vim.notify("󰯳 Security auto-rendering enabled", vim.log.levels.INFO)
  end, {
    desc = " 󰯳 Enable security lens auto-rendering"
  })

  vim.api.nvim_create_user_command('TracebackSecurityDisable', function()
    local bufnr = vim.api.nvim_get_current_buf()
    local security_lens = require('traceback.lenses.lens_security')
    security_lens.disable_auto_render(bufnr)
    vim.notify("󰯳 Security auto-rendering disabled", vim.log.levels.INFO)
  end, {
    desc = " 󰯳 Disable security lens auto-rendering"
  })

  -- Configuration commands
  vim.api.nvim_create_user_command('TracebackConfig', function(opts)
    local action = opts.args or "show"
    local init = require('traceback.init')
    
    if action == "show" then
      local config = init.get_config()
      local config_str = vim.inspect(config)
      
      -- Create a new buffer to show config
      local buf = vim.api.nvim_create_buf(false, true)
      vim.api.nvim_buf_set_lines(buf, 0, -1, false, vim.split(config_str, "\n"))
      vim.api.nvim_buf_set_option(buf, 'filetype', 'lua')
      vim.api.nvim_buf_set_option(buf, 'readonly', true)
      
      local win = vim.api.nvim_open_win(buf, true, {
        relative = 'editor',
        width = math.min(120, vim.o.columns - 4),
        height = math.min(40, vim.o.lines - 4),
        col = 2,
        row = 2,
        border = 'rounded',
        style = 'minimal',
        title = " TraceBack Configuration ",
        title_pos = 'center'
      })
      
      -- Close window on escape or q
      vim.keymap.set('n', '<Esc>', function() vim.api.nvim_win_close(win, true) end, { buffer = buf })
      vim.keymap.set('n', 'q', function() vim.api.nvim_win_close(win, true) end, { buffer = buf })
    else
      vim.notify("󰘖 Unknown config action. Use 'show'", vim.log.levels.WARN)
    end
  end, {
    nargs = '?',
    complete = function() return {'show'} end,
    desc = " 󰮷 Show TraceBack configuration"
  })

  require('traceback.lenses').setup_commands()
  
  -- register enhanced default keymaps (non-recursive, silent)
  keymaps = keymaps or {}
  local function map(lhs, rhs, desc)
    if not lhs or lhs == '' then return end
    pcall(vim.keymap.set, 'n', lhs, rhs, { noremap = true, silent = true, desc = desc })
  end
  
  -- Core keymaps
  map(keymaps.timeline, function() vim.cmd('TracebackTimeline') end, "TraceBack: Timeline browser")
  map(keymaps.capture, function() vim.cmd('TracebackCapture') end, "TraceBack: Force capture")
  map(keymaps.restore, function() vim.cmd('TracebackRestore 1') end, "TraceBack: Restore latest snapshot")
  map(keymaps.replay, function() vim.cmd('TracebackReplay 1 2 100') end, "TraceBack: Replay snapshots")
  map(keymaps.toggle_security, function() vim.cmd('TracebackLensesToggle security') end, "TraceBack: Toggle security lens")
  
  -- Enhanced action keymaps
  map(keymaps.actions, function() vim.cmd('TracebackActions') end, "TraceBack: Show actions")
  map(keymaps.quick_fix, function() vim.cmd('TracebackQuickFix') end, "TraceBack: Apply quick fix")
  map(keymaps.explain, function() vim.cmd('TracebackExplain') end, "TraceBack: Explain annotation")
  map(keymaps.allowlist, function() vim.cmd('TracebackAllowlist') end, "TraceBack: Add to allowlist")
  map(keymaps.suggest_improvements, function() vim.cmd('TracebackSuggestBuffer') end, "TraceBack: Buffer suggestions")
  map(keymaps.suggest_function, function() vim.cmd('TracebackSuggestFunction') end, "TraceBack: Function suggestions")
  map(keymaps.refactor, function() vim.cmd('TracebackRefactor') end, "TraceBack: Refactoring suggestions")
  map(keymaps.scan_comprehensive, function() vim.cmd('TracebackScan comprehensive') end, "TraceBack: Comprehensive scan")
  map(keymaps.quickfix_captures, function() vim.cmd('TracebackQuickfixCaptures') end, "TraceBack: Quickfix captures")
end

return M
