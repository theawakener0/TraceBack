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

  -- Actions and suggestions commands
  vim.api.nvim_create_user_command('TracebackActions', function()
    require('traceback.actions').show_actions()
  end, {
    desc = " 󰒓 Show TraceBack actions for annotation at cursor"
  })

  vim.api.nvim_create_user_command('TracebackSuggest', function(opts)
    local scope = opts.args or "buffer"
    if scope == "buffer" then
      require('traceback.telescope').suggestions_picker()
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
    require('traceback.telescope').suggestions_picker()
  end, {
    desc = " 󰧑 Show improvement suggestions for entire buffer with telescope picker"
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

  -- Debug lens quickfix integration
  vim.api.nvim_create_user_command('TracebackQuickfixCaptures', function()
    require('traceback.lenses.lens_debug').populate_quickfix_with_captures()
  end, {
    desc = " 󰌶 Populate quickfix with file:line captures from debug lens"
  })

  require('traceback.lenses').setup_commands()
  -- register optional default keymaps (non-recursive, silent)
  keymaps = keymaps or {}
  local function map(lhs, rhs)
    if not lhs or lhs == '' then return end
    pcall(vim.keymap.set, 'n', lhs, rhs, { noremap = true, silent = true })
  end
  map(keymaps.timeline, function() vim.cmd('TracebackTimeline') end)
  map(keymaps.capture, function() vim.cmd('TracebackCapture') end)
  map(keymaps.restore, function() vim.cmd('TracebackRestore 1') end)
  map(keymaps.replay, function() vim.cmd('TracebackReplay 1 2 100') end)
  map(keymaps.toggle_security, function() vim.cmd('TracebackLensesToggle security') end)
  
  -- Action keymaps
  map(keymaps.actions or '<Leader>ta', function() vim.cmd('TracebackActions') end)
  map(keymaps.quick_fix or '<Leader>tf', function() vim.cmd('TracebackQuickFix') end)
  map(keymaps.explain or '<Leader>te', function() vim.cmd('TracebackExplain') end)
  map(keymaps.suggest or '<Leader>ts', function() vim.cmd('TracebackSuggestBuffer') end)
  map(keymaps.quickfix_captures or '<Leader>tq', function() vim.cmd('TracebackQuickfixCaptures') end)
end

return M
