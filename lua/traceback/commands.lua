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
end

return M
