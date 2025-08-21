local M = {}

function M.setup(keymaps)
  vim.api.nvim_create_user_command('TracebackTimeline', function()
    require('traceback.telescope').timeline_picker()
  end, {})

  vim.api.nvim_create_user_command('TracebackCapture', function()
    require('traceback.core').capture()
  end, {})

  vim.api.nvim_create_user_command('TracebackRestore', function(opts)
    require('traceback.core').restore(tonumber(opts.args))
  end, { nargs = 1 })

  vim.api.nvim_create_user_command('TracebackReplay', function(opts)
    local args = vim.split(opts.args, ' ')
    local from = tonumber(args[1])
    local to = tonumber(args[2])
    local delay = tonumber(args[3])
    require('traceback.core').replay(from, to, delay)
  end, { nargs = '+' })

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
