local M = {}
local U = require('traceback.utils')

function M.setup(keymaps)
  vim.api.nvim_create_user_command('TracebackTimeline', function()
    require('traceback.ui').timeline_picker()
  end, { 
    desc = " 󰈙 Open TraceBack timeline browser - navigate through buffer snapshots with preview" 
  })

  vim.api.nvim_create_user_command('TracebackHistory', function()
    require('traceback.ui').history_picker()
  end, {
    desc = " 󰔚 Open TraceBack history (Timeline + Undo)"
  })

  vim.api.nvim_create_user_command('TracebackLenses', function()
    require('traceback.ui').lenses_picker()
  end, {
    desc = " 󰍉 Toggle TraceBack lenses (code | lsp | security)"
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

  vim.api.nvim_create_user_command('TracebackReplayCancel', function()
    require('traceback.core').replay_cancel()
  end, {
    desc = " 󰜺 Cancel an ongoing replay"
  })

  -- Actions/suggestions commands removed per refactor

  -- Enhanced scanning commands
  -- Scanning/suggestion commands removed

  vim.api.nvim_create_user_command('TracebackHealth', function()
    local init = require('traceback.init')
    local health = init.health_check()
    
    -- Render health details in a scratch window (quiet policy)
    local lines = {}
    local status_icon = health.status == "ok" and "󰗠" or "󰔶"
    table.insert(lines, string.format("%s TraceBack Health: %s", status_icon, health.status))
    if #health.issues > 0 then
      table.insert(lines, "")
      table.insert(lines, "Issues:")
      for _, m in ipairs(health.issues) do table.insert(lines, "  - " .. m) end
    end
    if #health.suggestions > 0 then
      table.insert(lines, "")
      table.insert(lines, "Suggestions:")
      for _, m in ipairs(health.suggestions) do table.insert(lines, "  - " .. m) end
    end

    local buf = vim.api.nvim_create_buf(false, true)
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
    vim.api.nvim_buf_set_option(buf, 'filetype', 'markdown')
    vim.api.nvim_buf_set_option(buf, 'modifiable', false)

    local width = math.min(100, vim.o.columns - 6)
    local height = math.min(20, vim.o.lines - 6)
    local win = vim.api.nvim_open_win(buf, true, {
      relative = 'editor',
      width = width,
      height = height,
      col = math.floor((vim.o.columns - width) / 2),
      row = math.floor((vim.o.lines - height) / 2),
      border = 'rounded',
      style = 'minimal',
      title = ' TraceBack Health ',
      title_pos = 'center',
    })
    -- Close helpers
    vim.keymap.set('n', '<Esc>', function() pcall(vim.api.nvim_win_close, win, true) end, { buffer = buf })
    vim.keymap.set('n', 'q', function() pcall(vim.api.nvim_win_close, win, true) end, { buffer = buf })
  end, {
    desc = " 󰗠 Check TraceBack component health"
  })

  -- Security-specific commands
  vim.api.nvim_create_user_command('TracebackSecurityEnable', function()
    local bufnr = vim.api.nvim_get_current_buf()
    local security_lens = require('traceback.lenses.lens_security')
    security_lens.enable_auto_render(bufnr)
  U.lens_notify("󰯳 Security auto-rendering enabled", vim.log.levels.INFO)
  end, {
    desc = " 󰯳 Enable security lens auto-rendering"
  })

  vim.api.nvim_create_user_command('TracebackSecurityDisable', function()
    local bufnr = vim.api.nvim_get_current_buf()
    local security_lens = require('traceback.lenses.lens_security')
    security_lens.disable_auto_render(bufnr)
  U.lens_notify("󰯳 Security auto-rendering disabled", vim.log.levels.INFO)
  end, {
    desc = " 󰯳 Disable security lens auto-rendering"
  })

  -- Configuration commands (show only)
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
  if keymaps.history then
    map(keymaps.history, function() vim.cmd('TracebackHistory') end, "TraceBack: History browser")
  end
  map(keymaps.capture, function() vim.cmd('TracebackCapture') end, "TraceBack: Force capture")
  map(keymaps.restore, function() vim.cmd('TracebackRestore 1') end, "TraceBack: Restore latest snapshot")
  map(keymaps.replay, function() vim.cmd('TracebackReplay 1 2 100') end, "TraceBack: Replay snapshots")
  map(keymaps.toggle_security, function() vim.cmd('TracebackLensesToggle security') end, "TraceBack: Toggle security lens")
  -- Actions/suggestions keymaps removed
end

return M
