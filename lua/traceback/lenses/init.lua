local M = {}

local ns = vim.api.nvim_create_namespace('TracebackLenses')
local cfg = {
  code = true,
  lsp = true,
  security = true,
  auto_render = true,
  -- debounce timings (ms) per event
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
  max_annotations = 200,
  scan_window = 400,
  treesitter = true,
  -- lens specific options
  lsp_max_per_line = 1,
  lsp_truncate = 120,
  lsp_show_codes = true,
  lsp_show_source = false,
  code_show_metrics = true, -- show params/LOC alongside complexity
}

local utils = require('traceback.lenses.utils')

local modules = {
  code = require('traceback.lenses.lens_code'),
  lsp = require('traceback.lenses.lens_lsp'),
  security = require('traceback.lenses.lens_security'),
}

local function clear(bufnr)
  vim.api.nvim_buf_clear_namespace(bufnr, ns, 0, -1)
end

-- simple debounced scheduler to coalesce frequent events
local uv = vim.loop
local timer = uv.new_timer()
local scheduled_buf = nil
local function schedule_render(bufnr, delay)
  if not cfg.auto_render then return end
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  delay = delay or cfg.debounce_ms or 120
  scheduled_buf = bufnr
  timer:stop()
  timer:start(delay, 0, vim.schedule_wrap(function()
    if scheduled_buf and vim.api.nvim_buf_is_loaded(scheduled_buf) then
      pcall(M.render, scheduled_buf)
    end
  end))
end

function M.render(bufnr, user_cfg)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  if user_cfg then for k,v in pairs(user_cfg) do cfg[k]=v end end
  -- load project-level allowlist into cfg for security lens
  if cfg.security then
    local ok, al = pcall(function() return require('traceback.lenses.lens_security').get_project_allowlist() end)
    if ok and type(al) == 'table' then cfg.project_allowlist = al end
  end
  clear(bufnr)
  local topline, botline = utils.get_viewport()
  local from = math.max(1, topline - math.floor(cfg.scan_window/2))
  local to = botline + math.floor(cfg.scan_window/2)
  local total = 0
  if cfg.code then total = total + (modules.code.render(bufnr, ns, cfg, from, to) or 0) end
  if cfg.lsp then total = total + (modules.lsp.render(bufnr, ns, cfg, from, to) or 0) end
  if cfg.security then total = total + (modules.security.render(bufnr, ns, cfg, from, to) or 0) end
  return total
end

function M.set_config(user_cfg)
  if not user_cfg then return end
  for k, v in pairs(user_cfg) do cfg[k] = v end
end

function M.setup_commands()
  vim.api.nvim_create_user_command('TracebackLenses', function() 
    local total = M.render()
    if total and total > 0 then
      vim.notify('󰍉 Rendered ' .. total .. ' lens annotations', vim.log.levels.INFO)
    end
  end, { 
    desc = " 󰍉 Render all active lenses - show code insights, debug info, and security warnings" 
  })
  
  vim.api.nvim_create_user_command('TracebackLensesToggle', function(opts)
    local which = opts.args
  local icons = { code = '󰌵', lsp = '󰒡', security = '󰌾' }
    local old_state = cfg[which]
    
    if which == 'code' then cfg.code = not cfg.code
  elseif which == 'lsp' then cfg.lsp = not cfg.lsp
    elseif which == 'security' then cfg.security = not cfg.security
    end
    
    local status = cfg[which] and 'enabled' or 'disabled'
    local icon = icons[which] or '󰒓'
    vim.notify(icon .. ' ' .. which:gsub('^%l', string.upper) .. ' lens ' .. status, vim.log.levels.INFO)
  M.render()
  end, { 
    nargs = 1, 
  complete = function() return {'code','lsp','security'} end,
  desc = " 󰒓 Toggle specific lens type - code/lsp/security"
  })

  -- interactive commands for security tuning
  vim.api.nvim_create_user_command('TracebackSecurityAllow', function(opts)
    local arg = opts.args
    local lens = modules.security
    if lens and lens.add_allow then 
      lens.add_allow(arg)
      vim.notify('󰌾 Added security allowlist entry: ' .. arg, vim.log.levels.INFO)
    end
    M.render()
  end, { 
    nargs = 1,
    desc = " 󰌾 Add pattern to security lens allowlist - suppress false positives"
  })

  vim.api.nvim_create_user_command('TracebackSecuritySet', function(opts)
    local parts = vim.split(opts.args, ' ')
    local key = parts[1]
    local val = tonumber(parts[2]) or parts[2]
    if key and val ~= nil then 
      cfg[key] = val 
      vim.notify('󰒓 Set ' .. key .. ' = ' .. tostring(val), vim.log.levels.INFO)
    end
    M.render()
  end, { 
    nargs = '+',
    desc = " 󰒓 Configure lens settings - set key value pairs"
  })

  local group = vim.api.nvim_create_augroup('TracebackLensesAuto', {clear=true})
  vim.api.nvim_create_autocmd('DiagnosticChanged', { group = group, callback = function(args)
    local b = args.buf or vim.api.nvim_get_current_buf()
    if vim.api.nvim_buf_is_loaded(b) then schedule_render(b, cfg.event_debounce.DiagnosticChanged) end
  end })
  vim.api.nvim_create_autocmd('CursorHold', { group = group, callback = function()
    schedule_render(vim.api.nvim_get_current_buf(), cfg.event_debounce.CursorHold)
  end })
  vim.api.nvim_create_autocmd('BufEnter', { group = group, callback = function(args)
    schedule_render(args.buf, cfg.event_debounce.BufEnter)
  end })
  vim.api.nvim_create_autocmd('TextChanged', { group = group, callback = function()
    schedule_render(vim.api.nvim_get_current_buf(), cfg.event_debounce.TextChanged)
  end })
  vim.api.nvim_create_autocmd('WinScrolled', { group = group, callback = function()
    schedule_render(vim.api.nvim_get_current_buf(), cfg.event_debounce.WinScrolled)
  end })
  vim.api.nvim_create_autocmd('InsertLeave', { group = group, callback = function()
    schedule_render(vim.api.nvim_get_current_buf(), cfg.event_debounce.InsertLeave)
  end })
  vim.api.nvim_create_autocmd('LspAttach', { group = group, callback = function(args)
    if args.buf then schedule_render(args.buf, cfg.event_debounce.LspAttach) end
  end })
end

return M
