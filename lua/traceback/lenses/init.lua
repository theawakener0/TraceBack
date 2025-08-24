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
  TextChangedI = 300,
    WinScrolled = 120,
    CursorHold = 0,
    InsertLeave = 80,
    BufEnter = 100,
  BufWinEnter = 100,
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

local utils_ok, utils = pcall(require, 'traceback.lenses.utils')
if not utils_ok then
  vim.schedule(function()
    vim.notify('TraceBack: failed to load lenses.utils: ' .. tostring(utils), vim.log.levels.WARN)
  end)
  utils = nil
end

local modules = {}
do
  local ok_code, mod_code = pcall(require, 'traceback.lenses.lens_code')
  if ok_code then modules.code = mod_code else vim.schedule(function()
    vim.notify('TraceBack: failed to load code lens: ' .. tostring(mod_code), vim.log.levels.WARN)
  end) end
  local ok_lsp, mod_lsp = pcall(require, 'traceback.lenses.lens_lsp')
  if ok_lsp then modules.lsp = mod_lsp else vim.schedule(function()
    vim.notify('TraceBack: failed to load LSP lens: ' .. tostring(mod_lsp), vim.log.levels.WARN)
  end) end
  local ok_sec, mod_sec = pcall(require, 'traceback.lenses.lens_security')
  if ok_sec then modules.security = mod_sec else vim.schedule(function()
    vim.notify('TraceBack: failed to load security lens: ' .. tostring(mod_sec), vim.log.levels.WARN)
  end) end
end

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
      local ok, err = pcall(M.render, scheduled_buf)
      if not ok and err then
        vim.notify('TraceBack lenses render failed: ' .. tostring(err), vim.log.levels.WARN)
      end
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
  -- Safe viewport with fallback if utils not available
  local topline, botline
  if utils and utils.get_viewport then
    local ok_vp, tl, bl = pcall(utils.get_viewport)
    if ok_vp and tl and bl then
      topline, botline = tl, bl
    end
  end
  if not topline or not botline then
    topline = tonumber(vim.fn.line('w0')) or 1
    botline = tonumber(vim.fn.line('w$')) or vim.api.nvim_buf_line_count(bufnr)
  end
  local total_lines = vim.api.nvim_buf_line_count(bufnr)
  local half = math.floor((cfg.scan_window or 400) / 2)
  local from = math.max(1, (tonumber(topline) or 1) - half)
  local to = (tonumber(botline) or total_lines) + half
  from = math.max(1, math.min(from, total_lines))
  to = math.max(from, math.min(to, total_lines))
  local total = 0
  local function safe_render(name, fn)
    local ok_r, res = pcall(fn, bufnr, ns, cfg, from, to)
    if not ok_r then
      vim.notify('TraceBack ' .. name .. ' lens error: ' .. tostring(res), vim.log.levels.WARN)
      return 0
    end
    return res or 0
  end
  if cfg.code and modules.code and modules.code.render then total = total + safe_render('code', modules.code.render) end
  if cfg.lsp and modules.lsp and modules.lsp.render then total = total + safe_render('lsp', modules.lsp.render) end
  if cfg.security and modules.security and modules.security.render then total = total + safe_render('security', modules.security.render) end
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

  vim.api.nvim_create_user_command('TracebackLensesClear', function()
    local b = vim.api.nvim_get_current_buf()
    clear(b)
  end, {
    desc = ' 󰅚 Clear all TraceBack lens annotations in current buffer'
  })

  -- Simple health check to diagnose why lenses may not render
  vim.api.nvim_create_user_command('TracebackLensesHealth', function()
    local msgs = {}
    local function add(ok, msg)
      table.insert(msgs, (ok and '✔ ' or '✖ ') .. msg)
    end
    add(utils ~= nil, 'utils module loaded')
    local tl, bl
    if utils and utils.get_viewport then
      local ok_vp, a, b = pcall(utils.get_viewport)
      add(ok_vp and a and b, 'viewport resolved')
      tl, bl = a, b
    else
      add(false, 'viewport helper missing')
    end
    -- Try a dry-run render in a protected call
    local ok_render, res = pcall(function()
      local b = vim.api.nvim_get_current_buf()
      local from = 1; local to = math.min(vim.api.nvim_buf_line_count(b), 50)
      local count = 0
      if cfg.code and modules.code then count = count + (modules.code.render(b, ns, cfg, from, to) or 0) end
      if cfg.lsp and modules.lsp then count = count + (modules.lsp.render(b, ns, cfg, from, to) or 0) end
      if cfg.security and modules.security then count = count + (modules.security.render(b, ns, cfg, from, to) or 0) end
      return count
    end)
    add(ok_render, 'protected render call')
    vim.notify('TraceBack lenses health:\n' .. table.concat(msgs, '\n'), vim.log.levels.INFO)
  end, {
    desc = ' 󰈞 TraceBack lenses health check - diagnose rendering issues'
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
  vim.api.nvim_create_autocmd('TextChangedI', { group = group, callback = function()
    schedule_render(vim.api.nvim_get_current_buf(), cfg.event_debounce.TextChangedI)
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
  vim.api.nvim_create_autocmd('BufWinEnter', { group = group, callback = function(args)
    schedule_render(args.buf or vim.api.nvim_get_current_buf(), cfg.event_debounce.BufWinEnter)
  end })
end

return M
