local M = {}

local ns = vim.api.nvim_create_namespace('TracebackLenses')
local cfg = {
  code = true,
  debug = true,
  security = true,
  auto_render = true,
  max_annotations = 200,
  scan_window = 400,
  treesitter = true,
}

local utils = require('traceback.lenses.utils')

local modules = {
  code = require('traceback.lenses.lens_code'),
  debug = require('traceback.lenses.lens_debug'),
  security = require('traceback.lenses.lens_security'),
}

local function clear(bufnr)
  vim.api.nvim_buf_clear_namespace(bufnr, ns, 0, -1)
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
  if cfg.debug then total = total + (modules.debug.render(bufnr, ns, cfg, from, to) or 0) end
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
    local icons = { code = '󰌵', debug = '󰃤', security = '󰌾' }
    local old_state = cfg[which]
    
    if which == 'code' then cfg.code = not cfg.code
    elseif which == 'debug' then cfg.debug = not cfg.debug
    elseif which == 'security' then cfg.security = not cfg.security
    end
    
    local status = cfg[which] and 'enabled' or 'disabled'
    local icon = icons[which] or '󰒓'
    vim.notify(icon .. ' ' .. which:gsub('^%l', string.upper) .. ' lens ' .. status, vim.log.levels.INFO)
    M.render()
  end, { 
    nargs = 1, 
    complete = function() return {'code','debug','security'} end,
    desc = " 󰒓 Toggle specific lens type - code/debug/security"
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
    if vim.api.nvim_buf_is_loaded(b) then pcall(M.render, b) end
  end })
  vim.api.nvim_create_autocmd('CursorHold', { group = group, callback = function()
    if cfg.auto_render then pcall(M.render, vim.api.nvim_get_current_buf()) end
  end })
end

return M
