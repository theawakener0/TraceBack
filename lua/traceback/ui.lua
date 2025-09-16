local M = {}
local U = require('traceback.utils')

local function has_telescope()
  return pcall(require, 'telescope.pickers')
end

local function has_mini_pick()
  return pcall(require, 'mini.pick')
end

local function get_cfg()
  local ok, init = pcall(require, 'traceback.init')
  if not ok or not init.get_config then return {} end
  return init.get_config() or {}
end

local function fallback_select(entries, on_choose)
  local items = {}
  for _, e in ipairs(entries or {}) do table.insert(items, e.display or tostring(e)) end
  if #items == 0 then return end
  vim.ui.select(items, { prompt = 'TraceBack' }, function(_, idx)
    if idx and on_choose then on_choose(entries[idx], idx) end
  end)
end

function M.timeline_picker()
  local cfg = get_cfg()
  local pref = (cfg.ui and cfg.ui.picker) or 'auto'
  if pref == 'telescope' or (pref == 'auto' and has_telescope()) then
    local ok, tb_tel = pcall(require, 'traceback.telescope')
    if ok then return tb_tel.timeline_picker() end
  end
  if pref == 'mini' or (pref == 'auto' and has_mini_pick()) then
    local ok, tb_mini = pcall(require, 'traceback.mini')
    if ok then return tb_mini.timeline_picker() end
  end
  -- Fallback: simple selector without preview
  local items = require('traceback.telescope').timeline_items()
  if #items == 0 then
    -- Provide quiet feedback instead of doing nothing
    pcall(vim.api.nvim_echo, { { 'TraceBack: No snapshots for this buffer', 'WarningMsg' } }, true, {})
    return
  end
  fallback_select(items, function(entry)
    local core = require('traceback.core')
    local ok_restore = core.restore(entry.idx)
    if not ok_restore then
      U.notify('Failed to restore snapshot #' .. tostring(entry.idx), vim.log.levels.ERROR)
    end
  end)
end

function M.lenses_picker()
  local cfg = get_cfg()
  local pref = (cfg.ui and cfg.ui.picker) or 'auto'
  if pref == 'telescope' or (pref == 'auto' and has_telescope()) then
    local ok, tb_tel = pcall(require, 'traceback.telescope')
    if ok then return tb_tel.lenses_picker() end
  end
  if pref == 'mini' or (pref == 'auto' and has_mini_pick()) then
    local ok, tb_mini = pcall(require, 'traceback.mini')
    if ok then return tb_mini.lenses_picker() end
  end
  -- Fallback: simple toggle menu
  local entries = {
    { key = 'code', display = '󰌵 Code lens' },
    { key = 'lsp', display = '󰒡 LSP lens' },
    { key = 'security', display = '󰌾 Security lens' },
  }
  fallback_select(entries, function(entry)
    vim.cmd('TracebackLensesToggle ' .. entry.key)
  end)
end

function M.undo_picker()
  local cfg = get_cfg()
  local pref = (cfg.ui and cfg.ui.picker) or 'auto'
  if pref == 'telescope' or (pref == 'auto' and has_telescope()) then
    local ok, tb_tel = pcall(require, 'traceback.telescope')
    if ok and tb_tel.undo_picker then return tb_tel.undo_picker() end
  end
  if pref == 'mini' or (pref == 'auto' and has_mini_pick()) then
    local ok, tb_mini = pcall(require, 'traceback.mini')
    if ok and tb_mini.undo_picker then return tb_mini.undo_picker() end
  end
  -- Fallback: simple list
  local cur_buf = vim.api.nvim_get_current_buf()
  local undo = require('traceback.undo')
  local entries = undo.entries(cur_buf)
  if #entries == 0 then
    pcall(vim.api.nvim_echo, { { 'TraceBack: No undo history for this buffer', 'WarningMsg' } }, true, {})
    return
  end
  local items = {}
  for _, e in ipairs(entries) do table.insert(items, { display = undo.format_entry(e), seq = e.seq }) end
  fallback_select(items, function(entry)
    require('traceback.undo').goto_seq(entry.seq)
  end)
end

-- Combined history picker: shows TraceBack snapshots and Vim undo entries
function M.history_picker()
  local cfg = get_cfg()
  local pref = (cfg.ui and cfg.ui.picker) or 'auto'
  if pref == 'telescope' or (pref == 'auto' and has_telescope()) then
    local ok, tb_tel = pcall(require, 'traceback.telescope')
    if ok and tb_tel.history_picker then return tb_tel.history_picker() end
  end
  if pref == 'mini' or (pref == 'auto' and has_mini_pick()) then
    local ok, tb_mini = pcall(require, 'traceback.mini')
    if ok and tb_mini.history_picker then return tb_mini.history_picker() end
  end
  -- Fallback: simple unified list
  local cur_buf = vim.api.nvim_get_current_buf()
  local tb_items = require('traceback.telescope').timeline_items(cur_buf)
  local undo = require('traceback.undo')
  local undo_items = undo.entries(cur_buf)
  local entries = {}
  for _, e in ipairs(tb_items) do table.insert(entries, { kind = 'snapshot', display = e.display, idx = e.idx }) end
  for _, u in ipairs(undo_items) do table.insert(entries, { kind = 'undo', display = undo.format_entry(u), seq = u.seq }) end
  if #entries == 0 then
    pcall(vim.api.nvim_echo, { { 'TraceBack: Nothing to show (no snapshots or undo history)', 'WarningMsg' } }, true, {})
    return
  end
  fallback_select(entries, function(entry)
    if entry.kind == 'snapshot' then
      local core = require('traceback.core')
      local ok_restore = core.restore(entry.idx)
      if not ok_restore then
        U.notify('Failed to restore snapshot #' .. tostring(entry.idx), vim.log.levels.ERROR)
      end
    elseif entry.kind == 'undo' then
      require('traceback.undo').goto_seq(entry.seq)
    end
  end)
end

return M
