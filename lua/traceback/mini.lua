local M = {}
local U = require('traceback.utils')

local function ensure_mini()
  local ok, pick = pcall(require, 'mini.pick')
  if not ok then return nil end
  return pick
end

local function timeline_items()
  return require('traceback.telescope').timeline_items()
end

function M.timeline_picker()
  local pick = ensure_mini()
  if not pick then return end
  local items = timeline_items()
  if #items == 0 then
    pcall(vim.api.nvim_echo, { { 'TraceBack: No snapshots for this buffer', 'WarningMsg' } }, true, {})
    return
  end
  pick.pick(
    items,
    { prompt = 'TraceBack Timeline', format_item = function(e) return e.display end },
    function(item)
      if not item then return end
      local core = require('traceback.core')
      local ok_restore = core.restore(item.idx)
      if not ok_restore then
        U.notify('Failed to restore snapshot #' .. tostring(item.idx), vim.log.levels.ERROR)
      end
    end
  )
end

function M.lenses_picker()
  local pick = ensure_mini()
  if not pick then return end
  local entries = {
    { key = 'code', display = '󰌵 Code lens' },
    { key = 'lsp', display = '󰒡 LSP lens' },
    { key = 'security', display = '󰌾 Security lens' },
  }
  pick.pick(
    entries,
    { prompt = 'TraceBack Lenses', format_item = function(e) return e.display end },
    function(item)
      if not item then return end
      vim.cmd('TracebackLensesToggle ' .. item.key)
    end
  )
end

function M.history_picker()
  local pick = ensure_mini()
  if not pick then return end
  local cur_buf = vim.api.nvim_get_current_buf()
  local tb_items = timeline_items()
  local undo = require('traceback.undo')
  local undo_entries = undo.entries(cur_buf)
  local items = {}
  for _, e in ipairs(tb_items) do table.insert(items, { kind = 'snapshot', display = e.display, idx = e.idx }) end
  for _, u in ipairs(undo_entries) do table.insert(items, { kind = 'undo', display = undo.format_entry(u), seq = u.seq }) end
  if #items == 0 then
    pcall(vim.api.nvim_echo, { { 'TraceBack: Nothing to show (no snapshots or undo history)', 'WarningMsg' } }, true, {})
    return
  end
  pick.pick(
    items,
    { prompt = 'TraceBack History', format_item = function(e) return e.display end },
    function(item)
      if not item then return end
      if item.kind == 'snapshot' then
        local ok_restore = require('traceback.core').restore(item.idx)
        if not ok_restore then U.notify('Failed to restore snapshot #' .. tostring(item.idx), vim.log.levels.ERROR) end
      elseif item.kind == 'undo' then
        require('traceback.undo').goto_seq(item.seq)
      end
    end
  )
end

function M.undo_picker()
  local pick = ensure_mini()
  if not pick then return end
  local cur_buf = vim.api.nvim_get_current_buf()
  local undo = require('traceback.undo')
  local ulist = undo.tree_items(cur_buf)
  if #ulist == 0 then
    pcall(vim.api.nvim_echo, { { 'TraceBack: No undo history for this buffer', 'WarningMsg' } }, true, {})
    return
  end
  local items = {}
  for _, u in ipairs(ulist) do table.insert(items, { kind = 'undo', display = u.display, seq = u.seq }) end
  pick.pick(
    items,
    { prompt = 'Vim Undo Tree', format_item = function(e) return e.display end },
    function(item)
      if not item then return end
      require('traceback.undo').goto_seq(item.seq)
    end
  )
end

return M
