local M = {}

-- Safely get undotree for a buffer
local function get_undotree(bufnr)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  local ok, ut = pcall(function()
    return vim.api.nvim_buf_call(bufnr, function()
      return vim.fn.undotree()
    end)
  end)
  if not ok or type(ut) ~= 'table' then return nil end
  return ut
end

-- Flatten the undo entries into a simple list with depth for display
local function flatten_entries(entries, out, depth)
  entries = entries or {}
  out = out or {}
  depth = depth or 0
  for _, e in ipairs(entries) do
    table.insert(out, {
      seq = e.seq,
      time = e.time,
      save = e.save,
      depth = depth,
    })
    if type(e.alt) == 'table' and #e.alt > 0 then
      flatten_entries(e.alt, out, depth + 1)
    end
  end
  return out
end

-- Public: get a flat list of undo entries for a buffer
function M.entries(bufnr)
  local ut = get_undotree(bufnr)
  if not ut then return {} end
  local flat = flatten_entries(ut.entries or {}, {}, 0)
  -- Best effort to mark current head sequence if available
  local current_seq = ut.seq_cur or (ut.curhead and ut.curhead.seq) or nil
  for _, e in ipairs(flat) do
    e.is_current = (current_seq ~= nil and e.seq == current_seq) or false
  end
  return flat
end

-- Public: jump buffer to a specific undo sequence number
function M.goto_seq(seq, bufnr)
  if not seq then return false end
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  local ok = pcall(function()
    vim.api.nvim_buf_call(bufnr, function()
      vim.cmd('silent keepjumps undo ' .. tostring(seq))
    end)
  end)
  return ok
end

-- Helper: format a display label for an undo entry
function M.format_entry(e)
  local t = (e.time and os.date('%H:%M:%S', math.floor(tonumber(e.time) or 0))) or '--:--:--'
  local icon = e.is_current and '' or ''
  local indent = string.rep('  ', e.depth or 0)
  return string.format('%s %s seq:%d at %s', icon, indent .. 'Undo', e.seq or -1, t)
end

return M
