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

-- Build tree-style visual items for undo entries
local function get_cfg()
  local ok, init = pcall(require, 'traceback.init')
  if ok and init.get_config then return init.get_config() or {} end
  return {}
end

local function deepcopy(tbl)
  if type(tbl) ~= 'table' then return tbl end
  local res = {}
  for k, v in pairs(tbl) do res[k] = deepcopy(v) end
  return res
end

local function rel_time(ts)
  local now = os.time()
  local t = tonumber(ts) or 0
  local diff = math.max(0, now - t)
  if diff < 60 then return string.format('%ds ago', diff) end
  if diff < 3600 then return string.format('%dm ago', math.floor(diff/60)) end
  if diff < 86400 then return string.format('%dh ago', math.floor(diff/3600)) end
  return string.format('%dd ago', math.floor(diff/86400))
end

local function build_tree(entries, out, prefix_branches, style, current_seq, opts)
  entries = entries or {}
  local count = #entries
  for idx, e in ipairs(entries) do
    local is_last = (idx == count)
    local line_prefix = ''
    for _, more in ipairs(prefix_branches or {}) do
      line_prefix = line_prefix .. (more and (style == 'ascii' and '|  ' or '│  ') or '   ')
    end
    local connector = (style == 'ascii') and (is_last and '`--' or '|--') or (is_last and '└──' or '├──')
    local ts_hms = (e.time and os.date('%H:%M:%S', math.floor(tonumber(e.time)))) or '--:--:--'
    local ts_rel = (opts and opts.relative) and (' · ' .. rel_time(e.time)) or ''
    local depth_badge = (opts and opts.show_depth) and (string.format(' [d:%d]', #prefix_branches)) or ''
    local disp = string.format('%s %s seq:%d at %s%s%s', line_prefix .. connector, 'Undo', tonumber(e.seq) or -1, ts_hms, ts_rel, depth_badge)
    local is_cur = (current_seq ~= nil and e.seq == current_seq) or false
    table.insert(out, {
      seq = e.seq, time = e.time, is_current = is_cur, display = disp, entry = e,
      depth = #prefix_branches, kind = 'undo'
    })
    if type(e.alt) == 'table' and #e.alt > 0 then
      local nb = deepcopy(prefix_branches)
      table.insert(nb, not is_last)
      build_tree(e.alt, out, nb, style, current_seq, opts)
    end
  end
end

function M.tree_items(bufnr, opts)
  local ut = get_undotree(bufnr)
  if not ut then return {} end
  local cfg = get_cfg()
  local ui = cfg.ui or {}
  local uic = ui.undo_tree or {}
  local style = (opts and opts.style) or uic.style or 'unicode'
  local rel = (opts and opts.relative) or (uic.relative ~= false) -- default true
  local show_depth = (opts and opts.show_depth) or (uic.show_depth or false)
  local out = {}
  build_tree(ut.entries or {}, out, {}, style, ut.seq_cur or (ut.curhead and ut.curhead.seq) or nil, { relative = rel, show_depth = show_depth })
  -- Mark current node visually
  for i, it in ipairs(out) do
    if it.is_current then
      out[i].display = ((style == 'ascii') and '* ' or '• ') .. out[i].display
    else
      out[i].display = '  ' .. out[i].display
    end
  end
  return out
end

return M
