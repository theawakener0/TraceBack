local M = {}

local timelines = {}
local augroup = vim.api.nvim_create_augroup('TracebackCore', { clear = true })

local function now_ms()
  return vim.loop.now()
end

local function buf_key(bufnr)
  return tostring(bufnr)
end

local function get_buf_text(bufnr)
  return vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
end

local function snapshot_buf(bufnr)
  local lines = get_buf_text(bufnr)
  return {
    ts = now_ms(),
    cursor = vim.api.nvim_win_get_cursor(0),
    file = vim.api.nvim_buf_get_name(bufnr),
    lines = lines,
  }
end

local function get_timeline(bufnr)
  local key = buf_key(bufnr)
  if not timelines[key] then
    timelines[key] = {
      last_capture = 0,
      snapshots = {},
      index = 0,
    }
  end
  return timelines[key]
end

local function push_snapshot(bufnr, snap, cfg)
  local tl = get_timeline(bufnr)
  table.insert(tl.snapshots, snap)
  if #tl.snapshots > cfg.snapshot.max_snapshots then
    table.remove(tl.snapshots, 1)
  end
  tl.index = #tl.snapshots
  -- Render lenses if enabled
  if cfg.lenses and cfg.lenses.auto_render then
    pcall(function() require('traceback.lenses').render(bufnr) end)
  end
end

local function restore_snapshot(bufnr, idx)
  local tl = get_timeline(bufnr)
  if idx < 1 or idx > #tl.snapshots then return false end
  local s = tl.snapshots[idx]
  vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, s.lines)
  pcall(vim.api.nvim_win_set_cursor, 0, s.cursor)
  tl.index = idx
  return true
end

local function replay(bufnr, from_idx, to_idx, delay_ms)
  local tl = get_timeline(bufnr)
  from_idx = math.max(1, from_idx or 1)
  to_idx = math.min(#tl.snapshots, to_idx or #tl.snapshots)
  delay_ms = delay_ms or 80
  local i = from_idx
  local timer = vim.loop.new_timer()
  timer:start(0, delay_ms, function()
    if i > to_idx then
      timer:stop(); timer:close()
      return
    end
    vim.schedule(function()
      restore_snapshot(bufnr, i)
    end)
    i = i + 1
  end)
end

function M.setup(cfg)
  M.cfg = cfg
  vim.api.nvim_create_autocmd({ 'BufEnter' }, {
    group = augroup,
    callback = function(args)
      local bufnr = args.buf
      local tl = get_timeline(bufnr)
      if #tl.snapshots == 0 then
        push_snapshot(bufnr, snapshot_buf(bufnr), cfg)
      end
    end,
  })

  vim.api.nvim_create_autocmd({ 'TextChanged', 'TextChangedI' }, {
    group = augroup,
    callback = function(args)
      local bufnr = args.buf
      local tl = get_timeline(bufnr)
      local now = now_ms()
      if now - tl.last_capture >= cfg.snapshot.throttle_ms then
        push_snapshot(bufnr, snapshot_buf(bufnr), cfg)
        tl.last_capture = now
      end
    end,
  })
end

function M.timeline(bufnr)
  return get_timeline(bufnr or vim.api.nvim_get_current_buf())
end

function M.capture(bufnr)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  push_snapshot(bufnr, snapshot_buf(bufnr), M.cfg)
end

function M.restore(idx, bufnr)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  return restore_snapshot(bufnr, idx)
end

function M.replay(from_idx, to_idx, delay_ms, bufnr)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  return replay(bufnr, from_idx, to_idx, delay_ms)
end

return M
