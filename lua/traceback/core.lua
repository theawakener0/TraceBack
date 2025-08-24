local M = {}

local timelines = {}
local augroup = vim.api.nvim_create_augroup('TracebackCore', { clear = true })
local buf_keys = {}

-- persistent storage file under ('/traceback/snapshots.json')
local function state_file()
  local state_dir = vim.fn.stdpath('state') .. '/traceback'
  vim.fn.mkdir(state_dir, 'p')
  return state_dir .. '/snapshots.json'
end

local function now_ms()
  -- use wall-clock ms so timestamps and throttling behave across sessions
  return math.floor(os.time() * 1000)
end

local function buf_key(bufnr)
  local name = vim.api.nvim_buf_get_name(bufnr)
  if name and name ~= '' then
    return name
  end
  return 'buf:' .. tostring(bufnr)
end

local function get_buf_text(bufnr)
  return vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
end

local function snapshot_buf(bufnr)
  local lines = get_buf_text(bufnr)
  return {
    bufnr = bufnr,
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
  buf_keys[bufnr] = key
  return timelines[key]
end

-- persist current timeline to file
local function save_state()
  -- determine snapshot limit (fallback to 1000 if config missing)
  local max_snapshots = (M and M.cfg and M.cfg.snapshot and M.cfg.snapshot.max_snapshots) or 1000

  -- build a serializable, size-bounded copy of timelines
  local serial = {}
  for key, tl in pairs(timelines) do
    if not vim.startswith(key, 'buf:') then
      local snaps = tl.snapshots or {}
      local keep_from = math.max(1, #snaps - max_snapshots + 1)
      local s_list = {}
      for i = keep_from, #snaps do
        local s = snaps[i]
        -- copy only primitive/serializable fields
        table.insert(s_list, {
          bufnr = s.bufnr,
          ts = s.ts,
          cursor = s.cursor,
          file = s.file,
          lines = s.lines,
        })
      end
      serial[key] = {
        last_capture = tl.last_capture,
        index = (#s_list == 0) and 0 or math.max(1, math.min(tl.index or #s_list, #s_list)) ,
        snapshots = s_list,
      }
    end
  end

  -- encode to JSON
  local ok, encoded_or_err = pcall(vim.fn.json_encode, serial)
  if not ok or not encoded_or_err then
    return false, "json_encode failed: " .. tostring(encoded_or_err)
  end
  local encoded = encoded_or_err

  -- write atomically: write to tmp then rename
  local path = state_file()
  local tmp = path .. '.tmp'
  local f, err = io.open(tmp, 'wb')
  if not f then
    return false, "open tmp failed: " .. tostring(err)
  end
  local wrote, werr = f:write(encoded)
  f:close()
  if not wrote then
    pcall(os.remove, tmp)
    return false, "write failed: " .. tostring(werr)
  end

  -- try to rename into place; if os.rename fails try replacing existing file first
  local renamed, rename_err = os.rename(tmp, path)
  if not renamed then
    pcall(os.remove, path)
    renamed, rename_err = os.rename(tmp, path)
    if not renamed then
      pcall(os.remove, tmp)
      return false, "rename failed: " .. tostring(rename_err)
    end
  end

  return true
end

local function load_state()
  local path = state_file()
  local f, ferr = io.open(path, 'r')
  if not f then return false, "no state file: " .. tostring(ferr) end
  local content = f:read('*a')
  f:close()
  if not content or content == '' then return false, "empty state" end

  local ok, decoded = pcall(vim.fn.json_decode, content)
  if not ok or type(decoded) ~= 'table' then return false, "invalid json" end

  local max_snapshots = (M and M.cfg and M.cfg.snapshot and M.cfg.snapshot.max_snapshots) or 1000

  for k, v in pairs(decoded) do
    -- skip unnamed buffer timelines if any slipped into the state file
    if not vim.startswith(k, 'buf:') and type(v) == 'table' then
      local raw_snaps = v.snapshots
      if type(raw_snaps) == 'table' then
        local snaps = {}
        for i = 1, #raw_snaps do
          local s = raw_snaps[i]
          if type(s) == 'table' and type(s.lines) == 'table' then
            local ts = tonumber(s.ts) or now_ms()
            local cursor = s.cursor
            if type(cursor) ~= 'table' or #cursor < 2 then cursor = {1, 1} end
            local file = s.file or k
            local bufnr = s.bufnr  -- restore bufnr if available
            local lines = {}
            for _, ln in ipairs(s.lines) do table.insert(lines, tostring(ln or '')) end
            table.insert(snaps, { bufnr = bufnr, ts = ts, cursor = cursor, file = file, lines = lines })
          end
        end

        -- keep only the most recent max_snapshots
        if #snaps > max_snapshots then
          local keep_from = #snaps - max_snapshots + 1
          local trimmed = {}
          for i = keep_from, #snaps do table.insert(trimmed, snaps[i]) end
          snaps = trimmed
        end

        local index = tonumber(v.index) or #snaps
        if #snaps == 0 then index = 0 else index = math.max(1, math.min(index, #snaps)) end

        timelines[k] = {
          last_capture = 0,
          snapshots = snaps,
          index = index,
        }
      end
    end
  end

  return true
end

local function push_snapshot(bufnr, snap, cfg)
  if type(snap) ~= 'table' or type(snap.lines) ~= 'table' then
    return false, "invalid snapshot"
  end

  cfg = cfg or (M and M.cfg) or {}
  local max_snapshots = (cfg.snapshot and cfg.snapshot.max_snapshots) or 200

  local tl = get_timeline(bufnr)

  -- dedupe: avoid consecutive identical snapshots (same file, cursor and content)
  local last = tl.snapshots[#tl.snapshots]
  if last then
    if last.file == snap.file and type(last.cursor) == 'table' and type(snap.cursor) == 'table'
       and last.cursor[1] == snap.cursor[1] and last.cursor[2] == snap.cursor[2]
       and #last.lines == #snap.lines then
      local identical = true
      for i = 1, #snap.lines do
        if last.lines[i] ~= snap.lines[i] then
          identical = false
          break
        end
      end
      if identical then
        -- refresh timestamp and last_capture but don't create a new snapshot
        last.ts = snap.ts or now_ms()
        tl.last_capture = last.ts
        tl.index = #tl.snapshots
        return false, "duplicate"
      end
    end
  end

  -- insert snapshot and enforce max length
  table.insert(tl.snapshots, snap)
  if #tl.snapshots > max_snapshots then
    table.remove(tl.snapshots, 1)
  end
  tl.index = #tl.snapshots
  tl.last_capture = tonumber(snap.ts) or now_ms()

  -- Render lenses if enabled (safe)
  if cfg.lenses and cfg.lenses.auto_render then
    pcall(function() require('traceback.lenses').render(bufnr) end)
  end

  -- persist only when timeline is file-backed; schedule to avoid blocking
  local key = buf_key(bufnr)
  if not vim.startswith(key, 'buf:') then
    vim.schedule(function() pcall(save_state) end)
  end

  return true
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

-- Auto-capture snapshots on buffer enter
local function auto_capture_snapshot()
  local bufnr = vim.api.nvim_get_current_buf()
  local tl = get_timeline(bufnr)
  if #tl.snapshots == 0 then
    push_snapshot(bufnr, snapshot_buf(bufnr), M.cfg)
  end
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

-- migrate timeline when a buff's filename (key) changes
local function migrate_key(bufnr, new_key)
  local old_key = buf_keys[bufnr] or buf_key(bufnr)
  if old_key == new_key then
    buf_keys[bufnr] = new_key
    return
  end

  local src = timelines[old_key]
  if not src then
    buf_keys[bufnr] = new_key
    return
  end

  local dst = timelines[new_key]

  -- helper: is two snapshots identical (file, cursor, content)
  local function snaps_identical(a, b)
    if not a or not b then return false end
    if a.file ~= b.file then return false end
    if type(a.cursor) ~= 'table' or type(b.cursor) ~= 'table' then return false end
    if a.cursor[1] ~= b.cursor[1] or a.cursor[2] ~= b.cursor[2] then return false end
    if #a.lines ~= #b.lines then return false end
    for i = 1, #a.lines do if a.lines[i] ~= b.lines[i] then return false end end
    return true
  end

  local max_snapshots = (M and M.cfg and M.cfg.snapshot and M.cfg.snapshot.max_snapshots) or 1000

  if not dst then
    -- simple move: preserve timeline object (cheap) and update mapping
    timelines[new_key] = src
    timelines[old_key] = nil
    buf_keys[bufnr] = new_key
    vim.schedule(function() pcall(save_state) end)
    return
  end

  -- merge src into dst: combine, sort by timestamp, remove duplicates, trim to max
  local combined = {}
  for _, s in ipairs(dst.snapshots or {}) do table.insert(combined, s) end
  for _, s in ipairs(src.snapshots or {}) do table.insert(combined, s) end

  table.sort(combined, function(a, b) return (a.ts or 0) < (b.ts or 0) end)

  local unique = {}
  for i = 1, #combined do
    local cur = combined[i]
    local last = unique[#unique]
    if not snaps_identical(last, cur) then
      table.insert(unique, cur)
    else
      -- if identical, keep the one with later ts (most recent)
      if (cur.ts or 0) > (last.ts or 0) then
        unique[#unique] = cur
      end
    end
  end

  -- trim to most recent max_snapshots
  if #unique > max_snapshots then
    local keep_from = #unique - max_snapshots + 1
    local trimmed = {}
    for i = keep_from, #unique do table.insert(trimmed, unique[i]) end
    unique = trimmed
  end

  -- determine new index: try to keep position near where the source's last index ended up
  local function find_snapshot_index_by_ref(list, target)
    if not target then return nil end
    for i = 1, #list do
      if (list[i].ts == target.ts)
         and list[i].file == target.file
         and type(list[i].cursor) == 'table' and type(target.cursor) == 'table'
         and list[i].cursor[1] == target.cursor[1]
         and list[i].cursor[2] == target.cursor[2] then
        return i
      end
    end
    return nil
  end

  local new_index = 0
  -- prefer mapping the source's current index (if exists)
  if src.index and src.index >= 1 and src.index <= #src.snapshots then
    local src_snap = src.snapshots[src.index]
    local mapped = find_snapshot_index_by_ref(unique, src_snap)
    if mapped then new_index = mapped end
  end
  -- fallback: try mapping dst.index (preserve where destination viewed last)
  if new_index == 0 and dst.index and dst.index >= 1 and dst.index <= #dst.snapshots then
    local dst_snap = dst.snapshots[dst.index]
    local mapped = find_snapshot_index_by_ref(unique, dst_snap)
    if mapped then new_index = mapped end
  end
  -- final fallback: most recent snapshot index or 0 if none
  if new_index == 0 and #unique > 0 then new_index = #unique end

  -- set merged timeline
  local last_capture = 0
  for _, s in ipairs(unique) do if (s.ts or 0) > last_capture then last_capture = s.ts or 0 end end
  timelines[new_key] = {
    last_capture = last_capture,
    snapshots = unique,
    index = new_index,
  }

  -- cleanup old timeline and mapping
  timelines[old_key] = nil
  buf_keys[bufnr] = new_key

  vim.schedule(function() pcall(save_state) end)
end

function M.setup(cfg)
  cfg = cfg or {}
  cfg.snapshot = cfg.snapshot or {}
  cfg.snapshot.max_snapshots = cfg.snapshot.max_snapshots or 1000
  cfg.snapshot.throttle_ms = cfg.snapshot.throttle_ms or 5000
  cfg.lenses = cfg.lenses or { auto_render = true }

  M.cfg = cfg

  -- load persisted timelines on setup
  pcall(load_state)

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
      end
    end,
  })

  -- handle renames/saves: migrate timeline
  vim.api.nvim_create_autocmd({ 'BufFilePost'}, {
    group = augroup,
    callback = function(args)
      local bufnr = args.buf
      migrate_key(bufnr, buf_key(bufnr))
    end,
  })

  -- when buff is deleted/wiped out, remove its timeline
  vim.api.nvim_create_autocmd({'BufDelete', 'BufWipeout'}, {
    group = augroup,
    callback = function(args)
      local bufnr = args.buf
      local key = buf_keys[bufnr] or buf_key(bufnr)
      local removed = false
      if timelines[key] then
        timelines[key] = nil
        removed = true
      end
      buf_keys[bufnr] = nil
      if removed then
        pcall(save_state)
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
