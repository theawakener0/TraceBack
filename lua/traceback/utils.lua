local M = {}

local api = vim.api

-- Common validation utilities
function M.validate_buffer(bufnr)
  return bufnr and api.nvim_buf_is_valid(bufnr)
end

function M.validate_position(pos)
  return pos and type(pos) == "table" and #pos >= 2 and 
         type(pos[1]) == "number" and type(pos[2]) == "number" and
         pos[1] > 0 and pos[2] >= 0
end

function M.validate_range(range)
  return range and type(range) == "table" and
         range.start and range["end"] and
         M.validate_position(range.start) and
         M.validate_position(range["end"])
end

-- Safe execution wrapper
function M.safe_execute(fn, error_msg, ...)
  local ok, result = pcall(fn, ...)
  if not ok then
    if error_msg then
      vim.notify(error_msg .. ": " .. tostring(result), vim.log.levels.ERROR)
    end
    return nil, result
  end
  return result
end

-- Timeout-protected execution
function M.with_timeout(fn, timeout_ms, ...)
  local start_time = os.clock()
  local timeout_seconds = timeout_ms / 1000
  
  -- For simple functions, just execute
  local ok, result = pcall(fn, ...)
  
  if os.clock() - start_time > timeout_seconds then
    vim.notify("Operation timed out after " .. timeout_ms .. "ms", vim.log.levels.WARN)
    return nil
  end
  
  if not ok then
    return nil, result
  end
  
  return result
end

-- Language detection with aliases
function M.get_normalized_filetype(ft)
  local aliases = {
    typescript = "javascript",
    tsx = "javascript", 
    jsx = "javascript",
    cc = "cpp",
    cxx = "cpp",
    ["c++"] = "cpp",
    py = "python",
    rb = "ruby",
    sh = "shell",
    bash = "shell",
    zsh = "shell"
  }
  
  return aliases[ft] or ft
end

-- Get buffer content safely
function M.get_buffer_lines(bufnr, start_line, end_line)
  if not M.validate_buffer(bufnr) then
    return nil, "Invalid buffer"
  end
  
  local ok, lines = pcall(api.nvim_buf_get_lines, bufnr, start_line or 0, end_line or -1, false)
  if not ok then
    return nil, "Failed to get buffer lines: " .. tostring(lines)
  end
  
  return lines
end

-- Cache utilities
function M.create_cache(ttl_ms)
  local cache = {
    data = {},
    ttl_ms = ttl_ms or 30000
  }
  
  function cache:get(key)
    local entry = self.data[key]
    if not entry then
      return nil
    end
    
    if os.clock() - entry.timestamp > (self.ttl_ms / 1000) then
      self.data[key] = nil
      return nil
    end
    
    return entry.value
  end
  
  function cache:set(key, value)
    self.data[key] = {
      value = value,
      timestamp = os.clock()
    }
  end
  
  function cache:clear()
    self.data = {}
  end
  
  function cache:cleanup()
    local current_time = os.clock()
    local ttl_seconds = self.ttl_ms / 1000
    
    for key, entry in pairs(self.data) do
      if current_time - entry.timestamp > ttl_seconds then
        self.data[key] = nil
      end
    end
  end
  
  return cache
end

-- String utilities
function M.trim(str)
  return str:match("^%s*(.-)%s*$")
end

function M.split(str, delimiter)
  local result = {}
  local pattern = "(.-)" .. delimiter
  local last_end = 1
  local s, e, cap = str:find(pattern, 1)
  
  while s do
    if s ~= 1 or cap ~= "" then
      table.insert(result, cap)
    end
    last_end = e + 1
    s, e, cap = str:find(pattern, last_end)
  end
  
  if last_end <= #str then
    cap = str:sub(last_end)
    table.insert(result, cap)
  end
  
  return result
end

-- Table utilities
function M.table_merge(t1, t2)
  local result = {}
  for k, v in pairs(t1 or {}) do
    result[k] = v
  end
  for k, v in pairs(t2 or {}) do
    result[k] = v
  end
  return result
end

function M.table_filter(tbl, predicate)
  local result = {}
  for i, v in ipairs(tbl or {}) do
    if predicate(v, i) then
      table.insert(result, v)
    end
  end
  return result
end

function M.table_map(tbl, mapper)
  local result = {}
  for i, v in ipairs(tbl or {}) do
    local mapped = mapper(v, i)
    if mapped ~= nil then
      table.insert(result, mapped)
    end
  end
  return result
end

-- Performance monitoring
function M.benchmark(name, fn, ...)
  local start_time = os.clock()
  local result = fn(...)
  local duration = (os.clock() - start_time) * 1000
  
  vim.notify(string.format("%s took %.2fms", name, duration), vim.log.levels.DEBUG)
  return result
end

return M
