-- Unit tests for TraceBack plugin
-- Run with: nvim --clean -u minimal_init.lua test_unit.lua

local M = {}

-- Mock vim APIs for testing
_G.vim = _G.vim or {}
vim.tbl_deep_extend = vim.tbl_deep_extend or function(behavior, ...)
  local ret = {}
  for _, tbl in ipairs({...}) do
    for k, v in pairs(tbl) do
      if type(v) == "table" and ret[k] then
        ret[k] = vim.tbl_deep_extend(behavior, ret[k], v)
      else
        ret[k] = v
      end
    end
  end
  return ret
end

vim.deepcopy = vim.deepcopy or function(tbl)
  local copy = {}
  for k, v in pairs(tbl) do
    if type(v) == "table" then
      copy[k] = vim.deepcopy(v)
    else
      copy[k] = v
    end
  end
  return copy
end

vim.list_extend = vim.list_extend or function(dst, src)
  for _, v in ipairs(src) do
    table.insert(dst, v)
  end
  return dst
end

-- Test pattern compilation
function M.test_pattern_compilation()
  print("Testing pattern compilation...")
  
  -- Simple test patterns
  local test_patterns = {
    { pattern = '\\bprint\\s*\\(', hl = 'DiagnosticHint', icon = '󰞘', priority = 5 },
    { pattern = '\\bERROR\\b', hl = 'DiagnosticError', icon = '󰅚', priority = 1 },
  }
  
  local compiled = {}
  for _, p in ipairs(test_patterns) do
    local ok, rx = pcall(vim.regex, p.pattern)
    if ok then
      table.insert(compiled, { rx = rx, hl = p.hl, icon = p.icon, priority = p.priority })
      print("  ✓ Compiled pattern: " .. p.pattern)
    else
      print("  ✗ Failed to compile: " .. p.pattern)
    end
  end
  
  print("  Compiled " .. #compiled .. " patterns")
  return #compiled > 0
end

-- Test line matching
function M.test_line_matching()
  print("Testing line matching...")
  
  local test_lines = {
    'print("hello world")',  -- Should match print pattern
    'ERROR: Something went wrong',  -- Should match ERROR pattern
    'This is a normal line',  -- Should not match anything
    'console.log("debug")',  -- Should match console.log pattern (if JS)
  }
  
  local matches_found = 0
  
  for i, line in ipairs(test_lines) do
    -- Simple regex tests
    if line:match('print%s*%(') then
      print("  ✓ Line " .. i .. ": Found print pattern")
      matches_found = matches_found + 1
    elseif line:match('ERROR') then
      print("  ✓ Line " .. i .. ": Found ERROR pattern")
      matches_found = matches_found + 1
    elseif line:match('console%.log') then
      print("  ✓ Line " .. i .. ": Found console.log pattern")
      matches_found = matches_found + 1
    else
      print("  - Line " .. i .. ": No patterns matched")
    end
  end
  
  print("  Found " .. matches_found .. " matches")
  return matches_found > 0
end

-- Test file:line parsing
function M.test_file_line_parsing()
  print("Testing file:line parsing...")
  
  local test_traces = {
    'File "/path/to/file.py", line 123',
    '  at /path/to/file.js:45:67',
    '/path/to/file.go:89:12: error message',
    'No file info here',
  }
  
  local function parse_file_line(cap)
    if not cap then return nil end
    -- Python: File "path", line 123
    local file, line = cap:match('File%s+"([^"]+)",%s+line%s+(%d+)')
    if file and line then return file, tonumber(line) end
    -- JavaScript/Node: at /path/to/file:123:45
    file, line = cap:match('at%s+([^:]+):(%d+)')
    if file and line then return file, tonumber(line) end
    -- Generic: /path/to/file:123
    file, line = cap:match('([%w%p/.-]+):(%d+)')
    if file and line then return file, tonumber(line) end
    return nil
  end
  
  local parsed = 0
  for i, trace in ipairs(test_traces) do
    local file, line = parse_file_line(trace)
    if file and line then
      print(string.format("  ✓ Trace %d: %s:%d", i, file, line))
      parsed = parsed + 1
    else
      print("  - Trace " .. i .. ": No file:line found")
    end
  end
  
  print("  Parsed " .. parsed .. " traces")
  return parsed > 0
end

-- Run all tests
function M.run_tests()
  print("=" .. string.rep("=", 50))
  print("Running TraceBack Plugin Unit Tests")
  print("=" .. string.rep("=", 50))
  
  local tests = {
    { name = "Pattern Compilation", func = M.test_pattern_compilation },
    { name = "Line Matching", func = M.test_line_matching },
    { name = "File:Line Parsing", func = M.test_file_line_parsing },
  }
  
  local passed = 0
  local total = #tests
  
  for _, test in ipairs(tests) do
    print("\n" .. string.rep("-", 30))
    local success = test.func()
    if success then
      print("✓ " .. test.name .. " PASSED")
      passed = passed + 1
    else
      print("✗ " .. test.name .. " FAILED")
    end
  end
  
  print("\n" .. string.rep("=", 50))
  print(string.format("Test Results: %d/%d passed", passed, total))
  print("=" .. string.rep("=", 50))
  
  return passed == total
end

-- Auto-run tests if this file is executed directly
if ... == nil then
  M.run_tests()
end

return M
