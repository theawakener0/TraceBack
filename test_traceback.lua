-- TraceBack Plugin Test File
-- This file contains examples of patterns that should be detected by the lenses

-- Debug patterns that should be detected
print("Debug print statement")  -- Should be detected as debug hint
vim.inspect({test = "data"})     -- Should be detected as debug hint
vim.notify("Test notification")  -- Should be detected as debug hint

-- Error patterns
error("This is an error")        -- Should be detected as warning
assert(false, "Assertion failed") -- Should be detected as warning

-- Todo patterns
-- TODO: This needs to be implemented  -- Should be detected as warning
-- FIXME: Fix this bug               -- Should be detected as warning
-- HACK: Temporary workaround        -- Should be detected as warning

-- Security patterns (these would be in other file types)
-- eval("user_input")  -- JavaScript - would be security error
-- os.system("command") -- Python - would be security error

-- Stack trace patterns for testing
-- File "/path/to/file.py", line 123, in function_name
--   at /path/to/file.js:45:67
-- /path/to/file.go:89:12: error message

-- Complex function for complexity analysis
local function complex_function(a, b, c, d, e, f, g)
  if a then
    if b then
      if c then
        for i = 1, 10 do
          if d then
            while e do
              if f then
                for j = 1, 5 do
                  if g then
                    print("Very nested")
                  else
                    error("Error in deep nesting")
                  end
                end
              end
              break
            end
          end
        end
      end
    end
  end
  
  -- This function should trigger refactoring suggestions
  -- due to high complexity and parameter count
  return true
end

-- Simple function for comparison
local function simple_function()
  return "Hello World"
end

-- Function with potential performance issues
local function inefficient_function()
  local result = {}
  for i = 1, 1000 do
    -- This could be flagged as inefficient pattern
    table.insert(result, string.format("Item %d", i))
  end
  return result
end

-- Testing different log levels
print("INFO: This is info")      -- Should be detected
print("ERROR: This is error")    -- Should be detected as error
print("WARN: This is warning")   -- Should be detected as warning
print("DEBUG: This is debug")    -- Should be detected as hint

-- Testing exception patterns
-- Exception in thread "main"     -- Should be detected
-- Traceback (most recent call last): -- Should be detected

return {
  complex_function = complex_function,
  simple_function = simple_function,
  inefficient_function = inefficient_function
}
