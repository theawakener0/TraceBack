local U = {}

-- Enhanced cache system for performance optimization
local cache = {
  ts_queries = {},
  security_analysis = {},
  function_analysis = {},
  pattern_matches = {},
  timestamps = {}
}

-- Cache management with TTL
local function is_cache_valid(key, ttl_ms)
  ttl_ms = ttl_ms or 30000 -- 30 second default
  local timestamp = cache.timestamps[key]
  if not timestamp then return false end
  return (os.clock() - timestamp) < (ttl_ms / 1000)
end

local function set_cache(key, value, ttl_ms)
  cache[key] = cache[key] or {}
  cache[key] = value
  cache.timestamps[key] = os.clock()
end

local function get_cache(key)
  return cache[key]
end

-- Return the visible viewport (topline, botline) with robust fallbacks
function U.get_viewport()
  -- Try the fast path with guards
  local ok, topline, botline = pcall(function()
    local w = vim.api.nvim_get_current_win()
    local info = vim.fn.getwininfo(w)
    if type(info) == 'table' and info[1] and info[1].topline and info[1].botline then
      return info[1].topline, info[1].botline
    end
    return nil, nil
  end)
  if ok and tonumber(topline) and tonumber(botline) then
    return topline, botline
  end

  -- Fallback to window lines; ensure numbers
  local tl = tonumber(vim.fn.line('w0')) or 1
  local bl = tonumber(vim.fn.line('w$')) or vim.api.nvim_buf_line_count(0)
  return tl, bl
end

-- Enhanced viewport with context window calculation
function U.get_viewport_with_context(context_lines)
  context_lines = context_lines or 50
  local topline, botline = U.get_viewport()
  local total_lines = vim.api.nvim_buf_line_count(0)
  
  local start_line = math.max(1, topline - context_lines)
  local end_line = math.min(total_lines, botline + context_lines)
  
  return start_line, end_line, topline, botline
end

function U.ts_available(bufnr, cfg)
  -- if the user explicitly disabled treesitter, respect that
  if not (cfg.treesitter == nil or cfg.treesitter) then return false end

  -- guard if vim.treesitter is not present (avoid pcall(true, nil) confusion)
  if not (vim and vim.treesitter and type(vim.treesitter.get_parser) == 'function') then
    return false
  end

  local ok, parser = pcall(vim.treesitter.get_parser, bufnr)
  return ok and parser ~= nil
end

-- Enhanced security analysis utilities
function U.analyze_security_context(bufnr, line_nr, pattern, matched_text)
  local context = {
    in_function = false,
    function_name = nil,
    in_loop = false,
    variable_context = {},
    surrounding_patterns = {},
    confidence_modifiers = 0
  }
  
  -- Check if in function
  local func_info = U.get_function_at_line(bufnr, line_nr)
  if func_info then
    context.in_function = true
    context.function_name = func_info.name
    context.confidence_modifiers = context.confidence_modifiers + 0.1
  end
  
  -- Check if in loop context
  context.in_loop = U.is_in_loop_context(bufnr, line_nr)
  if context.in_loop then
    context.confidence_modifiers = context.confidence_modifiers + 0.15
  end
  
  -- Analyze surrounding patterns
  context.surrounding_patterns = U.get_surrounding_patterns(bufnr, line_nr, pattern)
  if #context.surrounding_patterns > 1 then
    context.confidence_modifiers = context.confidence_modifiers + 0.1
  end
  
  -- Variable context analysis
  context.variable_context = U.analyze_variable_usage(bufnr, line_nr, matched_text)
  
  return context
end

-- Function detection with caching
function U.get_function_at_line(bufnr, line_nr)
  local cache_key = string.format("func_%d_%d", bufnr, line_nr)
  
  if is_cache_valid(cache_key, 10000) then
    return get_cache(cache_key)
  end
  
  local ft = vim.bo[bufnr].filetype
  local query = U.get_ts_query(ft, 'functions')
  if not query then return nil end
  
  local ok, parser = pcall(vim.treesitter.get_parser, bufnr, ft)
  if not ok then return nil end
  
  local tree = parser:parse()[1]
  if not tree then return nil end
  
  local root = tree:root()
  
  for id, node in query:iter_captures(root, bufnr) do
    local name = query.captures[id]
    if name == 'fn' then
      local sr, sc, er, ec = node:range()
      if line_nr - 1 >= sr and line_nr - 1 <= er then
        local func_name = "anonymous"
        
        -- Get function name
        for name_id, name_node in query:iter_captures(node, bufnr) do
          if query.captures[name_id] == 'name' then
            func_name = U.get_node_text(name_node, bufnr)
            break
          end
        end
        
        local result = {
          name = func_name,
          range = { start = { sr + 1, sc }, ["end"] = { er + 1, ec } },
          lines = er - sr + 1,
          node = node
        }
        
        set_cache(cache_key, result)
        return result
      end
    end
  end
  
  set_cache(cache_key, nil)
  return nil
end

-- Enhanced loop detection
function U.is_in_loop_context(bufnr, line_nr)
  local ft = vim.bo[bufnr].filetype
  
  if not U.ts_available(bufnr, { treesitter = true }) then
    return false
  end
  
  local loop_queries = {
    c = "[(while_statement) (for_statement) (do_statement)] @loop",
    cpp = "[(while_statement) (for_statement) (do_statement)] @loop", 
    lua = "[(while_statement) (for_statement) (repeat_statement)] @loop",
    python = "[(while_statement) (for_statement)] @loop",
    javascript = "[(while_statement) (for_statement) (for_in_statement) (for_of_statement)] @loop",
    go = "[(for_statement)] @loop",
    default = "[(while_statement) (for_statement)] @loop"
  }
  
  local query_text = loop_queries[ft] or loop_queries.default
  local ok, query = pcall(vim.treesitter.query.parse, ft, query_text)
  if not ok or not query then return false end
  
  local ok_parser, parser = pcall(vim.treesitter.get_parser, bufnr, ft)
  if not ok_parser then return false end
  
  local tree = parser:parse()[1]
  if not tree then return false end
  
  local root = tree:root()
  
  for _, node in query:iter_captures(root, bufnr) do
    local sr, _, er, _ = node:range()
    if line_nr - 1 >= sr and line_nr - 1 <= er then
      return true
    end
  end
  
  return false
end

-- Pattern analysis around a specific line
function U.get_surrounding_patterns(bufnr, line_nr, pattern)
  local context_size = 10
  local start_line = math.max(1, line_nr - context_size)
  local end_line = math.min(vim.api.nvim_buf_line_count(bufnr), line_nr + context_size)
  
  local lines = vim.api.nvim_buf_get_lines(bufnr, start_line - 1, end_line, false)
  local patterns = {}
  
  for i, line in ipairs(lines) do
    local line_number = start_line + i - 1
    if line_number ~= line_nr and line:find(pattern) then
      table.insert(patterns, {
        line_nr = line_number,
        distance = math.abs(line_number - line_nr),
        content = line
      })
    end
  end
  
  return patterns
end

-- Variable usage analysis for security context
function U.analyze_variable_usage(bufnr, line_nr, matched_text)
  local variables = {}
  
  -- Extract potential variable names from matched text
  for var_name in matched_text:gmatch("[%a_][%w_]*") do
    if #var_name > 2 then -- Filter out very short matches
      table.insert(variables, var_name)
    end
  end
  
  if #variables == 0 then return {} end
  
  -- Analyze usage context within function or nearby lines
  local context_lines = 20
  local start_line = math.max(1, line_nr - context_lines)
  local end_line = math.min(vim.api.nvim_buf_line_count(bufnr), line_nr + context_lines)
  
  local lines = vim.api.nvim_buf_get_lines(bufnr, start_line - 1, end_line, false)
  local usage_analysis = {}
  
  for _, var_name in ipairs(variables) do
    local usages = {}
    for i, line in ipairs(lines) do
      local line_number = start_line + i - 1
      if line:find(var_name) then
        table.insert(usages, {
          line_nr = line_number,
          context = line,
          is_assignment = line:find(var_name .. "%s*[=:]") ~= nil,
          is_function_call = line:find(var_name .. "%s*%(") ~= nil
        })
      end
    end
    
    if #usages > 0 then
      usage_analysis[var_name] = usages
    end
  end
  
  return usage_analysis
end

-- Smart auto-rendering decision maker
function U.should_auto_render_security(bufnr, event_type)
  -- Don't auto-render too frequently
  local cache_key = string.format("auto_render_%d", bufnr)
  if is_cache_valid(cache_key, 2000) then -- 2 second cooldown
    return false
  end
  
  -- Priority events that should trigger immediate rendering
  local priority_events = {
    "DiagnosticChanged",
    "LspAttach", 
    "BufEnter",
    "InsertLeave"
  }
  
  local should_render = false
  
  for _, priority_event in ipairs(priority_events) do
    if event_type == priority_event then
      should_render = true
      break
    end
  end
  
  -- Check if buffer has significant security-relevant content
  if should_render then
    local ft = vim.bo[bufnr].filetype
    local security_relevant_filetypes = {
      "c", "cpp", "python", "javascript", "typescript", "lua", "go", "php", "ruby", "java"
    }
    
    local is_relevant = false
    for _, relevant_ft in ipairs(security_relevant_filetypes) do
      if ft == relevant_ft then
        is_relevant = true
        break
      end
    end
    
    if is_relevant then
      set_cache(cache_key, true)
      return true
    end
  end
  
  return false
end

-- Enhanced buffer analysis for scanning
function U.analyze_buffer_complexity(bufnr)
  local analysis = {
    total_lines = vim.api.nvim_buf_line_count(bufnr),
    functions = {},
    complexity_hotspots = {},
    security_indicators = {},
    performance_issues = {},
    maintainability_score = 0
  }
  
  -- Basic complexity metrics
  local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
  local complexity_indicators = {
    nested_blocks = 0,
    long_lines = 0,
    TODO_comments = 0,
    debug_statements = 0
  }
  
  for i, line in ipairs(lines) do
    -- Count nesting levels
    local indent_level = #line:match("^%s*") / 2 -- Assuming 2-space indentation
    if indent_level > 4 then
      complexity_indicators.nested_blocks = complexity_indicators.nested_blocks + 1
      table.insert(analysis.complexity_hotspots, {
        line_nr = i,
        type = "deep_nesting",
        severity = indent_level > 6 and "high" or "medium",
        description = string.format("Deep nesting level: %d", indent_level)
      })
    end
    
    -- Long lines
    if #line > 120 then
      complexity_indicators.long_lines = complexity_indicators.long_lines + 1
      if #line > 200 then
        table.insert(analysis.complexity_hotspots, {
          line_nr = i,
          type = "long_line",
          severity = "medium", 
          description = string.format("Very long line: %d characters", #line)
        })
      end
    end
    
    -- TODO/FIXME comments
    if line:match("[Tt][Oo][Dd][Oo]") or line:match("[Ff][Ii][Xx][Mm][Ee]") then
      complexity_indicators.TODO_comments = complexity_indicators.TODO_comments + 1
    end
    
    -- Debug statements
    if line:match("console%.log") or line:match("print%(") or line:match("printf%(") then
      complexity_indicators.debug_statements = complexity_indicators.debug_statements + 1
    end
  end
  
  -- Calculate maintainability score (0-100)
  local base_score = 100
  base_score = base_score - math.min(20, complexity_indicators.nested_blocks * 2)
  base_score = base_score - math.min(15, complexity_indicators.long_lines * 0.5)
  base_score = base_score - math.min(10, complexity_indicators.TODO_comments * 1)
  base_score = base_score - math.min(10, complexity_indicators.debug_statements * 0.5)
  
  analysis.maintainability_score = math.max(0, base_score)
  
  return analysis
end

-- Enhanced scan window calculation with smart boundaries
function U.get_scan_boundaries(bufnr, topline, botline, scan_window)
  scan_window = scan_window or 400
  local total_lines = vim.api.nvim_buf_line_count(bufnr)
  local half = math.floor(scan_window / 2)
  
  local from = math.max(1, (tonumber(topline) or 1) - half)
  local to = (tonumber(botline) or total_lines) + half
  from = math.max(1, math.min(from, total_lines))
  to = math.max(from, math.min(to, total_lines))
  
  return from, to
end

-- Performance-aware rendering decision
function U.should_render_range(bufnr, from, to, max_annotations)
  max_annotations = max_annotations or 200
  local range_size = to - from + 1
  
  -- Don't render very large ranges to avoid performance issues
  if range_size > 2000 then
    return false, "Range too large for performance"
  end
  
  -- Check buffer size constraints  
  local total_lines = vim.api.nvim_buf_line_count(bufnr)
  if total_lines > 10000 then
    -- For very large files, only render visible area plus small context
    local topline, botline = U.get_viewport()
    local context = 100
    local suggested_from = math.max(1, topline - context)
    local suggested_to = math.min(total_lines, botline + context)
    
    if from < suggested_from or to > suggested_to then
      return false, "Suggested range: " .. suggested_from .. "-" .. suggested_to
    end
  end
  
  return true
end

-- Language detection with enhanced treesitter support
function U.get_effective_language(bufnr)
  local ft = vim.bo[bufnr].filetype
  
  -- Language mappings for better pattern support
  local language_mappings = {
    typescript = "javascript",
    tsx = "javascript",
    jsx = "javascript", 
    cc = "cpp",
    cxx = "cpp",
    ["c++"] = "cpp",
    py = "python",
    go = "go",
  }
  
  return language_mappings[ft] or ft
end

local ts_queries_cache = {}
function U.get_ts_query(ft, kind)
  ts_queries_cache[ft] = ts_queries_cache[ft] or {}
  if ts_queries_cache[ft][kind] ~= nil then return ts_queries_cache[ft][kind] end
  local texts = {
    functions = {
      lua = [[
        (function_declaration name: (_) @name) @fn
        (local_function name: (_) @name) @fn
        (assignment_statement 
          (variable_list 
            name: (identifier) @name) 
          (expression_list 
            value: (function_definition))) @fn
      ]],
      python = [[ 
        (function_definition name: (identifier) @name) @fn 
        (async_function_definition name: (identifier) @name) @fn
        (class_definition name: (identifier) @name) @fn
      ]],
      javascript = [[
        (function_declaration name: (identifier) @name) @fn
        (method_definition name: (property_identifier) @name) @fn
        (variable_declarator 
          name: (identifier) @name 
          value: (function_expression)) @fn
        (variable_declarator 
          name: (identifier) @name 
          value: (arrow_function)) @fn
        (assignment_expression 
          left: (member_expression property: (property_identifier) @name)
          right: (function_expression)) @fn
        (assignment_expression 
          left: (member_expression property: (property_identifier) @name)
          right: (arrow_function)) @fn
        (class_declaration name: (identifier) @name) @fn
      ]],
      typescript = [[
        (function_declaration name: (identifier) @name) @fn
        (method_definition name: (property_identifier) @name) @fn
        (variable_declarator 
          name: (identifier) @name 
          value: (function_expression)) @fn
        (variable_declarator 
          name: (identifier) @name 
          value: (arrow_function)) @fn
        (assignment_expression 
          left: (member_expression property: (property_identifier) @name)
          right: (function_expression)) @fn
        (assignment_expression 
          left: (member_expression property: (property_identifier) @name)
          right: (arrow_function)) @fn
        (class_declaration name: (type_identifier) @name) @fn
        (interface_declaration name: (type_identifier) @name) @fn
      ]],
      go = [[
        (function_declaration name: (identifier) @name) @fn
        (method_declaration name: (field_identifier) @name) @fn
        (type_declaration 
          (type_spec name: (type_identifier) @name 
            type: (struct_type))) @fn
        (type_declaration 
          (type_spec name: (type_identifier) @name 
            type: (interface_type))) @fn
      ]],
      c = [[
        (function_definition 
          declarator: (function_declarator 
            declarator: (identifier) @name)) @fn
        (function_definition 
          declarator: (function_declarator 
            declarator: (pointer_declarator 
              declarator: (identifier) @name))) @fn
        (declaration 
          declarator: (function_declarator 
            declarator: (identifier) @name)) @fn
      ]],
      cpp = [[
        (function_definition 
          declarator: (function_declarator 
            declarator: (identifier) @name)) @fn
        (function_definition 
          declarator: (function_declarator 
            declarator: (qualified_identifier 
              name: (identifier) @name))) @fn
        (template_declaration 
          (function_definition 
            declarator: (function_declarator 
              declarator: (identifier) @name))) @fn
        (class_specifier name: (type_identifier) @name) @fn
        (struct_specifier name: (type_identifier) @name) @fn
      ]],
    },
    sc = {
      lua = [[ (comment) @c (string) @s ]],
      python = [[ (comment) @c (string) @s ]],
      javascript = [[ (comment) @c (string) @s (template_string) @s ]],
      typescript = [[ (comment) @c (string) @s (template_string) @s ]],
      go = [[ (comment) @c (interpreted_string_literal) @s (raw_string_literal) @s ]],
      c = [[ (comment) @c (string_literal) @s (char_literal) @s ]],
      cpp = [[ (comment) @c (string_literal) @s (char_literal) @s (raw_string_literal) @s ]],
      default = [[ (comment) @c (string) @s ]],
    },
  }
  local text = (texts[kind] and texts[kind][ft]) or (texts[kind] and texts[kind].default)
  if not text then ts_queries_cache[ft][kind] = false; return nil end
  local ok, q = pcall(vim.treesitter.query.parse, ft, text)
  ts_queries_cache[ft][kind] = ok and q or false
  return ok and q or nil
end

function U.get_node_text(node, bufnr)
  local ok, res = pcall(vim.treesitter.get_node_text, node, bufnr)
  if ok then return res end
  return ''
end

function U.ts_sc_ranges(bufnr, ft, from, to)
  local q = U.get_ts_query(ft, 'sc')
  if not q then return {} end
  local ok, parser = pcall(vim.treesitter.get_parser, bufnr, ft)
  if not ok then return {} end
  local tree = parser:parse()[1]
  if not tree then return {} end
  local root = tree:root()
  local ranges = {}
  for id, node in q:iter_captures(root, bufnr, from-1, to) do
    local name = q.captures[id]
    if name == 'c' or name == 's' then
      local sr, sc, er, ec = node:range()
      for ln = sr, er do
        ranges[ln] = ranges[ln] or {}
      end
      ranges[sr] = ranges[sr] or {}
      table.insert(ranges[sr], { s = sc, e = (sr==er and ec or math.huge) })
    end
  end
  return ranges
end

function U.col_in_ranges(line, col, ranges)
  local rs = ranges[line]
  if not rs then return false end
  for _, r in ipairs(rs) do
    if col >= r.s and col < r.e then return true end
  end
  return false
end

return U
