local M = {}

local api = vim.api
local utils = require('traceback.utils')

-- Add caching for expensive operations
local cache = {
  treesitter_queries = {},
  function_analysis = {},
  pattern_matches = {},
  language_patterns = {}
}

-- Language aliases for better detection (moved to utils)
local language_aliases = {
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

-- Advanced suggestion engine with ML-inspired heuristics
function M.setup(opts)
  M.config = vim.tbl_deep_extend("force", {
    enable_complexity_analysis = true,
    enable_pattern_detection = true,
    enable_security_suggestions = true,
    enable_performance_hints = true,
    suggestion_confidence_threshold = 0.7,
    max_suggestions_per_scan = 10,
    cache_enabled = true,
    cache_ttl_ms = 30000,
    timeout_ms = 1000,
    debug = false
  }, opts or {})
  
  -- Validate configuration
  M._validate_config(M.config)
  
  -- Setup cache cleanup timer
  if M.config.cache_enabled then
    M._setup_cache_cleanup()
  end
end

-- Configuration validation
function M._validate_config(config)
  local errors = {}
  
  if config.max_suggestions_per_scan <= 0 then
    table.insert(errors, "max_suggestions_per_scan must be positive")
  end
  
  if config.suggestion_confidence_threshold < 0 or config.suggestion_confidence_threshold > 1 then
    table.insert(errors, "suggestion_confidence_threshold must be between 0 and 1")
  end
  
  if config.timeout_ms <= 0 then
    table.insert(errors, "timeout_ms must be positive")
  end
  
  if #errors > 0 then
    error("TraceBack suggestions configuration errors: " .. table.concat(errors, "; "))
  end
end

-- Cache management
function M._setup_cache_cleanup()
  vim.defer_fn(function()
    M._cleanup_cache()
    if M.config.cache_enabled then
      M._setup_cache_cleanup()
    end
  end, M.config.cache_ttl_ms)
end

function M._cleanup_cache()
  local current_time = os.clock()
  local ttl_seconds = M.config.cache_ttl_ms / 1000
  
  for cache_type, cache_data in pairs(cache) do
    for key, entry in pairs(cache_data) do
      if entry.timestamp and (current_time - entry.timestamp) > ttl_seconds then
        cache_data[key] = nil
      end
    end
  end
end

-- Enhanced treesitter utilities with caching and error handling
local treesitter = {
  get_query = function(lang, query_string)
    local cache_key = lang .. ":" .. query_string
    
    if M.config and M.config.cache_enabled and cache.treesitter_queries[cache_key] then
      local cached = cache.treesitter_queries[cache_key]
      if os.clock() - cached.timestamp < (M.config.cache_ttl_ms / 1000) then
        return cached.query
      end
    end
    
    local ok, query = pcall(vim.treesitter.query.parse, lang, query_string)
    if not ok then
      if M.config and M.config.debug then
        vim.notify("Failed to parse treesitter query for " .. lang .. ": " .. tostring(query), vim.log.levels.DEBUG)
      end
      return nil
    end
    
    if M.config and M.config.cache_enabled then
      cache.treesitter_queries[cache_key] = {
        query = query,
        timestamp = os.clock()
      }
    end
    
    return query
  end,
  
  get_captures = function(bufnr, lang, query_string, node_range)
    if not node_range then
      return {}
    end
    
    local query = treesitter.get_query(lang, query_string)
    if not query then
      return {}
    end
    
    local captures = {}
    local ok, parser = pcall(vim.treesitter.get_parser, bufnr, lang)
    if not ok or not parser then
      return {}
    end
    
    local tree_ok, trees = pcall(parser.parse, parser)
    if not tree_ok or not trees or #trees == 0 then
      return {}
    end
    
    local tree = trees[1]
    local root = tree:root()
    
    -- Apply timeout protection
    local start_time = os.clock()
    local timeout_seconds = (M.config and M.config.timeout_ms or 1000) / 1000
    
    for id, match, metadata in query:iter_matches(root, bufnr, node_range[1], node_range[2]) do
      if os.clock() - start_time > timeout_seconds then
        if M.config and M.config.debug then
          vim.notify("Treesitter query timeout for " .. lang, vim.log.levels.WARN)
        end
        break
      end
      
      for name, node in pairs(match) do
        local capture_name = query.captures[name]
        if capture_name then
          local node_ok, node_text = pcall(vim.treesitter.get_node_text, node, bufnr)
          if node_ok then
            table.insert(captures, {
              name = capture_name,
              node = node,
              text = node_text,
              range = {node:range()}
            })
          end
        end
      end
    end
    
    return captures
  end
}

-- Main suggestion analysis function
function M.analyze_and_suggest(bufnr, range)
  bufnr = bufnr or api.nvim_get_current_buf()
  
  -- Input validation
  if not utils.validate_buffer(bufnr) then
    if M.config and M.config.debug then
      vim.notify("Invalid buffer for suggestion analysis", vim.log.levels.DEBUG)
    end
    return {}
  end
  
  if range and not utils.validate_range(range) then
    if M.config and M.config.debug then
      vim.notify("Invalid range for suggestion analysis", vim.log.levels.DEBUG)
    end
    return {}
  end
  
  local ft = vim.bo[bufnr].filetype
  if not ft or ft == "" then
    return {}
  end
  
  local suggestions = {}
  local start_time = os.clock()
  local timeout_seconds = (M.config and M.config.timeout_ms or 1000) / 1000
  
  -- Complexity analysis suggestions
  if M.config and M.config.enable_complexity_analysis then
    local complexity_suggestions = utils.with_timeout(M._analyze_complexity, M.config.timeout_ms, bufnr, range, ft)
    if complexity_suggestions then
      vim.list_extend(suggestions, complexity_suggestions)
    end
    
    -- Check timeout
    if os.clock() - start_time > timeout_seconds then
      if M.config.debug then
        vim.notify("Suggestion analysis timeout during complexity analysis", vim.log.levels.WARN)
      end
      return suggestions
    end
  end
  
  -- Pattern detection suggestions
  if M.config and M.config.enable_pattern_detection then
    local pattern_suggestions = utils.with_timeout(M._detect_patterns, M.config.timeout_ms, bufnr, range, ft)
    if pattern_suggestions then
      vim.list_extend(suggestions, pattern_suggestions)
    end
    
    -- Check timeout
    if os.clock() - start_time > timeout_seconds then
      if M.config.debug then
        vim.notify("Suggestion analysis timeout during pattern detection", vim.log.levels.WARN)
      end
      return suggestions
    end
  end
  
  -- Security improvement suggestions
  if M.config and M.config.enable_security_suggestions then
    vim.list_extend(suggestions, M._analyze_security(bufnr, range, ft))
  end
  
  -- Performance optimization suggestions
  if M.config.enable_performance_hints then
    vim.list_extend(suggestions, M._analyze_performance(bufnr, range, ft))
  end
  
  -- Filter by confidence and sort
  suggestions = vim.tbl_filter(function(s) 
    return s.confidence >= M.config.suggestion_confidence_threshold 
  end, suggestions)
  
  table.sort(suggestions, function(a, b)
    if a.priority ~= b.priority then
      return a.priority < b.priority
    end
    return a.confidence > b.confidence
  end)
  
  return vim.list_slice(suggestions, 1, M.config.max_suggestions_per_scan)
end

-- Complexity analysis with refactoring suggestions
function M._analyze_complexity(bufnr, range, ft)
  local suggestions = {}
  
  -- Input validation
  if not bufnr or not api.nvim_buf_is_valid(bufnr) then
    return suggestions
  end
  
  local utils_ok, utils = pcall(require, 'traceback.lenses.utils')
  if not utils_ok then
    if M.config.debug then
      vim.notify("Failed to load utils: " .. tostring(utils), vim.log.levels.DEBUG)
    end
    return suggestions
  end
  
  if not utils.ts_available(bufnr, { treesitter = true }) then
    return suggestions
  end
  
  -- Check cache first
  local cache_key = string.format("complexity_%d_%s_%s", bufnr, 
    range and table.concat(range, "_") or "full", ft)
  
  if M.config.cache_enabled and cache.function_analysis[cache_key] then
    local cached = cache.function_analysis[cache_key]
    if os.clock() - cached.timestamp < (M.config.cache_ttl_ms / 1000) then
      return cached.suggestions
    end
  end
  
  local function_analysis_ok, function_analysis = pcall(M._analyze_functions, bufnr, range, ft)
  if not function_analysis_ok then
    if M.config.debug then
      vim.notify("Function analysis failed: " .. tostring(function_analysis), vim.log.levels.DEBUG)
    end
    return suggestions
  end
  
  for _, func in ipairs(function_analysis or {}) do
    if func.complexity and func.complexity > 15 then
      table.insert(suggestions, {
        type = "refactor",
        title = string.format("High complexity function: %s", func.name or "unknown"),
        description = string.format("Function '%s' has complexity %d. Consider breaking it into smaller functions.", 
          func.name or "unknown", func.complexity),
        range = func.range,
        confidence = 0.9,
        priority = 1,
        impact = "maintainability",
        suggestion = M._generate_refactor_suggestion(func, ft),
        actions = {
          {
            type = "extract_method",
            title = "Extract methods",
            description = "Break this function into smaller, focused methods"
          },
          {
            type = "reduce_nesting",
            title = "Reduce nesting",
            description = "Use early returns to reduce nesting levels"
          }
        }
      })
    elseif func.lines and func.lines > 50 then
      table.insert(suggestions, {
        type = "refactor",
        title = string.format("Long function: %s", func.name or "unknown"),
        description = string.format("Function '%s' is %d lines long. Consider splitting it.", 
          func.name or "unknown", func.lines),
        range = func.range,
        confidence = 0.8,
        priority = 2,
        impact = "readability",
        suggestion = "Consider the Single Responsibility Principle: each function should do one thing well.",
        actions = {
          {
            type = "extract_method",
            title = "Extract logical blocks",
            description = "Identify logical blocks that can become separate functions"
          }
        }
      })
    end
    
    if func.parameter_count > 5 then
      table.insert(suggestions, {
        type = "refactor",
        title = string.format("Too many parameters: %s", func.name),
        description = string.format("Function '%s' has %d parameters. Consider using a config object.", func.name, func.parameter_count),
        range = func.range,
        confidence = 0.85,
        priority = 2,
        impact = "usability",
        suggestion = M._generate_parameter_refactor_suggestion(func, ft),
        actions = {
          {
            type = "parameter_object",
            title = "Create parameter object",
            description = "Group related parameters into an object"
          }
        }
      })
    end
  end
  
  -- Cache the results
  if M.config.cache_enabled then
    cache.function_analysis[cache_key] = {
      suggestions = suggestions,
      timestamp = os.clock()
    }
  end
  
  return suggestions
end

-- Pattern detection for common code smells and improvements
function M._detect_patterns(bufnr, range, ft)
  local suggestions = {}
  
  -- Input validation
  if not bufnr or not api.nvim_buf_is_valid(bufnr) then
    return suggestions
  end
  
  if not range or not range.start or not range["end"] then
    return suggestions
  end
  
  -- Check cache first
  local cache_key = string.format("patterns_%d_%s_%s", bufnr, 
    table.concat({range.start[1], range.start[2], range["end"][1], range["end"][2]}, "_"), ft)
  
  if M.config.cache_enabled and cache.pattern_matches[cache_key] then
    local cached = cache.pattern_matches[cache_key]
    if os.clock() - cached.timestamp < (M.config.cache_ttl_ms / 1000) then
      return cached.suggestions
    end
  end
  
  local lines_ok, lines = pcall(api.nvim_buf_get_lines, bufnr, range.start[1] - 1, range["end"][1], false)
  if not lines_ok or not lines then
    if M.config.debug then
      vim.notify("Failed to get buffer lines: " .. tostring(lines), vim.log.levels.DEBUG)
    end
    return suggestions
  end
  
  -- Language-specific pattern analysis
  local patterns_ok, patterns = pcall(M._get_patterns_for_language, ft)
  if not patterns_ok or not patterns then
    if M.config.debug then
      vim.notify("Failed to get patterns for language " .. ft .. ": " .. tostring(patterns), vim.log.levels.DEBUG)
    end
    return suggestions
  end
  
  local start_time = os.clock()
  local timeout_seconds = M.config.timeout_ms / 1000
  
  for i, line in ipairs(lines) do
    -- Check timeout
    if os.clock() - start_time > timeout_seconds then
      if M.config.debug then
        vim.notify("Pattern detection timeout", vim.log.levels.WARN)
      end
      break
    end
    
    local line_nr = range.start[1] + i - 1
    
    for _, pattern in ipairs(patterns) do
      local match_start, match_end = line:find(pattern.regex)
      if match_start then
        local confidence = pattern.base_confidence
        
        -- Context-aware confidence adjustment
        if pattern.context_boost then
          confidence = confidence + M._calculate_context_boost(bufnr, line_nr, pattern)
        end
        
        if confidence >= M.config.suggestion_confidence_threshold then
          table.insert(suggestions, {
            type = "improvement",
            title = pattern.title,
            description = pattern.description,
            range = {
              start = { line_nr, match_start - 1 },
              ["end"] = { line_nr, match_end }
            },
            confidence = confidence,
            priority = pattern.priority,
            impact = pattern.impact,
            suggestion = pattern.suggestion,
            replacement = pattern.replacement and pattern.replacement(line:sub(match_start, match_end)),
            actions = pattern.actions or {
              {
                type = "apply_suggestion",
                title = "Apply suggestion",
                description = "Apply the recommended change"
              }
            }
          })
        end
      end
    end
  end
  
  -- Cache the results
  if M.config.cache_enabled then
    cache.pattern_matches[cache_key] = {
      suggestions = suggestions,
      timestamp = os.clock()
    }
  end
  
  return suggestions
end

-- Security analysis with upgrade suggestions
function M._analyze_security(bufnr, range, ft)
  local suggestions = {}
  
  -- Input validation
  if not bufnr or not api.nvim_buf_is_valid(bufnr) then
    return suggestions
  end
  
  if not range or not range.start or not range["end"] then
    return suggestions
  end
  
  local lines_ok, lines = pcall(api.nvim_buf_get_lines, bufnr, range.start[1] - 1, range["end"][1], false)
  if not lines_ok or not lines then
    if M.config.debug then
      vim.notify("Failed to get buffer lines for security analysis: " .. tostring(lines), vim.log.levels.DEBUG)
    end
    return suggestions
  end
  
  local patterns_ok, security_patterns = pcall(M._get_security_upgrade_patterns, ft)
  if not patterns_ok or not security_patterns then
    if M.config.debug then
      vim.notify("Failed to get security patterns for " .. ft .. ": " .. tostring(security_patterns), vim.log.levels.DEBUG)
    end
    return suggestions
  end
  
  local start_time = os.clock()
  local timeout_seconds = M.config.timeout_ms / 1000
  
  for i, line in ipairs(lines) do
    -- Check timeout
    if os.clock() - start_time > timeout_seconds then
      if M.config.debug then
        vim.notify("Security analysis timeout", vim.log.levels.WARN)
      end
      break
    end
    
    local line_nr = range.start[1] + i - 1
    
    for _, pattern in ipairs(security_patterns) do
      local match_ok, match_start, match_end = pcall(string.find, line, pattern.regex or "")
      if match_ok and match_start then
        table.insert(suggestions, {
          type = "security",
          title = pattern.title or "Security improvement",
          description = pattern.description or "Security issue detected",
          range = {
            start = { line_nr, match_start - 1 },
            ["end"] = { line_nr, match_end }
          },
          confidence = pattern.confidence,
          priority = 1, -- Security always high priority
          impact = "security",
          suggestion = pattern.upgrade_suggestion,
          replacement = pattern.replacement,
          cwe = pattern.cwe,
          actions = {
            {
              type = "security_upgrade",
              title = "Apply security fix",
              description = "Replace with secure alternative"
            },
            {
              type = "learn_more",
              title = "Learn more",
              description = "Open security documentation"
            }
          }
        })
      end
    end
  end
  
  return suggestions
end

-- Performance analysis and optimization suggestions
function M._analyze_performance(bufnr, range, ft)
  local suggestions = {}
  local lines = api.nvim_buf_get_lines(bufnr, range.start[1] - 1, range["end"][1], false)
  
  local perf_patterns = M._get_performance_patterns(ft)
  
  for i, line in ipairs(lines) do
    local line_nr = range.start[1] + i - 1
    
    for _, pattern in ipairs(perf_patterns) do
      local match_start, match_end = line:find(pattern.regex)
      if match_start then
        -- Check if this is in a loop (performance impact multiplier)
        local in_loop = M._is_in_loop(bufnr, line_nr, ft)
        local confidence = pattern.confidence
        if in_loop then
          confidence = math.min(0.95, confidence + 0.2)
        end
        
        table.insert(suggestions, {
          type = "performance",
          title = pattern.title,
          description = pattern.description .. (in_loop and " (detected in loop - high impact)" or ""),
          range = {
            start = { line_nr, match_start - 1 },
            ["end"] = { line_nr, match_end }
          },
          confidence = confidence,
          priority = in_loop and 2 or 3,
          impact = "performance",
          suggestion = pattern.optimization,
          replacement = pattern.replacement,
          actions = {
            {
              type = "optimize",
              title = "Apply optimization",
              description = "Replace with optimized version"
            },
            {
              type = "benchmark",
              title = "Show benchmark",
              description = "Compare performance characteristics"
            }
          }
        })
      end
    end
  end
  
  return suggestions
end

-- Function analysis with Treesitter
function M._analyze_functions(bufnr, range, ft)
  local utils = require('traceback.lenses.utils')
  local functions = {}
  
  local query = utils.get_ts_query(ft, 'functions')
  if not query then return functions end
  
  local ok, parser = pcall(vim.treesitter.get_parser, bufnr, ft)
  if not ok then return functions end
  
  local tree = parser:parse()[1]
  if not tree then return functions end
  
  local root = tree:root()
  
  for id, node in query:iter_captures(root, bufnr, range.start[1] - 1, range["end"][1]) do
    local name = query.captures[id]
    if name == 'fn' then
      local sr, sc, er, ec = node:range()
      local func_name = "anonymous"
      
      -- Get function name
      for name_id, name_node in query:iter_captures(node, bufnr) do
        if query.captures[name_id] == 'name' then
          func_name = utils.get_node_text(name_node, bufnr)
          break
        end
      end
      
      local func_info = {
        name = func_name,
        range = { start = { sr + 1, sc }, ["end"] = { er + 1, ec } },
        lines = er - sr + 1,
        complexity = M._calculate_cyclomatic_complexity(node, bufnr, ft),
        parameter_count = M._count_parameters(node, bufnr, ft),
        nesting_depth = M._calculate_nesting_depth(node, bufnr, ft)
      }
      
      table.insert(functions, func_info)
    end
  end
  
  return functions
end

-- Enhanced cyclomatic complexity calculation
function M._calculate_cyclomatic_complexity(node, bufnr, ft)
  local complexity = 1 -- Base complexity
  
local complexity_patterns = {
    c = {
        "if_statement", "while_statement", "for_statement", "do_statement",
        "switch_statement", "case_statement", "conditional_expression",
        'binary_expression operator: "&&"',
        'binary_expression operator: "||"'
    },
    cpp = {
        "if_statement", "while_statement", "for_statement", "do_statement",
        "switch_statement", "case_statement", "conditional_expression",
        "try_statement", "catch_clause",
        'binary_expression operator: "&&"',
        'binary_expression operator: "||"'
    },
    lua = {
        "if_statement", "while_statement", "for_statement", "repeat_statement",
        "elseif_clause",
        'binary_expression operator: "and"',
        'binary_expression operator: "or"'
    },
    python = {
        "if_statement", "while_statement", "for_statement", "try_statement",
        "except_clause", "elif_clause", "conditional_expression",
        "boolean_operator"
    },
    javascript = {
        "if_statement", "while_statement", "do_statement",
        "for_statement", "for_in_statement", "for_of_statement",
        "switch_statement", "switch_case",
        "try_statement", "catch_clause",
        "ternary_expression", "logical_expression"
    },
    go = {
        "if_statement", "for_statement",
        "switch_statement", "type_switch_statement", "case_clause",
        "select_statement", "comm_clause",
        'binary_expression operator: "&&"',
        'binary_expression operator: "||"'
    },
    default = {
        "if_statement", "while_statement", "for_statement",
        "switch_statement", "case_clause",
        "try_statement", "catch_clause",
        "conditional_expression", "logical_expression", "ternary_expression"
    }
}
  
  local patterns = complexity_patterns[ft] or complexity_patterns.default
  local query_text = ""
  for _, pattern in ipairs(patterns) do
    query_text = query_text .. string.format("(%s) @complexity\n", pattern)
  end
  
  local ok, query = pcall(vim.treesitter.query.parse, ft, query_text)
  if ok and query then
    for _ in query:iter_captures(node, bufnr) do
      complexity = complexity + 1
    end
  end
  
  return complexity
end

-- Count function parameters
function M._count_parameters(node, bufnr, ft)
  local param_queries = {
    lua = "(parameters (identifier) @param)",
    python = "(parameters (identifier) @param)",
    javascript = "(formal_parameters (identifier) @param)",
    default = "(parameters (identifier) @param)"
  }
  
  local query_text = param_queries[ft] or param_queries.default
  local ok, query = pcall(vim.treesitter.query.parse, ft, query_text)
  if not ok or not query then return 0 end
  
  local count = 0
  for _ in query:iter_captures(node, bufnr) do
    count = count + 1
  end
  
  return count
end

-- Calculate maximum nesting depth
function M._calculate_nesting_depth(node, bufnr, ft)
  local function traverse(current_node, depth)
    local max_depth = depth
    
    local nesting_nodes = {
      "if_statement", "while_statement", "for_statement", "try_statement",
      "function_declaration", "block", "compound_statement"
    }
    
    for child in current_node:iter_children() do
      local node_type = child:type()
      local child_depth = depth
      
      for _, nesting_type in ipairs(nesting_nodes) do
        if node_type == nesting_type then
          child_depth = depth + 1
          break
        end
      end
      
      max_depth = math.max(max_depth, traverse(child, child_depth))
    end
    
    return max_depth
  end
  
  return traverse(node, 0)
end

-- Generate refactoring suggestions
function M._generate_refactor_suggestion(func, ft)
  if func.complexity > 20 then
    return string.format(
      "This function has very high complexity (%d). Consider:\n" ..
      "1. Extract smaller functions for distinct responsibilities\n" ..
      "2. Use early returns to reduce nesting\n" ..
      "3. Consider the Command or Strategy pattern\n" ..
      "4. Split into multiple cohesive functions",
      func.complexity
    )
  elseif func.complexity > 15 then
    return string.format(
      "This function has high complexity (%d). Consider:\n" ..
      "1. Extract helper functions for complex logic\n" ..
      "2. Reduce conditional nesting\n" ..
      "3. Use guard clauses for early returns",
      func.complexity
    )
  else
    return "Consider extracting logical blocks into separate functions for better readability."
  end
end

function M._generate_parameter_refactor_suggestion(func, ft)
    local examples = {
        c = string.format(
            "/* Instead of: */\n" ..
            "/* int %s(int p1, int p2, int p3, int p4, int p5, int p6) */\n" ..
            "/* Try: */\n" ..
            "typedef struct { int p1; int p2; int p3; int p4; int p5; int p6; } %s_Config;\n" ..
            "int %s(const %s_Config* cfg) {\n" ..
            "  // use cfg->p1, cfg->p2, ...\n" ..
            "}\n",
            func.name, func.name, func.name, func.name
        ),
        cpp = string.format(
            "// Instead of: int %s(int p1, int p2, int p3, int p4, int p5, int p6)\n" ..
            "// Try object parameter with defaults:\n" ..
            "struct %sConfig { int p1; int p2; int p3 = 0; int p4 = 0; int p5 = 0; int p6 = 0; };\n" ..
            "int %s(const %sConfig& cfg) {\n" ..
            "  // use cfg.p1, cfg.p2, ...\n" ..
            "}\n",
            func.name, func.name, func.name, func.name
        ),
        lua = string.format(
            "-- Instead of: function %s(p1, p2, p3, p4, p5, p6)\n" ..
            "-- Try options table with defaults:\n" ..
            "function %s(opts)\n" ..
            "  opts = opts or {}\n" ..
            "  local p1 = opts.p1 or 0\n" ..
            "  local p2 = opts.p2 or 0\n" ..
            "  -- ...\n" ..
            "end",
            func.name, func.name
        ),
        python = string.format(
            "# Instead of: def %s(p1, p2, p3, p4, p5, p6):\n" ..
            "# Prefer dataclass or keyword-only params:\n" ..
            "from dataclasses import dataclass\n" ..
            "@dataclass\n" ..
            "class %sConfig:\n" ..
            "    p1: int\n" ..
            "    p2: int\n" ..
            "    p3: int | None = None\n" ..
            "    p4: int | None = None\n" ..
            "    p5: int | None = None\n" ..
            "    p6: int | None = None\n" ..
            "def %s(cfg: %sConfig) -> None:\n" ..
            "    # use cfg.p1, cfg.p2, ...\n" ..
            "    pass\n" ..
            "# or\n" ..
            "def %s(*, p1, p2, p3=None, p4=None, p5=None, p6=None):\n" ..
            "    pass",
            func.name, func.name, func.name, func.name, func.name
        ),
        javascript = string.format(
            "// Instead of: function %s(p1, p2, p3, p4, p5, p6) {}\n" ..
            "// Prefer object parameter with destructuring and defaults:\n" ..
            "function %s({ p1, p2, p3 = 0, p4 = 0, p5 = 0, p6 = 0 } = {}) {\n" ..
            "  // use p1, p2, ...\n" ..
            "}\n" ..
            "// or\n" ..
            "function %s(options = {}) {\n" ..
            "  const { p1, p2, p3 = 0, p4 = 0, p5 = 0, p6 = 0 } = options;\n" ..
            "}\n",
            func.name, func.name, func.name
        ),
        go = string.format(
            "// Instead of: func %s(p1, p2, p3, p4, p5, p6 int) {}\n" ..
            "// Prefer a config struct (use value or pointer based on size):\n" ..
            "type %sConfig struct {\n" ..
            "  P1 int\n" ..
            "  P2 int\n" ..
            "  P3 int\n" ..
            "  P4 int\n" ..
            "  P5 int\n" ..
            "  P6 int\n" ..
            "}\n" ..
            "func %s(cfg %sConfig) {\n" ..
            "  // use cfg.P1, cfg.P2, ...\n" ..
            "}\n",
            func.name, func.name, func.name, func.name
        )
    }
    
    return examples[ft] or string.format(
        "Function %s has too many parameters (%d). Group related fields into a config/options object or struct and pass that instead.",
        func.name, func.parameter_count
    )
end

-- Language-specific patterns for code improvement
function M._get_patterns_for_language(ft)
local patterns = {
    lua = {
        {
            regex = "if%s+.+%s+then%s+return%s+.+%s+else%s+return%s+.+%s+end",
            title = "Simplify conditional return",
            description = "This if-else return can be simplified",
            base_confidence = 0.8,
            priority = 3,
            impact = "readability",
            suggestion = "Use a direct return: return cond and val1 or val2 (be careful if val1 can be false/nil)"
        },
        {
            regex = "for%s+[%w_]+%s*=%s*1%s*,%s*#%s*[%w_]+%s*do",
            title = "Use ipairs for array iteration",
            description = "ipairs communicates intent and is idiomatic for sequence iteration",
            base_confidence = 0.75,
            priority = 4,
            impact = "idiom",
            suggestion = "Use: for i, v in ipairs(t) do ... end"
        },
        {
            regex = "%.%.",
            title = "Avoid repeated string concatenation",
            description = "String concatenation in tight loops is slow",
            base_confidence = 0.6,
            priority = 4,
            impact = "performance",
            context_boost = true,
            suggestion = "Accumulate parts and use table.concat(parts) or use string.format for readability"
        },
        {
            regex = "[\"'].-[\"']%s*%..+",
            title = "Prefer string.format over concatenation",
            description = "Formatting improves readability and often performance",
            base_confidence = 0.7,
            priority = 4,
            impact = "readability",
            suggestion = "Use string.format('Hello %s', name) instead of 'Hello ' .. name"
        }
    },

    python = {
        {
            regex = "for%s+[%w_]+%s+in%s+range%s*%(%s*len%s*%(%s*[^%)]+%s*%)%s*%)%s*:",
            title = "Use enumerate instead of range(len())",
            description = "Direct iteration is more Pythonic and readable",
            base_confidence = 0.9,
            priority = 2,
            impact = "idiom",
            suggestion = "Use: for i, item in enumerate(items):"
        },
        {
            regex = "for%s+[%w_,%s]-in%s+[%w_]+%.keys%s*%(%s*%)%s*:",
            title = "Iterate dict directly instead of keys()",
            description = "Iterating a dict yields keys by default",
            base_confidence = 0.85,
            priority = 3,
            impact = "readability",
            suggestion = "Use: for k in d: (or d.items() for key-value pairs)"
        },
        {
            regex = "==%s*None",
            title = "Use 'is None'",
            description = "Identity check is preferred for None",
            base_confidence = 0.9,
            priority = 2,
            impact = "correctness",
            suggestion = "Use: is None"
        },
        {
            regex = "~=%s*None", -- keep from misfire; Lua doesn't support !=, so include alt below
            title = "placeholder",
            description = "placeholder",
            base_confidence = 0.0,
            priority = 9,
            impact = "none",
            suggestion = ""
        },
        {
            regex = "!=%s*None",
            title = "Use 'is not None'",
            description = "Identity check is preferred for None",
            base_confidence = 0.9,
            priority = 2,
            impact = "correctness",
            suggestion = "Use: is not None"
        },
        {
            regex = "[^%w_]open%s*%(",
            title = "Use context manager for files",
            description = "with ensures files are closed even on errors",
            base_confidence = 0.6,
            priority = 3,
            impact = "safety",
            context_boost = true,
            suggestion = "Use: with open(path) as f: ..."
        },
        {
            regex = "[\"'].-[\"']%s*%+%s*[%w_]+",
            title = "Prefer f-strings or format",
            description = "f-strings are clearer and faster",
            base_confidence = 0.8,
            priority = 3,
            impact = "readability",
            suggestion = "Use: f'Hello {name}' or 'Hello {}'.format(name)"
        }
    },

    javascript = {
        {
            regex = "for%s*%(%s*var%s+[%w_]+%s*=%s*0%s*;.-%.length%s*;.-%+%+%s*%)",
            title = "Use for...of or forEach",
            description = "Modern iteration methods are more expressive",
            base_confidence = 0.85,
            priority = 3,
            impact = "modernization",
            suggestion = "Use: for (const item of array) { ... } or array.forEach(item => ...)"
        },
        {
            regex = "var%s+[%w_]+",
            title = "Use const/let instead of var",
            description = "Block-scoped declarations prevent subtle bugs",
            base_confidence = 0.95,
            priority = 2,
            impact = "safety",
            suggestion = "Use const for immutables, let for reassignable variables"
        },
        {
            regex = "==[^=]",
            title = "Use strict equality",
            description = "Avoid coercion with ==/!=",
            base_confidence = 0.85,
            priority = 3,
            impact = "correctness",
            suggestion = "Use === and !=="
        },
        {
            regex = "!=[^=]",
            title = "Use strict inequality",
            description = "Avoid coercion with ==/!=",
            base_confidence = 0.85,
            priority = 3,
            impact = "correctness",
            suggestion = "Use !=="
        },
        {
            regex = "%.indexOf%s*%(",
            title = "Use includes for membership",
            description = "includes is clearer than indexOf(...) !== -1",
            base_confidence = 0.7,
            priority = 4,
            impact = "readability",
            context_boost = true,
            suggestion = "Use: array.includes(value)"
        },
        {
            regex = "[\"'].-[\"']%s*%+%s*[%w_]+",
            title = "Prefer template literals",
            description = "Template literals improve readability",
            base_confidence = 0.8,
            priority = 3,
            impact = "readability",
            suggestion = "Use: `Hello ${name}`"
        }
    },

    typescript = {
        {
            regex = "var%s+[%w_]+",
            title = "Use const/let instead of var",
            description = "Block-scoped declarations prevent subtle bugs",
            base_confidence = 0.95,
            priority = 2,
            impact = "safety",
            suggestion = "Use const for immutables, let for reassignable variables"
        },
        {
            regex = "for%s*%(%s*let%s+[%w_]+%s*=%s*0%s*;.-%.length%s*;.-%+%+%s*%)",
            title = "Use for...of or forEach",
            description = "Modern iteration methods are more expressive",
            base_confidence = 0.85,
            priority = 3,
            impact = "modernization",
            suggestion = "Use: for (const item of array) { ... } or array.forEach(item => ...)"
        },
        {
            regex = "==[^=]",
            title = "Use strict equality",
            description = "Avoid coercion with ==/!=",
            base_confidence = 0.85,
            priority = 3,
            impact = "correctness",
            suggestion = "Use === and !=="
        }
    },

    c = {
        {
            regex = "if%s*%b()%s*return%s+[^;]+;%s*else%s*return%s+[^;]+;",
            title = "Simplify conditional return",
            description = "Replace if-else return with a single expression",
            base_confidence = 0.8,
            priority = 3,
            impact = "readability",
            suggestion = "Use: return cond ? a : b; (or just return cond; when returning booleans)"
        },
        {
            regex = "sprintf%s*%(",
            title = "Prefer snprintf over sprintf",
            description = "snprintf avoids buffer overflows",
            base_confidence = 0.95,
            priority = 2,
            impact = "safety",
            suggestion = "Use snprintf(buffer, size, ...)"
        },
        {
            regex = "strcpy%s*%(",
            title = "Prefer strncpy/strlcpy over strcpy",
            description = "Bounded copies are safer",
            base_confidence = 0.9,
            priority = 2,
            impact = "safety",
            suggestion = "Use strncpy or strlcpy with proper bounds"
        }
    },

    cpp = {
        {
            regex = "for%s*%(%s*[%w_:]+%s+[%w_]+%s*=%s*0%s*;.-<%s*[%w_:]+%.size%s*%(%s*%)%s*;.-%+%+%s*%)",
            title = "Use range-based for loop",
            description = "Range-based for loops are safer and clearer",
            base_confidence = 0.85,
            priority = 3,
            impact = "modernization",
            suggestion = "Use: for (auto& x : container) { ... }"
        },
        {
            regex = "NULL",
            title = "Use nullptr instead of NULL",
            description = "nullptr is type-safe and preferred in C++",
            base_confidence = 0.95,
            priority = 2,
            impact = "modernization",
            suggestion = "Replace NULL with nullptr"
        },
        {
            regex = "std::endl",
            title = "Avoid std::endl",
            description = "std::endl flushes the stream and can hurt performance",
            base_confidence = 0.85,
            priority = 4,
            impact = "performance",
            suggestion = "Use '\\n' for newlines unless flushing is required"
        },
        {
            regex = "push_back%s*%(%s*[%w_:]+%s*%b()%s*%)",
            title = "Prefer emplace_back",
            description = "Avoids temporary objects and can be more efficient",
            base_confidence = 0.8,
            priority = 4,
            impact = "performance",
            suggestion = "Use emplace_back with constructor arguments"
        }
    },

    go = {
        {
            regex = "for%s+[%w_,%s]-:=%s*0%s*;%s*[%w_]+%s*<%s*len%s*%(%s*[%w_]+%s*%)%s*;%s*[%w_]+%s*%+%+%s*%)",
            title = "Use range over index-based loop",
            description = "range is idiomatic and less error-prone",
            base_confidence = 0.9,
            priority = 2,
            impact = "idiom",
            suggestion = "Use: for i, v := range slice { ... }"
        },
        {
            regex = "fmt%.Errorf%s*%(%s*\".-%%v.-\"%s*,%s*err%s*%)",
            title = "Wrap errors with %w",
            description = "Use %w to wrap the underlying error",
            base_confidence = 0.85,
            priority = 3,
            impact = "maintainability",
            suggestion = "Use: fmt.Errorf(\"context: %w\", err)"
        },
        {
            regex = "[%w_]+%s*%+%=%s*\".-\"",
            title = "Avoid string += in loops",
            description = "Use strings.Builder for efficient string building",
            base_confidence = 0.6,
            priority = 4,
            impact = "performance",
            context_boost = true,
            suggestion = "Use strings.Builder with WriteString and builder.String()"
        },
        {
            regex = "make%s*%(%s*%[%]%w+%s*,%s*0%s*%)",
            title = "Inefficient slice initialization",
            description = "Creating slice with zero length but no capacity",
            base_confidence = 0.7,
            priority = 3,
            impact = "performance",
            suggestion = "Use: make([]Type, 0, expectedSize) to pre-allocate capacity"
        },
        {
            regex = "append%s*%(%s*[%w_]+%s*,%s*[%w_]+%s*%[:%s*%]%s*%.%.%.%s*%)",
            title = "Inefficient slice append",
            description = "Appending entire slice can be optimized",
            base_confidence = 0.8,
            priority = 3,
            impact = "performance",
            suggestion = "Consider copy() for better performance with large slices"
        },
        {
            regex = "json%.Marshal%s*%(%s*[%w_]+%s*%)",
            title = "Repeated JSON marshaling",
            description = "Cache marshaled JSON if data doesn't change frequently",
            base_confidence = 0.5,
            priority = 4,
            impact = "performance",
            context_boost = true,
            suggestion = "Consider caching JSON output or using json.RawMessage"
        },
        {
            regex = "regexp%.MustCompile%s*%(%s*\"",
            title = "Repeated regex compilation",
            description = "Compile regex once and reuse",
            base_confidence = 0.9,
            priority = 2,
            impact = "performance",
            suggestion = "Move regex compilation to package level or use sync.Once"
        },
        {
            regex = "time%.Sleep%s*%(%s*[%d]+%s*%*%s*time%.",
            title = "Blocking sleep",
            description = "Consider using context with timeout instead",
            base_confidence = 0.6,
            priority = 3,
            impact = "concurrency",
            suggestion = "Use: ctx, cancel := context.WithTimeout(); select { case <-ctx.Done(): }"
        },
        {
            regex = "sync%.Mutex.*Lock%s*%(%s*%).*defer.*Unlock",
            title = "Consider RWMutex for read-heavy operations",
            description = "RWMutex allows concurrent reads",
            base_confidence = 0.4,
            priority = 4,
            impact = "performance",
            context_boost = true,
            suggestion = "Use sync.RWMutex if reads are more frequent than writes"
        }
    }
}
  
  return patterns[ft] or {}
end

-- Security upgrade patterns
function M._get_security_upgrade_patterns(ft)
local patterns = {
    c = {
        {
            regex = "strcpy%s*%(",
            title = "Unsafe string copy",
            description = "strcpy can lead to buffer overflows",
            confidence = 0.95,
            cwe = "CWE-120",
            upgrade_suggestion = "Use strncpy or strlcpy with proper bounds",
            replacement = "strncpy"
        },
        {
            regex = "strcat%s*%(",
            title = "Unsafe string concatenation",
            description = "strcat can overflow destination buffer",
            confidence = 0.95,
            cwe = "CWE-120",
            upgrade_suggestion = "Use strncat or strlcat with proper bounds",
            replacement = "strncat"
        },
        {
            regex = "sprintf%s*%(",
            title = "Unsafe formatted output",
            description = "sprintf does not limit output size and can overflow buffers",
            confidence = 0.95,
            cwe = "CWE-120",
            upgrade_suggestion = "Use snprintf with the destination buffer size",
            replacement = "snprintf"
        },
        {
            regex = "gets%s*%(",
            title = "Obsolete and unsafe input",
            description = "gets cannot limit input size and is inherently unsafe",
            confidence = 0.98,
            cwe = "CWE-242",
            upgrade_suggestion = "Use fgets with buffer size limits",
            replacement = "fgets"
        },
        {
            regex = "scanf%s*%(%s*\"[^\"\n]*%%s[^\"\n]*\"",
            title = "Unsafe scanf usage",
            description = "Using %s without field width can overflow buffers",
            confidence = 0.85,
            cwe = "CWE-120",
            upgrade_suggestion = "Specify a maximum field width or use fgets",
            replacement = "fgets"
        },
        {
            regex = "system%s*%(",
            title = "OS command injection risk",
            description = "system executes a shell which can be exploited if inputs are untrusted",
            confidence = 0.9,
            cwe = "CWE-78",
            upgrade_suggestion = "Avoid system; use execve with validated args or dedicated APIs",
            replacement = "execve"
        },
        {
            regex = "popen%s*%(",
            title = "OS command injection risk",
            description = "popen spawns a shell; unsafe with untrusted input",
            confidence = 0.9,
            cwe = "CWE-78",
            upgrade_suggestion = "Avoid shell; use exec family with argument array",
            replacement = "execve"
        },
        {
            regex = "[^_%w]rand%s*%(",
            title = "Insecure random generator",
            description = "rand is not cryptographically secure",
            confidence = 0.85,
            cwe = "CWE-330",
            upgrade_suggestion = "Use getrandom/arc4random or a CSPRNG",
            replacement = "arc4random"
        },
        {
            regex = "mktemp%s*%(",
            title = "Insecure temporary file creation",
            description = "mktemp is race-prone",
            confidence = 0.9,
            cwe = "CWE-377",
            upgrade_suggestion = "Use mkstemp which returns an open file descriptor",
            replacement = "mkstemp"
        }
    },

    cpp = {
        {
            regex = "strcpy%s*%(",
            title = "Unsafe string copy",
            description = "strcpy can lead to buffer overflows",
            confidence = 0.95,
            cwe = "CWE-120",
            upgrade_suggestion = "Use std::string or strncpy/strlcpy with bounds",
            replacement = "std::string"
        },
        {
            regex = "strcat%s*%(",
            title = "Unsafe string concatenation",
            description = "strcat can overflow destination buffer",
            confidence = 0.95,
            cwe = "CWE-120",
            upgrade_suggestion = "Use std::string or strncat/strlcat",
            replacement = "std::string"
        },
        {
            regex = "sprintf%s*%(",
            title = "Unsafe formatted output",
            description = "sprintf can overflow buffers",
            confidence = 0.95,
            cwe = "CWE-120",
            upgrade_suggestion = "Use snprintf or std::snprintf with buffer size",
            replacement = "snprintf"
        },
        {
            regex = "system%s*%(",
            title = "OS command injection risk",
            description = "system invokes a shell; unsafe with untrusted input",
            confidence = 0.9,
            cwe = "CWE-78",
            upgrade_suggestion = "Use execvp/execve or platform APIs with sanitized args",
            replacement = "execvp"
        },
        {
            regex = "popen%s*%(",
            title = "OS command injection risk",
            description = "popen spawns a shell; unsafe with untrusted input",
            confidence = 0.9,
            cwe = "CWE-78",
            upgrade_suggestion = "Avoid shell; use process APIs and argument arrays",
            replacement = "exec"
        },
        {
            regex = "[^_%w]rand%s*%(",
            title = "Insecure random generator",
            description = "rand is not cryptographically secure",
            confidence = 0.85,
            cwe = "CWE-330",
            upgrade_suggestion = "Use std::random_device or OS CSPRNG for secrets",
            replacement = "std::random_device"
        }
    },

    lua = {
        {
            regex = "loadstring%s*%(",
            title = "Arbitrary code execution",
            description = "loadstring can execute untrusted code",
            confidence = 0.95,
            cwe = "CWE-94",
            upgrade_suggestion = "Avoid dynamic code execution or strictly sandbox it",
            replacement = "-- avoid loadstring"
        },
        {
            regex = "[^_%w]load%s*%(",
            title = "Arbitrary code execution",
            description = "load can execute untrusted code",
            confidence = 0.95,
            cwe = "CWE-94",
            upgrade_suggestion = "Avoid load with untrusted input; consider sandboxing",
            replacement = "-- avoid load"
        },
        {
            regex = "dofile%s*%(",
            title = "Untrusted file execution",
            description = "dofile executes file content",
            confidence = 0.9,
            cwe = "CWE-94",
            upgrade_suggestion = "Avoid executing untrusted files; parse data instead",
            replacement = "-- avoid dofile"
        },
        {
            regex = "os%.execute%s*%(",
            title = "OS command injection risk",
            description = "os.execute invokes a shell",
            confidence = 0.9,
            cwe = "CWE-78",
            upgrade_suggestion = "Avoid shell; use dedicated APIs and validate inputs",
            replacement = "-- avoid os.execute"
        },
        {
            regex = "io%.popen%s*%(",
            title = "OS command injection risk",
            description = "io.popen spawns a shell",
            confidence = 0.9,
            cwe = "CWE-78",
            upgrade_suggestion = "Avoid shell commands; use safe APIs",
            replacement = "-- avoid io.popen"
        },
        {
            regex = "math%.random%s*%(",
            title = "Insecure random for secrets",
            description = "math.random is not cryptographically secure",
            confidence = 0.85,
            cwe = "CWE-330",
            upgrade_suggestion = "Use an OS CSPRNG via FFI or external lib for secrets",
            replacement = "-- use CSPRNG"
        }
    },

    python = {
        {
            regex = "pickle%.loads?%s*%(",
            title = "Unsafe deserialization",
            description = "pickle.load/loads can execute arbitrary code",
            confidence = 0.98,
            cwe = "CWE-502",
            upgrade_suggestion = "Use json or safe, schema-validated formats",
            replacement = "json.loads"
        },
        {
            regex = "yaml%.load%s*%(",
            title = "Unsafe YAML load",
            description = "yaml.load without SafeLoader can execute arbitrary code",
            confidence = 0.95,
            cwe = "CWE-502",
            upgrade_suggestion = "Use yaml.safe_load",
            replacement = "yaml.safe_load"
        },
        {
            regex = "subprocess%.[Pp]open[^)]-shell%s*=%s*True[^)]*%)+",
            title = "Shell injection vulnerability",
            description = "shell=True enables shell injection attacks",
            confidence = 0.9,
            cwe = "CWE-78",
            upgrade_suggestion = "Use shell=False and pass arguments as a list",
            replacement = "subprocess.run([...], shell=False)"
        },
        {
            regex = "subprocess%.[Rr]un[^)]-shell%s*=%s*True[^)]*%)+",
            title = "Shell injection vulnerability",
            description = "shell=True enables shell injection attacks",
            confidence = 0.9,
            cwe = "CWE-78",
            upgrade_suggestion = "Use shell=False and pass arguments as a list",
            replacement = "subprocess.run([...], shell=False)"
        },
        {
            regex = "os%.system%s*%(",
            title = "OS command injection risk",
            description = "os.system invokes a shell",
            confidence = 0.9,
            cwe = "CWE-78",
            upgrade_suggestion = "Use subprocess.run([...], shell=False) with validated args",
            replacement = "subprocess.run([...], shell=False)"
        },
        {
            regex = "[^_%w]eval%s*%(",
            title = "Arbitrary code execution",
            description = "eval can execute untrusted code",
            confidence = 0.95,
            cwe = "CWE-94",
            upgrade_suggestion = "Avoid eval; use ast.literal_eval for simple data",
            replacement = "ast.literal_eval"
        },
        {
            regex = "[^_%w]exec%s*%(",
            title = "Arbitrary code execution",
            description = "exec can execute untrusted code",
            confidence = 0.95,
            cwe = "CWE-94",
            upgrade_suggestion = "Avoid exec; refactor to safer alternatives",
            replacement = "# avoid exec"
        },
        {
            regex = "requests%.[%w_]+%s*%([^)]-verify%s*=%s*False[^)]*%)",
            title = "TLS certificate verification disabled",
            description = "Disabling verification exposes to MITM attacks",
            confidence = 0.9,
            cwe = "CWE-295",
            upgrade_suggestion = "Enable certificate verification or provide cert bundle",
            replacement = "verify=True"
        },
        {
            regex = "hashlib%.md5%s*%(",
            title = "Weak hash algorithm",
            description = "MD5 is cryptographically broken",
            confidence = 0.95,
            cwe = "CWE-327",
            upgrade_suggestion = "Use SHA-256 or stronger, preferably with HMAC",
            replacement = "hashlib.sha256"
        },
        {
            regex = "hashlib%.sha1%s*%(",
            title = "Weak hash algorithm",
            description = "SHA-1 is deprecated",
            confidence = 0.95,
            cwe = "CWE-327",
            upgrade_suggestion = "Use SHA-256 or stronger, preferably with HMAC",
            replacement = "hashlib.sha256"
        },
        {
            regex = "random%.[%w_]+%s*%(",
            title = "Insecure random for secrets",
            description = "random module is not cryptographically secure",
            confidence = 0.9,
            cwe = "CWE-330",
            upgrade_suggestion = "Use secrets module for tokens and passwords",
            replacement = "secrets.token_hex"
        },
        {
            regex = "tempfile%.mktemp%s*%(",
            title = "Insecure temporary file creation",
            description = "mktemp is race-prone and unsafe",
            confidence = 0.95,
            cwe = "CWE-377",
            upgrade_suggestion = "Use NamedTemporaryFile or mkstemp",
            replacement = "tempfile.NamedTemporaryFile"
        },
        {
            regex = "app%.run%([^)]-debug%s*=%s*True[^)]*%)",
            title = "Debug mode enabled in production",
            description = "Flask debug exposes code execution endpoints",
            confidence = 0.85,
            cwe = "CWE-489",
            upgrade_suggestion = "Disable debug in production",
            replacement = "debug=False"
        }
    },

    javascript = {
        {
            regex = "eval%s*%(",
            title = "Code injection vulnerability",
            description = "eval can execute arbitrary code",
            confidence = 0.98,
            cwe = "CWE-94",
            upgrade_suggestion = "Avoid eval; use JSON.parse for data or safe interpreters",
            replacement = "JSON.parse"
        },
        {
            regex = "new%s+Function%s*%(",
            title = "Code injection vulnerability",
            description = "Function constructor evaluates strings as code",
            confidence = 0.95,
            cwe = "CWE-94",
            upgrade_suggestion = "Avoid dynamic code generation",
            replacement = "// avoid Function constructor"
        },
        {
            regex = "Function%s*%(",
            title = "Code injection vulnerability",
            description = "Function constructor evaluates strings as code",
            confidence = 0.9,
            cwe = "CWE-94",
            upgrade_suggestion = "Avoid dynamic code generation",
            replacement = "// avoid Function constructor"
        },
        {
            regex = "setTimeout%s*%(%s*[\"']",
            title = "String-based setTimeout",
            description = "Passing a string executes it like eval",
            confidence = 0.9,
            cwe = "CWE-94",
            upgrade_suggestion = "Pass a function callback instead of a string",
            replacement = "setTimeout(() => ...)"
        },
        {
            regex = "setInterval%s*%(%s*[\"']",
            title = "String-based setInterval",
            description = "Passing a string executes it like eval",
            confidence = 0.9,
            cwe = "CWE-94",
            upgrade_suggestion = "Pass a function callback instead of a string",
            replacement = "setInterval(() => ...)"
        },
        {
            regex = "document%.write%s*%(",
            title = "Potential XSS sink",
            description = "document.write can introduce XSS",
            confidence = 0.85,
            cwe = "CWE-79",
            upgrade_suggestion = "Avoid document.write; manipulate DOM safely",
            replacement = "// avoid document.write"
        },
        {
            regex = "innerHTML%s*=",
            title = "XSS vulnerability",
            description = "innerHTML can execute malicious scripts",
            confidence = 0.9,
            cwe = "CWE-79",
            upgrade_suggestion = "Use textContent or sanitize HTML",
            replacement = "textContent ="
        },
        {
            regex = "outerHTML%s*=",
            title = "XSS vulnerability",
            description = "outerHTML can execute malicious scripts",
            confidence = 0.85,
            cwe = "CWE-79",
            upgrade_suggestion = "Use textContent or sanitize HTML",
            replacement = "textContent ="
        },
        {
            regex = "child_process%.exec%s*%(",
            title = "OS command injection risk",
            description = "exec spawns a shell; vulnerable to injection",
            confidence = 0.9,
            cwe = "CWE-78",
            upgrade_suggestion = "Use execFile/spawn with argument arrays",
            replacement = "child_process.execFile"
        },
        {
            regex = "child_process%.execSync%s*%(",
            title = "OS command injection risk",
            description = "execSync spawns a shell; vulnerable to injection",
            confidence = 0.9,
            cwe = "CWE-78",
            upgrade_suggestion = "Use execFileSync/spawnSync with args",
            replacement = "child_process.execFileSync"
        },
        {
            regex = "crypto%.createHash%s*%(%s*[\"']md5[\"']%s*%)",
            title = "Weak hash algorithm",
            description = "MD5 is cryptographically broken",
            confidence = 0.95,
            cwe = "CWE-327",
            upgrade_suggestion = "Use SHA-256 or stronger",
            replacement = "crypto.createHash('sha256')"
        },
        {
            regex = "crypto%.createHash%s*%(%s*[\"']sha1[\"']%s*%)",
            title = "Weak hash algorithm",
            description = "SHA-1 is deprecated",
            confidence = 0.95,
            cwe = "CWE-327",
            upgrade_suggestion = "Use SHA-256 or stronger",
            replacement = "crypto.createHash('sha256')"
        }
    },

    typescript = {
        {
            regex = "eval%s*%(",
            title = "Code injection vulnerability",
            description = "eval can execute arbitrary code",
            confidence = 0.98,
            cwe = "CWE-94",
            upgrade_suggestion = "Avoid eval; use JSON.parse for data or safe interpreters",
            replacement = "JSON.parse"
        },
        {
            regex = "new%s+Function%s*%(",
            title = "Code injection vulnerability",
            description = "Function constructor evaluates strings as code",
            confidence = 0.95,
            cwe = "CWE-94",
            upgrade_suggestion = "Avoid dynamic code generation",
            replacement = "// avoid Function constructor"
        },
        {
            regex = "setTimeout%s*%(%s*[\"']",
            title = "String-based setTimeout",
            description = "Passing a string executes it like eval",
            confidence = 0.9,
            cwe = "CWE-94",
            upgrade_suggestion = "Pass a function callback instead of a string",
            replacement = "setTimeout(() => ...)"
        },
        {
            regex = "setInterval%s*%(%s*[\"']",
            title = "String-based setInterval",
            description = "Passing a string executes it like eval",
            confidence = 0.9,
            cwe = "CWE-94",
            upgrade_suggestion = "Pass a function callback instead of a string",
            replacement = "setInterval(() => ...)"
        },
        {
            regex = "innerHTML%s*=",
            title = "XSS vulnerability",
            description = "innerHTML can execute malicious scripts",
            confidence = 0.9,
            cwe = "CWE-79",
            upgrade_suggestion = "Use textContent or sanitize HTML",
            replacement = "textContent ="
        },
        {
            regex = "child_process%.exec%s*%(",
            title = "OS command injection risk",
            description = "exec spawns a shell; vulnerable to injection",
            confidence = 0.9,
            cwe = "CWE-78",
            upgrade_suggestion = "Use execFile/spawn with argument arrays",
            replacement = "child_process.execFile"
        }
    },

    go = {
        {
            regex = "tls%.Config%b{%s*[^}]-InsecureSkipVerify%s*:%s*true",
            title = "TLS verification disabled",
            description = "Disabling certificate verification exposes to MITM",
            confidence = 0.95,
            cwe = "CWE-295",
            upgrade_suggestion = "Set InsecureSkipVerify to false and use proper roots",
            replacement = "InsecureSkipVerify: false"
        },
        {
            regex = "exec%.Command%s*%(%s*\"sh\"%s*,%s*\"-c\"",
            title = "OS command injection risk",
            description = "Shell command execution is vulnerable to injection",
            confidence = 0.9,
            cwe = "CWE-78",
            upgrade_suggestion = "Avoid shell; use exec.Command with explicit args",
            replacement = "exec.Command(name, arg1, arg2)"
        },
        {
            regex = "[^_%w]md5%s*%.%s*[Nn]ew%s*%(",
            title = "Weak hash algorithm",
            description = "MD5 is cryptographically broken",
            confidence = 0.95,
            cwe = "CWE-327",
            upgrade_suggestion = "Use SHA-256 or stronger (crypto/sha256)",
            replacement = "sha256.New"
        },
        {
            regex = "[^_%w]sha1%s*%.%s*[Nn]ew%s*%(",
            title = "Weak hash algorithm",
            description = "SHA-1 is deprecated",
            confidence = 0.95,
            cwe = "CWE-327",
            upgrade_suggestion = "Use SHA-256 or stronger (crypto/sha256)",
            replacement = "sha256.New"
        },
        {
            regex = "[^_%w]rand%s*%.%s*Intn%s*%(",
            title = "Insecure random for secrets",
            description = "math/rand is not cryptographically secure",
            confidence = 0.8,
            cwe = "CWE-338",
            upgrade_suggestion = "Use crypto/rand for cryptographic purposes",
            replacement = "rand.Read (crypto/rand)"
        },
        {
            regex = "sql%.Query%s*%(%s*\".-\"%s*%+",
            title = "SQL injection vulnerability",
            description = "String concatenation in SQL queries allows injection",
            confidence = 0.9,
            cwe = "CWE-89",
            upgrade_suggestion = "Use parameterized queries with placeholders",
            replacement = "db.Query(\"SELECT * FROM table WHERE id = ?\", userID)"
        },
        {
            regex = "sql%.Exec%s*%(%s*\".-\"%s*%+",
            title = "SQL injection vulnerability",
            description = "String concatenation in SQL queries allows injection",
            confidence = 0.9,
            cwe = "CWE-89",
            upgrade_suggestion = "Use parameterized queries with placeholders",
            replacement = "db.Exec(\"UPDATE table SET value = ? WHERE id = ?\", newValue, userID)"
        },
        {
            regex = "template%.HTML%s*%(%s*[%w_]+%s*%)",
            title = "XSS vulnerability",
            description = "template.HTML bypasses auto-escaping",
            confidence = 0.85,
            cwe = "CWE-79",
            upgrade_suggestion = "Ensure input is properly sanitized or use text/template",
            replacement = "html.EscapeString(userInput)"
        },
        {
            regex = "http%.ListenAndServe%s*%(%s*\"[^:]*:80",
            title = "Unencrypted HTTP server",
            description = "HTTP traffic is unencrypted",
            confidence = 0.8,
            cwe = "CWE-319",
            upgrade_suggestion = "Use HTTPS with ListenAndServeTLS",
            replacement = "http.ListenAndServeTLS(\":443\", \"cert.pem\", \"key.pem\", handler)"
        },
        {
            regex = "ioutil%.WriteFile%s*%([^,]*,%s*[^,]*,%s*0777",
            title = "Overly permissive file permissions",
            description = "0777 allows read/write/execute for all users",
            confidence = 0.9,
            cwe = "CWE-732",
            upgrade_suggestion = "Use more restrictive permissions like 0644 or 0600",
            replacement = "0644"
        },
        {
            regex = "unsafe%.Pointer%s*%(",
            title = "Memory safety bypass",
            description = "unsafe.Pointer bypasses Go's type safety",
            confidence = 0.7,
            cwe = "CWE-119",
            upgrade_suggestion = "Use type-safe alternatives when possible",
            replacement = "// Consider type-safe alternatives"
        },
        {
            regex = "log%.Printf%s*%([^,]*,%s*[%w_]*[Pp]assword",
            title = "Password logged",
            description = "Passwords should not be logged",
            confidence = 0.85,
            cwe = "CWE-532",
            upgrade_suggestion = "Remove password from logs or mask it",
            replacement = "log.Printf(\"User: %s, Password: [REDACTED]\", user)"
        },
        {
            regex = "time%.Sleep%s*%(%s*[%d]+%s*%*%s*time%.Second%s*%)",
            title = "Potential DoS vector",
            description = "Long sleep times can be abused for DoS",
            confidence = 0.4,
            cwe = "CWE-400",
            upgrade_suggestion = "Use context with timeout for cancellation",
            replacement = "ctx, cancel := context.WithTimeout(ctx, duration)"
        },
        {
          regex = "crypto%.RandBytes%s*%(%s*[%d]+%s*%)",
          title = "Insecure random number generation",
          description = "crypto/rand should be used for cryptographic purposes",
          confidence = 0.9,
          cwe = "CWE-330",
          upgrade_suggestion = "Use crypto/rand for secret generation",
          replacement = "crypto/rand"
        }
    },
}
  
  return patterns[ft] or {}
end

-- Performance optimization patterns
function M._get_performance_patterns(ft)
local patterns = {
    c = {
        {
            regex = "strcat%s*%(",
            title = "Inefficient string concatenation",
            description = "Using strcat repeatedly (especially in loops) causes repeated scans and reallocations",
            confidence = 0.7,
            optimization = "Track buffer size and use snprintf/strncat with an index; preallocate once",
            replacement = "snprintf/strncat"
        },
        {
            regex = "sprintf%s*%(",
            title = "Expensive formatting in hot path",
            description = "sprintf is relatively slow and unsafe; repeated use in loops hurts performance",
            confidence = 0.65,
            optimization = "Use snprintf with a preallocated buffer or incremental writes",
            replacement = "snprintf"
        },
        {
            regex = "printf%s*%(",
            title = "I/O inside tight loop",
            description = "Printing inside loops flushes/locks frequently and is slow",
            confidence = 0.6,
            optimization = "Accumulate into a buffer and write once or use batched I/O",
            replacement = "buffered write"
        },
        {
            regex = "[^_%w]malloc%s*%(",
            title = "Heap allocation in loop",
            description = "Frequent malloc/free in loops is costly and fragments memory",
            confidence = 0.7,
            optimization = "Reuse objects or allocate outside the loop",
            replacement = "object reuse"
        },
        {
            regex = "for%s*%([^;]-;[^;]-strlen%s*%(",
            title = "strlen in loop condition",
            description = "strlen scans the string each iteration",
            confidence = 0.85,
            optimization = "Cache the length before the loop",
            replacement = "precompute length"
        },
        {
            regex = "%f[%w_]pow%s*%(",
            title = "pow in loop",
            description = "pow is expensive for integer powers",
            confidence = 0.75,
            optimization = "Use repeated multiplication or specialized fast paths",
            replacement = "x*x or fast pow"
        }
    },

    cpp = {
        {
            regex = "%.push_back%s*%(",
            title = "push_back without reserve",
            description = "Repeated growth of vectors reallocates and copies elements",
            confidence = 0.7,
            optimization = "Call reserve(n) before pushing in a loop",
            replacement = "vector.reserve(n)"
        },
        {
            regex = "std::endl",
            title = "Unnecessary stream flush",
            description = "std::endl forces a flush and is slow in hot paths",
            confidence = 0.8,
            optimization = "Use '\\n' and flush only if needed",
            replacement = "'\\n'"
        },
        {
            regex = "%+%=%s*[\"']",
            title = "String += in loop",
            description = "Repeated appends trigger reallocations and copies",
            confidence = 0.7,
            optimization = "Use std::string::reserve or std::ostringstream",
            replacement = "reserve()/ostringstream"
        },
        {
            regex = "std::stringstream",
            title = "Use ostringstream for building strings",
            description = "stringstream sync and dual-role add overhead",
            confidence = 0.6,
            optimization = "Prefer std::ostringstream for output-only",
            replacement = "std::ostringstream"
        },
        {
            regex = "new%s+std::regex%f[%W]",
            title = "Regex compilation in loop",
            description = "Compiling regex repeatedly is expensive",
            confidence = 0.75,
            optimization = "Precompile once (static/const) and reuse",
            replacement = "static std::regex"
        }
    },

    lua = {
        {
            regex = "%.%.",
            title = "String concatenation in hot path",
            description = "Repeated concatenation creates new strings and copies",
            confidence = 0.6,
            optimization = "Accumulate parts in a table and use table.concat",
            replacement = "table.concat"
        },
        {
            regex = "table%.insert%s*%(",
            title = "table.insert in tight loop",
            description = "Function call overhead each iteration",
            confidence = 0.6,
            optimization = "Use t[#t+1] = v and preallocate when possible",
            replacement = "t[#t+1] = v"
        },
        {
            regex = "pairs%s*%(",
            title = "pairs on sequences",
            description = "pairs over array-like tables is slower than numeric for",
            confidence = 0.6,
            optimization = "Use for i = 1, #t do for array-like tables",
            replacement = "for i=1,#t do"
        },
        {
            regex = "string%.format%s*%(",
            title = "Formatting in loop",
            description = "Formatting per-iteration adds overhead",
            confidence = 0.6,
            optimization = "Use table.concat or precompute templates",
            replacement = "table.concat/precompute"
        }
    },

    python = {
        {
            regex = "%+%=%s*[\"']",
            title = "String += in loop",
            description = "Strings are immutable; += creates a new string each time",
            confidence = 0.85,
            optimization = "Accumulate into a list and ''.join(list) once",
            replacement = "''.join(...)"
        },
        {
            regex = "%+%=%s*%[",
            title = "List += inside loop",
            description = "Creates intermediate lists and copies",
            confidence = 0.8,
            optimization = "Use list.extend(iterable)",
            replacement = ".extend(...)"
        },
        {
            regex = "len%s*%(%s*%[.-for.-in.-%]%s*%)",
            title = "List comp only for length",
            description = "Creates a temporary list just to get its size",
            confidence = 0.9,
            optimization = "Use sum(1 for _ in iterable)",
            replacement = "sum(1 for _ in ...)"
        },
        {
            regex = "re%.compile%s*%(",
            title = "Regex compilation in loop",
            description = "Compiling regex each time is expensive",
            confidence = 0.7,
            optimization = "Precompile once and reuse",
            replacement = "compiled_re = re.compile(...)"
        },
        {
            regex = "sorted%s*%(",
            title = "Sorting in hot path",
            description = "Sorting repeatedly inside loops is costly",
            confidence = 0.6,
            optimization = "Move sort outside the loop or use heapq for partial order",
            replacement = "heapq/one-time sort"
        }
    },

    javascript = {
        {
            regex = "innerHTML%s*%+=",
            title = "innerHTML += in loop",
            description = "Reparses and reflows the DOM on each assignment",
            confidence = 0.85,
            optimization = "Build once and assign, or use DocumentFragment",
            replacement = "DocumentFragment"
        },
        {
            regex = "document%.getElementById%s*%(",
            title = "Repeated DOM queries",
            description = "Querying DOM repeatedly is slow",
            confidence = 0.65,
            optimization = "Cache element references outside loops",
            replacement = "const el = ..."
        },
        {
            regex = "querySelector%a*%s*%(",
            title = "Repeated DOM queries",
            description = "Selector queries are relatively expensive",
            confidence = 0.65,
            optimization = "Cache references or narrow scope",
            replacement = "cache element"
        },
        {
            regex = "getBoundingClientRect%s*%(",
            title = "Layout thrashing risk",
            description = "Frequent layout reads can force reflow",
            confidence = 0.6,
            optimization = "Batch reads/writes; use requestAnimationFrame",
            replacement = "rAF + batching"
        },
        {
            regex = "new%s+RegExp%s*%(",
            title = "Regex compilation in loop",
            description = "Compiling regex repeatedly is expensive",
            confidence = 0.75,
            optimization = "Use literal /.../ or cache RegExp instance",
            replacement = "cached RegExp"
        },
        {
            regex = "JSON%.parse%s*%(%s*JSON%.stringify",
            title = "Expensive deep clone",
            description = "parse/stringify is slow and lossy",
            confidence = 0.8,
            optimization = "Use structuredClone or optimized clone utils",
            replacement = "structuredClone(...)"
        }
    },

    typescript = {
        {
            regex = "innerHTML%s*%+=",
            title = "innerHTML += in loop",
            description = "Reparses and reflows the DOM on each assignment",
            confidence = 0.85,
            optimization = "Build once and assign, or use DocumentFragment",
            replacement = "DocumentFragment"
        },
        {
            regex = "new%s+RegExp%s*%(",
            title = "Regex compilation in loop",
            description = "Compiling regex repeatedly is expensive",
            confidence = 0.75,
            optimization = "Use literal /.../ or cache RegExp instance",
            replacement = "cached RegExp"
        },
        {
            regex = "JSON%.parse%s*%(%s*JSON%.stringify",
            title = "Expensive deep clone",
            description = "parse/stringify is slow and lossy",
            confidence = 0.8,
            optimization = "Use structuredClone or optimized clone utils",
            replacement = "structuredClone(...)"
        }
    },

    go = {
        {
            regex = "fmt%.Sprintf%s*%(",
            title = "Formatting in hot path",
            description = "fmt creates allocations and is slow in loops",
            confidence = 0.75,
            optimization = "Use strings.Builder or bytes.Buffer and preallocate",
            replacement = "strings.Builder"
        },
        {
            regex = "fmt%.[Pp]rint[fln]?%s*%(",
            title = "I/O inside tight loop",
            description = "Printing each iteration is slow",
            confidence = 0.65,
            optimization = "Buffer output and flush once after the loop",
            replacement = "buffered write"
        },
        {
            regex = "[%w_]+%s*=%s*[%w_]+%s*%+%s*[\"']",
            title = "String concatenation in loop",
            description = "Building strings with + allocates",
            confidence = 0.65,
            optimization = "Use strings.Builder with Grow and WriteString",
            replacement = "strings.Builder"
        },
        {
            regex = "regexp%.[Cc]ompile%s*%(",
            title = "Regex compilation in loop",
            description = "Compiling regex repeatedly is expensive",
            confidence = 0.7,
            optimization = "Precompile with MustCompile and reuse",
            replacement = "regexp.MustCompile"
        },
        {
            regex = "regexp%.[Mm]ust[Cc]ompile%s*%(",
            title = "Regex compilation in hot path",
            description = "Even MustCompile should be done once, not per-iteration",
            confidence = 0.65,
            optimization = "Move compile outside the loop and reuse",
            replacement = "precompiled regexp"
        },
        {
            regex = "defer%s+[%w_%.:]+%s*%(",
            title = "defer in loop",
            description = "defer has per-iteration overhead and delays cleanup",
            confidence = 0.8,
            optimization = "Call directly in the loop or refactor to avoid defer",
            replacement = "direct call"
        }
    }
}
  
  return patterns[ft] or {}
end

-- Check if line is in a loop context
function M._is_in_loop(bufnr, line_nr, ft)
  local utils = require('traceback.lenses.utils')
  
  if not utils.ts_available(bufnr, { treesitter = true }) then
    return false
  end
  
  local loop_queries = {
    c = "[(while_statement) (for_statement) (do_statement)] @loop",
    cpp = "[(while_statement) (for_statement) (do_statement)] @loop",
    lua = "[(while_statement) (for_statement) (repeat_statement)] @loop",
    python = "[(while_statement) (for_statement)] @loop",
    javascript = "[(while_statement) (for_statement) (for_in_statement)] @loop",
    go = "[(while_statement) (for_statement)] @loop",
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

-- Context boost calculation for pattern confidence
function M._calculate_context_boost(bufnr, line_nr, pattern)
  -- Implement context-aware confidence boosting
  -- This could analyze surrounding code, variable names, function context, etc.
  local boost = 0
  
  -- Simple heuristics for now
  local line = api.nvim_buf_get_lines(bufnr, line_nr - 1, line_nr, false)[1]
  if not line then return boost end
  
  -- Boost confidence if in a function with many similar patterns
  local surrounding_lines = api.nvim_buf_get_lines(bufnr, 
    math.max(0, line_nr - 5), 
    math.min(api.nvim_buf_line_count(bufnr), line_nr + 5), 
    false)
  
  local pattern_count = 0
  for _, surr_line in ipairs(surrounding_lines) do
    if surr_line:find(pattern.regex) then
      pattern_count = pattern_count + 1
    end
  end
  
  if pattern_count > 2 then
    boost = boost + 0.1 -- Multiple similar patterns suggest a systematic issue
  end
  
  return boost
end

-- Get all suggestions for a range
function M.get_suggestions_for_range(bufnr, range)
  return M.analyze_and_suggest(bufnr, range)
end

-- Get suggestions for entire buffer
function M.get_suggestions_for_buffer(bufnr)
  bufnr = bufnr or api.nvim_get_current_buf()
  local line_count = api.nvim_buf_line_count(bufnr)
  
  return M.analyze_and_suggest(bufnr, {
    start = { 1, 0 },
    ["end"] = { line_count, 0 }
  })
end

-- Get suggestions for function at cursor
function M.get_suggestions_for_function_at_cursor(bufnr, cursor_pos)
  bufnr = bufnr or api.nvim_get_current_buf()
  cursor_pos = cursor_pos or api.nvim_win_get_cursor(0)
  
  local actions = require('traceback.actions')
  local func_info = actions._get_function_at_cursor(bufnr, cursor_pos)
  
  if not func_info then
    return {}
  end
  
  return M.analyze_and_suggest(bufnr, func_info.range)
end

-- Enhanced buffer scanning with multiple analysis layers
function M.scan_buffer_comprehensive(bufnr, options)
  bufnr = bufnr or api.nvim_get_current_buf()
  options = options or {}
  
  local scan_options = vim.tbl_deep_extend("force", {
    include_complexity = true,
    include_patterns = true,
    include_security = true,
    include_performance = true,
    include_dependencies = true,
    include_documentation = true,
    detailed_metrics = true,
    scan_depth = "thorough" -- "quick", "normal", "thorough"
  }, options)
  
  local scan_result = {
    summary = {
      total_lines = api.nvim_buf_line_count(bufnr),
      file_type = vim.bo[bufnr].filetype,
      scan_timestamp = os.date("%Y-%m-%d %H:%M:%S"),
      scan_duration = 0
    },
    metrics = {},
    suggestions = {},
    quality_score = 0,
    maintainability_index = 0
  }
  
  local start_time = os.clock()
  
  -- Layer 1: Basic code metrics
  if scan_options.include_complexity then
    scan_result.metrics.complexity = M._analyze_complexity_metrics(bufnr)
  end
  
  -- Layer 2: Code quality patterns
  if scan_options.include_patterns then
    scan_result.metrics.patterns = M._analyze_code_patterns(bufnr)
  end
  
  -- Layer 3: Security analysis
  if scan_options.include_security then
    scan_result.metrics.security = M._analyze_security_metrics(bufnr)
  end
  
  -- Layer 4: Performance analysis
  if scan_options.include_performance then
    scan_result.metrics.performance = M._analyze_performance_metrics(bufnr)
  end
  
  -- Layer 5: Dependency analysis
  if scan_options.include_dependencies then
    scan_result.metrics.dependencies = M._analyze_dependencies(bufnr)
  end
  
  -- Layer 6: Documentation analysis
  if scan_options.include_documentation then
    scan_result.metrics.documentation = M._analyze_documentation(bufnr)
  end
  
  -- Generate comprehensive suggestions
  scan_result.suggestions = M._generate_comprehensive_suggestions(bufnr, scan_result.metrics)
  
  -- Calculate quality scores
  scan_result.quality_score = M._calculate_quality_score(scan_result.metrics)
  scan_result.maintainability_index = M._calculate_maintainability_index(scan_result.metrics)
  
  scan_result.summary.scan_duration = os.clock() - start_time
  
  return scan_result
end

-- Analyze complexity metrics across the buffer
function M._analyze_complexity_metrics(bufnr)
  local metrics = {
    functions = {},
    total_complexity = 0,
    average_complexity = 0,
    max_complexity = 0,
    high_complexity_functions = 0,
    cyclomatic_distribution = { low = 0, medium = 0, high = 0, very_high = 0 }
  }
  
  local line_count = api.nvim_buf_line_count(bufnr)
  local functions = M._analyze_functions(bufnr, { start = { 1, 0 }, ["end"] = { line_count, 0 } }, vim.bo[bufnr].filetype)
  
  for _, func in ipairs(functions) do
    metrics.functions[func.name or "anonymous"] = {
      complexity = func.complexity,
      lines = func.lines,
      parameters = func.parameter_count or 0,
      nesting_depth = func.nesting_depth or 0,
      range = func.range
    }
    
    metrics.total_complexity = metrics.total_complexity + func.complexity
    metrics.max_complexity = math.max(metrics.max_complexity, func.complexity)
    
    if func.complexity > 15 then
      metrics.high_complexity_functions = metrics.high_complexity_functions + 1
      metrics.cyclomatic_distribution.very_high = metrics.cyclomatic_distribution.very_high + 1
    elseif func.complexity > 10 then
      metrics.cyclomatic_distribution.high = metrics.cyclomatic_distribution.high + 1
    elseif func.complexity > 5 then
      metrics.cyclomatic_distribution.medium = metrics.cyclomatic_distribution.medium + 1
    else
      metrics.cyclomatic_distribution.low = metrics.cyclomatic_distribution.low + 1
    end
  end
  
  if #functions > 0 then
    metrics.average_complexity = metrics.total_complexity / #functions
  end
  
  return metrics
end

-- Analyze code patterns and smells
function M._analyze_code_patterns(bufnr)
  local metrics = {
    code_smells = {},
    pattern_violations = {},
    duplication_candidates = {},
    naming_issues = {},
    structure_issues = {}
  }
  
  local lines = api.nvim_buf_get_lines(bufnr, 0, -1, false)
  local ft = vim.bo[bufnr].filetype
  
  -- Detect code smells
  metrics.code_smells = M._detect_code_smells(lines, ft)
  
  -- Find duplication candidates
  metrics.duplication_candidates = M._find_duplication_candidates(lines)
  
  -- Analyze naming patterns
  metrics.naming_issues = M._analyze_naming_patterns(lines, ft)
  
  -- Check structural issues
  metrics.structure_issues = M._analyze_structure_issues(lines, ft)
  
  return metrics
end

-- Analyze security metrics
function M._analyze_security_metrics(bufnr)
  local metrics = {
    vulnerability_count = 0,
    security_issues = {},
    risk_level = "low",
    hardcoded_secrets = 0,
    insecure_functions = 0,
    missing_validations = 0
  }
  
  local lines = api.nvim_buf_get_lines(bufnr, 0, -1, false)
  local ft = vim.bo[bufnr].filetype
  local security_patterns = M._get_security_upgrade_patterns(ft)
  
  for i, line in ipairs(lines) do
    for _, pattern in ipairs(security_patterns) do
      if line:find(pattern.regex or "") then
        metrics.vulnerability_count = metrics.vulnerability_count + 1
        table.insert(metrics.security_issues, {
          line = i,
          type = pattern.title,
          severity = M._get_security_severity(pattern),
          cwe = pattern.cwe
        })
        
        -- Categorize issues
        if pattern.title:lower():match("password") or pattern.title:lower():match("secret") then
          metrics.hardcoded_secrets = metrics.hardcoded_secrets + 1
        elseif pattern.title:lower():match("injection") or pattern.title:lower():match("exec") then
          metrics.insecure_functions = metrics.insecure_functions + 1
        end
      end
    end
  end
  
  -- Determine overall risk level
  if metrics.vulnerability_count > 5 or metrics.hardcoded_secrets > 0 then
    metrics.risk_level = "high"
  elseif metrics.vulnerability_count > 2 or metrics.insecure_functions > 0 then
    metrics.risk_level = "medium"
  end
  
  return metrics
end

-- Analyze performance metrics
function M._analyze_performance_metrics(bufnr)
  local metrics = {
    performance_issues = {},
    hot_path_violations = 0,
    inefficient_algorithms = 0,
    resource_leaks = 0,
    optimization_opportunities = {}
  }
  
  local lines = api.nvim_buf_get_lines(bufnr, 0, -1, false)
  local ft = vim.bo[bufnr].filetype
  local perf_patterns = M._get_performance_patterns(ft)
  
  for i, line in ipairs(lines) do
    for _, pattern in ipairs(perf_patterns) do
      if line:find(pattern.regex or "") then
        local is_in_loop = M._is_in_loop(bufnr, i, ft)
        local issue = {
          line = i,
          type = pattern.title,
          severity = is_in_loop and "high" or "medium",
          in_loop = is_in_loop,
          optimization = pattern.optimization
        }
        
        table.insert(metrics.performance_issues, issue)
        table.insert(metrics.optimization_opportunities, {
          line = i,
          description = pattern.optimization,
          expected_improvement = is_in_loop and "significant" or "moderate"
        })
        
        if is_in_loop then
          metrics.hot_path_violations = metrics.hot_path_violations + 1
        end
      end
    end
  end
  
  return metrics
end

-- Analyze dependencies and imports
function M._analyze_dependencies(bufnr)
  local metrics = {
    imports = {},
    external_dependencies = 0,
    unused_imports = 0,
    circular_dependencies = {},
    deprecated_dependencies = {}
  }
  
  local lines = api.nvim_buf_get_lines(bufnr, 0, -1, false)
  local ft = vim.bo[bufnr].filetype
  
  local import_patterns = {
    lua = { "require%s*[%(%'\"]([^%)'\"]+)[%)'\"%)%s]*", "local%s+([%w_]+)%s*=%s*require" },
    python = { "import%s+([%w_.]+)", "from%s+([%w_.]+)%s+import" },
    javascript = { "import%s+.-%s+from%s+['\"]([^'\"]+)['\"]", "require%s*%(%s*['\"]([^'\"]+)['\"]" },
    go = { "import%s+['\"]([^'\"]+)['\"]" },
    c = { "#include%s+[<\"]([^>\"]+)[>\"]" },
    cpp = { "#include%s+[<\"]([^>\"]+)[>\"]" }
  }
  
  local patterns = import_patterns[ft] or {}
  
  for _, line in ipairs(lines) do
    for _, pattern in ipairs(patterns) do
      local matches = { line:match(pattern) }
      for _, match in ipairs(matches) do
        if match then
          table.insert(metrics.imports, match)
          metrics.external_dependencies = metrics.external_dependencies + 1
        end
      end
    end
  end
  
  -- Remove duplicates
  local unique_imports = {}
  for _, import in ipairs(metrics.imports) do
    if not unique_imports[import] then
      unique_imports[import] = true
    end
  end
  
  metrics.imports = vim.tbl_keys(unique_imports)
  metrics.external_dependencies = #metrics.imports
  
  return metrics
end

-- Analyze documentation quality
function M._analyze_documentation(bufnr)
  local metrics = {
    comment_lines = 0,
    total_lines = 0,
    comment_ratio = 0,
    documented_functions = 0,
    total_functions = 0,
    documentation_coverage = 0,
    todo_comments = 0,
    fixme_comments = 0
  }
  
  local lines = api.nvim_buf_get_lines(bufnr, 0, -1, false)
  local ft = vim.bo[bufnr].filetype
  
  local comment_patterns = {
    lua = "^%s*%-%-",
    python = "^%s*#",
    javascript = "^%s*//",
    typescript = "^%s*//",
    c = "^%s*//",
    cpp = "^%s*//",
    go = "^%s*//"
  }
  
  local comment_pattern = comment_patterns[ft] or "^%s*#"
  
  metrics.total_lines = #lines
  
  for _, line in ipairs(lines) do
    if line:match(comment_pattern) then
      metrics.comment_lines = metrics.comment_lines + 1
      
      if line:lower():match("todo") then
        metrics.todo_comments = metrics.todo_comments + 1
      elseif line:lower():match("fixme") then
        metrics.fixme_comments = metrics.fixme_comments + 1
      end
    end
  end
  
  if metrics.total_lines > 0 then
    metrics.comment_ratio = metrics.comment_lines / metrics.total_lines
  end
  
  -- Analyze function documentation
  local functions = M._analyze_functions(bufnr, { start = { 1, 0 }, ["end"] = { metrics.total_lines, 0 } }, ft)
  metrics.total_functions = #functions
  
  for _, func in ipairs(functions) do
    -- Check if function has documentation before it
    local func_line = func.range.start[1]
    if func_line > 1 then
      local prev_line = api.nvim_buf_get_lines(bufnr, func_line - 2, func_line - 1, false)[1]
      if prev_line and prev_line:match(comment_pattern) then
        metrics.documented_functions = metrics.documented_functions + 1
      end
    end
  end
  
  if metrics.total_functions > 0 then
    metrics.documentation_coverage = metrics.documented_functions / metrics.total_functions
  end
  
  return metrics
end

-- Generate comprehensive suggestions based on all metrics
function M._generate_comprehensive_suggestions(bufnr, metrics)
  local suggestions = {}
  local ft = vim.bo[bufnr].filetype
  
  -- Complexity-based suggestions
  if metrics.complexity then
    if metrics.complexity.high_complexity_functions > 0 then
      table.insert(suggestions, {
        type = "refactor",
        priority = 1,
        title = "High complexity functions detected",
        description = string.format("Found %d functions with high complexity. Consider refactoring.",
          metrics.complexity.high_complexity_functions),
        impact = "maintainability",
        confidence = 0.9,
        action = "refactor_complex_functions"
      })
    end
    
    if metrics.complexity.average_complexity > 10 then
      table.insert(suggestions, {
        type = "refactor",
        priority = 2,
        title = "Overall complexity is high",
        description = string.format("Average function complexity is %.1f. Consider simplifying logic.",
          metrics.complexity.average_complexity),
        impact = "maintainability",
        confidence = 0.8,
        action = "simplify_logic"
      })
    end
  end
  
  -- Security-based suggestions
  if metrics.security then
    if metrics.security.risk_level == "high" then
      table.insert(suggestions, {
        type = "security",
        priority = 1,
        title = "High security risk detected",
        description = string.format("Found %d security vulnerabilities. Immediate attention required.",
          metrics.security.vulnerability_count),
        impact = "security",
        confidence = 0.95,
        action = "fix_security_issues"
      })
    elseif metrics.security.vulnerability_count > 0 then
      table.insert(suggestions, {
        type = "security",
        priority = 2,
        title = "Security improvements needed",
        description = string.format("Found %d potential security issues.",
          metrics.security.vulnerability_count),
        impact = "security",
        confidence = 0.8,
        action = "review_security"
      })
    end
  end
  
  -- Performance-based suggestions
  if metrics.performance then
    if metrics.performance.hot_path_violations > 0 then
      table.insert(suggestions, {
        type = "performance",
        priority = 1,
        title = "Performance bottlenecks in loops",
        description = string.format("Found %d performance issues in hot paths.",
          metrics.performance.hot_path_violations),
        impact = "performance",
        confidence = 0.85,
        action = "optimize_hot_paths"
      })
    end
  end
  
  -- Documentation suggestions
  if metrics.documentation then
    if metrics.documentation.documentation_coverage < 0.5 then
      table.insert(suggestions, {
        type = "documentation",
        priority = 3,
        title = "Low documentation coverage",
        description = string.format("Only %.0f%% of functions are documented.",
          metrics.documentation.documentation_coverage * 100),
        impact = "maintainability",
        confidence = 0.7,
        action = "improve_documentation"
      })
    end
    
    if metrics.documentation.todo_comments > 5 then
      table.insert(suggestions, {
        type = "maintenance",
        priority = 2,
        title = "Many TODO comments",
        description = string.format("Found %d TODO comments. Consider addressing them.",
          metrics.documentation.todo_comments),
        impact = "maintenance",
        confidence = 0.6,
        action = "address_todos"
      })
    end
  end
  
  return suggestions
end

-- Calculate overall quality score (0-100)
function M._calculate_quality_score(metrics)
  local score = 100
  
  -- Complexity penalty
  if metrics.complexity then
    local complexity_penalty = math.min(30, metrics.complexity.high_complexity_functions * 10)
    score = score - complexity_penalty
  end
  
  -- Security penalty
  if metrics.security then
    local security_penalty = math.min(40, metrics.security.vulnerability_count * 8)
    score = score - security_penalty
  end
  
  -- Performance penalty
  if metrics.performance then
    local perf_penalty = math.min(20, metrics.performance.hot_path_violations * 5)
    score = score - perf_penalty
  end
  
  -- Documentation penalty
  if metrics.documentation then
    local doc_penalty = (1 - metrics.documentation.documentation_coverage) * 15
    score = score - doc_penalty
  end
  
  return math.max(0, math.floor(score))
end

-- Calculate maintainability index (0-100)
function M._calculate_maintainability_index(metrics)
  -- Simplified maintainability index based on complexity, documentation, and size
  local base_score = 100
  
  if metrics.complexity then
    local complexity_factor = math.min(50, metrics.complexity.average_complexity * 3)
    base_score = base_score - complexity_factor
  end
  
  if metrics.documentation then
    local doc_bonus = metrics.documentation.documentation_coverage * 20
    base_score = base_score + doc_bonus
  end
  
  -- Adjust for file size (larger files are harder to maintain)
  local line_count = metrics.patterns and #metrics.patterns or 0
  if line_count > 500 then
    base_score = base_score - math.min(20, (line_count - 500) / 100)
  end
  
  return math.max(0, math.min(100, math.floor(base_score)))
end

-- Helper functions for detailed analysis
function M._detect_code_smells(lines, ft)
  local smells = {}
  
  -- Long parameter lists
  for i, line in ipairs(lines) do
    local param_count = 0
    for _ in line:gmatch(",") do
      param_count = param_count + 1
    end
    if param_count > 5 and line:match("function") then
      table.insert(smells, {
        line = i,
        type = "long_parameter_list",
        severity = "medium"
      })
    end
  end
  
  -- Large functions (simple heuristic)
  local in_function = false
  local function_start = 0
  local brace_count = 0
  
  for i, line in ipairs(lines) do
    if line:match("function") or line:match("def ") then
      in_function = true
      function_start = i
      brace_count = 0
    end
    
    if in_function then
      brace_count = brace_count + (line:match("{") and 1 or 0)
      brace_count = brace_count - (line:match("}") and 1 or 0)
      
      if brace_count == 0 and (line:match("}") or line:match("end")) then
        if i - function_start > 50 then
          table.insert(smells, {
            line = function_start,
            type = "large_function",
            severity = "high",
            length = i - function_start
          })
        end
        in_function = false
      end
    end
  end
  
  return smells
end

function M._find_duplication_candidates(lines)
  local candidates = {}
  local line_groups = {}
  
  -- Group similar lines
  for i, line in ipairs(lines) do
    local trimmed = line:match("^%s*(.-)%s*$")
    if #trimmed > 10 then -- Only consider substantial lines
      if not line_groups[trimmed] then
        line_groups[trimmed] = {}
      end
      table.insert(line_groups[trimmed], i)
    end
  end
  
  -- Find duplicates
  for line_text, line_numbers in pairs(line_groups) do
    if #line_numbers > 1 then
      table.insert(candidates, {
        text = line_text,
        occurrences = line_numbers,
        count = #line_numbers
      })
    end
  end
  
  return candidates
end

function M._analyze_naming_patterns(lines, ft)
  local issues = {}
  
  -- Check for naming conventions based on language
  local naming_patterns = {
    lua = {
      variable = "^[a-z][a-z0-9_]*$",
      function_name = "^[a-z][a-z0-9_]*$",
      constant = "^[A-Z][A-Z0-9_]*$"
    },
    python = {
      variable = "^[a-z][a-z0-9_]*$",
      function_name = "^[a-z][a-z0-9_]*$",
      constant = "^[A-Z][A-Z0-9_]*$",
      class_name = "^[A-Z][a-zA-Z0-9]*$"
    },
    javascript = {
      variable = "^[a-z][a-zA-Z0-9]*$",
      function_name = "^[a-z][a-zA-Z0-9]*$",
      constant = "^[A-Z][A-Z0-9_]*$"
    }
  }
  
  -- Simple naming analysis (this could be much more sophisticated)
  for i, line in ipairs(lines) do
    -- Check for single-letter variables (potential issue)
    if line:match("[^%w_][a-z]%s*=") and not line:match("for%s+[a-z]%s*=") then
      table.insert(issues, {
        line = i,
        type = "single_letter_variable",
        severity = "low"
      })
    end
    
    -- Check for overly long names
    local long_name = line:match("([%w_]{30,})")
    if long_name then
      table.insert(issues, {
        line = i,
        type = "overly_long_name",
        severity = "low",
        name = long_name
      })
    end
  end
  
  return issues
end

function M._analyze_structure_issues(lines, ft)
  local issues = {}
  
  -- Check for deep nesting
  local max_nesting = 0
  local current_nesting = 0
  
  for i, line in ipairs(lines) do
    local indent_level = #line:match("^%s*") / 2 -- Assuming 2-space indents
    
    if indent_level > max_nesting then
      max_nesting = indent_level
    end
    
    if indent_level > 6 then -- Deep nesting threshold
      table.insert(issues, {
        line = i,
        type = "deep_nesting",
        severity = "medium",
        level = indent_level
      })
    end
  end
  
  return issues
end

function M._get_security_severity(pattern)
  if pattern.cwe then
    -- High severity CWEs
    local high_severity = { "CWE-78", "CWE-94", "CWE-120", "CWE-502" }
    for _, cwe in ipairs(high_severity) do
      if pattern.cwe == cwe then
        return "high"
      end
    end
  end
  
  if pattern.confidence and pattern.confidence > 0.9 then
    return "high"
  elseif pattern.confidence and pattern.confidence > 0.7 then
    return "medium"
  else
    return "low"
  end
end

return M
