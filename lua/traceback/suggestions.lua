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
            confidence = 0.9,
            cwe = "CWE-330",
            upgrade_suggestion = "Use crypto/rand for secret generation",
            replacement = "crypto/rand"
        }
    }
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

return M
