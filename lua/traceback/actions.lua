local M = {}

local api = vim.api
local ns_actions = api.nvim_create_namespace("traceback_actions")
local providers = {}
local cfg = {}

-- Safe getter for suggestions module to avoid circular dependencies
local function get_suggestions()
  local U = require('traceback.utils')
  local suggestions_ok, suggestions = pcall(require, 'traceback.suggestions')
  if not suggestions_ok then
    if cfg.error_handling then
  U.notify("Suggestions module not available: " .. tostring(suggestions), vim.log.levels.DEBUG)
    end
    return nil
  end
  return suggestions
end

-- Input validation helpers
local function validate_buffer(bufnr)
  return bufnr and api.nvim_buf_is_valid(bufnr)
end

local function validate_position(pos)
  return pos and type(pos) == "table" and #pos >= 2 and 
         type(pos[1]) == "number" and type(pos[2]) == "number" and
         pos[1] > 0 and pos[2] >= 0
end

local function safe_execute(fn, ...)
  if not cfg.error_handling then
    return fn(...)
  end
  
  local ok, result = pcall(fn, ...)
  if not ok then
  U.notify("Action execution error: " .. tostring(result), vim.log.levels.ERROR)
    return nil
  end
  return result
end

-- Action types with metadata and icons
local ACTION_TYPES = {
  allowlist = { icon = "󰌾", title = "Add to allowlist", desc = "Suppress this pattern in security lens", priority = 1 },
  ignore_inline = { icon = "󰘖", title = "Ignore inline", desc = "Add ignore comment for this line", priority = 2 },
  ignore_virtual = { icon = "󰘕", title = "Ignore virtual", desc = "Add virtual text ignore marker", priority = 3 },
  explain = { icon = "󰋽", title = "Show explanation", desc = "Display detailed information about this issue", priority = 4 },
  apply_fix = { icon = "󰁨", title = "Apply suggested fix", desc = "Automatically apply the recommended solution", priority = 5 },
  refactor = { icon = "󰖷", title = "Refactor", desc = "Suggest code improvements", priority = 6 },
  suppress_file = { icon = "󰩺", title = "Suppress in file", desc = "Add file-level suppression", priority = 7 },
  create_config = { icon = "󰒓", title = "Create config", desc = "Generate configuration entry", priority = 8 },
  quick_docs = { icon = "󰋚", title = "Quick documentation", desc = "Open relevant documentation", priority = 9 },
  copy_snippet = { icon = "󰆏", title = "Copy secure snippet", desc = "Copy secure alternative to clipboard", priority = 10 }
}

-- Provider interface for exposing annotations with actions
function M.register_provider(name, provider_fn)
  if type(provider_fn) ~= "function" then
    error("Provider must be a function(bufnr, cursor_pos) -> annotations[]")
  end
  providers[name] = provider_fn
end

function M.setup(opts)
  cfg = vim.tbl_deep_extend("force", {
    max_annotations_per_provider = 50,
    auto_register_lens_providers = true,
    enable_smart_suggestions = true,
    enable_taint_analysis = true,
    action_preview = true,
    telemetry_enabled = false,
    timeout_ms = 1000,
    error_handling = true,
    suggestion_engine = {
      enable_complexity_analysis = true,
      enable_pattern_detection = true,
      enable_security_suggestions = true,
      enable_performance_hints = true,
      suggestion_confidence_threshold = 0.7,
      cache_enabled = true,
      timeout_ms = 1000,
      debug = false
    },
    keymaps = {
      show_actions = '<Leader>ta',
      quick_fix = '<Leader>tf',
      explain = '<Leader>te',
      allowlist = '<Leader>tw',
      suggest_improvements = '<Leader>ts',
      suggest_function = '<Leader>tF'
    }
  }, opts or {})
  
  -- Initialize suggestion engine with lazy loading to avoid circular dependencies
  if cfg.enable_smart_suggestions then
    vim.defer_fn(function()
      local suggestions_ok, suggestions = pcall(require, 'traceback.suggestions')
      if suggestions_ok then
        suggestions.setup(cfg.suggestion_engine)
      elseif cfg.error_handling then
  U.notify("Failed to load suggestions module: " .. tostring(suggestions), vim.log.levels.WARN)
      end
    end, 0)
  end
  
  -- Auto-register lens providers if enabled
  if cfg.auto_register_lens_providers then
    local ok, err = pcall(M._register_default_providers)
    if not ok and cfg.error_handling then
  U.notify("TraceBack: Failed to register providers: " .. tostring(err), vim.log.levels.WARN)
    elseif ok and cfg.error_handling then
  U.notify("TraceBack: Successfully registered " .. vim.tbl_count(providers) .. " providers", vim.log.levels.INFO)
    end
  end
  
  -- Mark setup as completed
  M._setup_completed = true
  
  -- Setup keymaps
  M._setup_keymaps()
  
  -- Setup commands
  M._setup_commands()
end

function M._register_default_providers()
  -- Register security lens provider
  M.register_provider("security", function(bufnr, cursor_pos)
    return M._get_security_annotations(bufnr, cursor_pos)
  end)
  
  -- Register code lens provider
  M.register_provider("code", function(bufnr, cursor_pos)
    return M._get_code_annotations(bufnr, cursor_pos)
  end)
  
  -- Register debug lens provider
  M.register_provider("debug", function(bufnr, cursor_pos)
    return M._get_debug_annotations(bufnr, cursor_pos)
  end)
  
  -- Register smart suggestions provider
  if cfg.enable_smart_suggestions then
    M.register_provider("suggestions", function(bufnr, cursor_pos)
      return M._get_smart_suggestions(bufnr, cursor_pos)
    end)
  end
end

function M._get_security_annotations(bufnr, cursor_pos)
  local line_nr = cursor_pos[1]
  local col = cursor_pos[2]
  local line = api.nvim_buf_get_lines(bufnr, line_nr - 1, line_nr, false)[1]
  if not line then return {} end
  
  local security_lens = require('traceback.lenses.lens_security')
  local ft = vim.bo[bufnr].filetype
  local annotations = {}
  
  -- Get security patterns for this filetype
  local patterns = M._get_security_patterns(ft)
  
  for _, pattern in ipairs(patterns) do
    local start_pos, end_pos = line:find(pattern.pat)
    if start_pos and col >= start_pos - 1 and col <= end_pos then
      local matched_text = line:sub(start_pos, end_pos)
      local annotation = {
        id = "security_" .. line_nr .. "_" .. start_pos,
        type = "security",
        title = pattern.msg,
        message = M._get_security_explanation(pattern, matched_text, ft),
        range = {
          start = { line_nr, start_pos - 1 },
          ["end"] = { line_nr, end_pos }
        },
        severity = M._get_severity_from_hl(pattern.hl),
        matched_text = matched_text,
        pattern = pattern,
        actions = M._get_security_actions(pattern, matched_text, ft)
      }
      table.insert(annotations, annotation)
    end
  end
  
  return annotations
end

function M._get_code_annotations(bufnr, cursor_pos)
  local line_nr = cursor_pos[1]
  local annotations = {}
  
  -- Get function complexity info if cursor is on a function
  local func_info = M._get_function_at_cursor(bufnr, cursor_pos)
  if func_info then
    local annotation = {
      id = "code_func_" .. line_nr,
      type = "code",
      title = "Function: " .. func_info.name,
      message = string.format("Complexity: %d lines, %d branches", func_info.lines, func_info.complexity),
      range = func_info.range,
      severity = M._get_complexity_severity(func_info.complexity),
      actions = M._get_code_actions(func_info)
    }
    table.insert(annotations, annotation)
  end
  
  return annotations
end

function M._get_debug_annotations(bufnr, cursor_pos)
  local line_nr = cursor_pos[1]
  local line = api.nvim_buf_get_lines(bufnr, line_nr - 1, line_nr, false)[1]
  if not line then return {} end
  
  local annotations = {}
  
  -- Check for debug patterns
local debug_patterns = {
    -- JavaScript / Browser
    { pat = "console%.log", msg = "Console.log statement", type = "console_log" },
    { pat = "console%.debug", msg = "Console.debug statement", type = "console_debug" },
    { pat = "console%.warn", msg = "Console.warn statement", type = "console_warn" },
    { pat = "console%.error", msg = "Console.error statement", type = "console_error" },
    { pat = "console%.trace", msg = "Console.trace statement", type = "console_trace" },
    { pat = "%f[%w]debugger%f[%W]", msg = "Debugger statement (JS)", type = "debugger" },

    -- Lua
    { pat = "%f[%w]print%(", msg = "print() call (Lua)", type = "lua_print" },
    { pat = "%f[%w]io%.write%(", msg = "io.write() call (Lua)", type = "lua_io_write" },
    { pat = "%f[%w]io%.stdout:write%(", msg = "io.stdout:write() (Lua)", type = "lua_io_stdout_write" },
    { pat = "%f[%w]io%.stderr:write%(", msg = "io.stderr:write() (Lua)", type = "lua_io_stderr_write" },
    { pat = "%f[%w]debug%.debug%(", msg = "debug.debug() (Lua)", type = "lua_debug_debug" },
    { pat = "%f[%w]vim%.inspect%(", msg = "vim.inspect() (Neovim debug)", type = "lua_vim_inspect" },
    { pat = "require%s*%(%s*['\"]inspect['\"]%s*%)", msg = "require('inspect') (Lua debug library)", type = "lua_require_inspect" },
    { pat = "require%s*%(%s*['\"]pl%.pretty['\"]%s*%)", msg = "require('pl.pretty') (pretty printer)", type = "lua_require_pl_pretty" },
    { pat = "%f[%w]ngx%.say%(", msg = "ngx.say() (OpenResty debug output)", type = "lua_ngx_say" },
    { pat = "%f[%w]dump%(", msg = "dump() call (common debug helper)", type = "lua_dump" },


    -- Python
    { pat = "%f[%w]print%(", msg = "print() call (Python/other)", type = "debug_print" },
    { pat = "%f[%w]pdb%.set_trace%(", msg = "pdb.set_trace()", type = "pdb_trace" },
    { pat = "%f[%w]import%s+pdb%f[%W]", msg = "import pdb (Python)", type = "import_pdb" },
    { pat = "%f[%w]logging%.debug%(", msg = "logging.debug() (Python)", type = "logging_debug" },

    -- Go
    { pat = "%f[%w]fmt%.Println%(", msg = "fmt.Println (Go)", type = "fmt_println" },
    { pat = "%f[%w]fmt%.Printf%(", msg = "fmt.Printf (Go)", type = "fmt_printf" },
    { pat = "%f[%w]log%.Println%(", msg = "log.Println (Go)", type = "log_println" },

    -- C / C++
    { pat = "printf%(", msg = "printf() call (C/C++)", type = "printf" },
    { pat = "fprintf%(", msg = "fprintf() call (C/C++)", type = "fprintf" },
    { pat = "puts%(", msg = "puts() call (C)", type = "puts" },
    { pat = "std%.cerr%s*<<", msg = "std::cerr output (C++)", type = "cerr" },
    { pat = "std%.cout%s*<<", msg = "std::cout output (C++)", type = "cout" },

    -- Generic / comments
    { pat = "[Tt][Oo][Dd][Oo]", msg = "TODO comment", type = "todo" },
    { pat = "[Ff][Ii][Xx][Mm][Ee]", msg = "FIXME comment", type = "fixme" },
    { pat = "[Xx][Xx][Xx]", msg = "XXX comment", type = "xxx" },

    -- Other common logger patterns
    { pat = "%f[%w]log%.debug%(", msg = "log.debug() (common logging libs)", type = "log_debug" },
    { pat = "%f[%w]trace%(", msg = "trace() call", type = "trace_call" }
}
  
  for _, pattern in ipairs(debug_patterns) do
    local start_pos, end_pos = line:find(pattern.pat)
    if start_pos then
      local annotation = {
        id = "debug_" .. line_nr .. "_" .. start_pos,
        type = "debug",
        title = pattern.msg,
        message = "Debug statement found: " .. line:sub(start_pos, end_pos),
        range = {
          start = { line_nr, start_pos - 1 },
          ["end"] = { line_nr, end_pos }
        },
        severity = "info",
        actions = M._get_debug_actions(pattern.type, line:sub(start_pos, end_pos))
      }
      table.insert(annotations, annotation)
    end
  end
  
  return annotations
end

function M._get_smart_suggestions(bufnr, cursor_pos)
  if not cfg.enable_smart_suggestions then
    return {}
  end
  
  local suggestions_engine = get_suggestions()
  if not suggestions_engine then
    return {}
  end
  
  local line_nr = cursor_pos[1]
  local col = cursor_pos[2]
  
  -- Get suggestions for the current function or a small range around cursor
  local func_info = M._get_function_at_cursor(bufnr, cursor_pos)
  local range
  
  if func_info then
    range = func_info.range
  else
    -- Fallback to a small range around the cursor
    range = {
      start = { math.max(1, line_nr - 10), 0 },
      ["end"] = { line_nr + 10, 0 }
    }
  end
  
  local suggestions_ok, suggestions = pcall(suggestions_engine.analyze_and_suggest, bufnr, range)
  if not suggestions_ok then
    if cfg.error_handling then
  U.notify("Failed to analyze suggestions: " .. tostring(suggestions), vim.log.levels.DEBUG)
    end
    return {}
  end
  
  local annotations = {}
  
  for _, suggestion in ipairs(suggestions or {}) do
    -- Convert suggestion to annotation format
    local annotation = {
      id = "suggestion_" .. suggestion.type .. "_" .. line_nr,
      type = "suggestion",
      title = suggestion.title,
      message = M._format_suggestion_message(suggestion),
      range = suggestion.range,
      severity = M._suggestion_severity(suggestion),
      confidence = suggestion.confidence,
      impact = suggestion.impact,
      suggestion_data = suggestion,
      actions = M._get_suggestion_actions(suggestion)
    }
    table.insert(annotations, annotation)
  end
  
  return annotations
end

function M._format_suggestion_message(suggestion)
  local message = suggestion.description
  
  if suggestion.confidence then
    message = message .. string.format("\n\n󰑭 Confidence: %.0f%%", suggestion.confidence * 100)
  end
  
  if suggestion.impact then
    message = message .. string.format("\n󰓎 Impact: %s", suggestion.impact)
  end
  
  if suggestion.suggestion then
    message = message .. "\n\n󰌶 Suggestion:\n" .. suggestion.suggestion
  end
  
  if suggestion.cwe then
    message = message .. string.format("\n🔗 Security Reference: %s", suggestion.cwe)
  end
  
  return message
end

function M._suggestion_severity(suggestion)
  if suggestion.type == "security" then
    return "error"
  elseif suggestion.type == "refactor" and suggestion.confidence > 0.8 then
    return "warning"
  elseif suggestion.type == "performance" and suggestion.priority <= 2 then
    return "warning"
  else
    return "info"
  end
end

function M._get_suggestion_actions(suggestion)
  local actions = {}
  
  -- Standard actions
  table.insert(actions, ACTION_TYPES.explain)
  
  -- Type-specific actions
  if suggestion.replacement then
    table.insert(actions, ACTION_TYPES.apply_fix)
  end
  
  if suggestion.type == "security" then
    table.insert(actions, ACTION_TYPES.quick_docs)
    table.insert(actions, ACTION_TYPES.copy_snippet)
  elseif suggestion.type == "refactor" then
    table.insert(actions, ACTION_TYPES.refactor)
  elseif suggestion.type == "performance" then
    local benchmark_action = vim.deepcopy(ACTION_TYPES.quick_docs)
    benchmark_action.title = "Show benchmark"
    benchmark_action.desc = "Compare performance characteristics"
    table.insert(actions, benchmark_action)
  end
  
  -- Actions from the suggestion itself
  if suggestion.actions then
    for _, action in ipairs(suggestion.actions) do
      local action_type = {
        icon = "󰒓",
        title = action.title,
        desc = action.description,
        priority = 99
      }
      table.insert(actions, action_type)
    end
  end
  
  return actions
end

function M._get_security_patterns(ft)
  local security_lens = require('traceback.lenses.lens_security')
  -- Access the insecure patterns from the security lens module
local patterns_by_ft = {
    c = {
        { pat = 'system%(', msg = 'system call (command injection)', hl = 'DiagnosticError' },
        { pat = 'strcpy%s*%(', msg = 'strcpy (buffer overflow)', hl = 'DiagnosticError' },
        { pat = 'gets%s*%(', msg = 'gets (buffer overflow)', hl = 'DiagnosticError' },
        { pat = 'strcat%s*%(', msg = 'strcat (buffer overflow)', hl = 'DiagnosticError' },
        { pat = 'sprintf%s*%(', msg = 'sprintf (buffer overflow)', hl = 'DiagnosticWarn' },
        { pat = 'scanf%s*%(', msg = 'scanf (unsafe input parsing)', hl = 'DiagnosticWarn' },
        { pat = 'popen%s*%(', msg = 'popen (command injection)', hl = 'DiagnosticWarn' },
        { pat = 'mktemp%s*%(', msg = 'mktemp (insecure temp file)', hl = 'DiagnosticWarn' },
        { pat = 'tmpnam%s*%(', msg = 'tmpnam (insecure temp name)', hl = 'DiagnosticWarn' }
    },
    cpp = {
        { pat = 'system%(', msg = 'system call (command injection)', hl = 'DiagnosticError' },
        { pat = 'strcpy%s*%(', msg = 'strcpy (buffer overflow)', hl = 'DiagnosticError' },
        { pat = 'gets%s*%(', msg = 'gets (buffer overflow)', hl = 'DiagnosticError' },
        { pat = 'strcat%s*%(', msg = 'strcat (buffer overflow)', hl = 'DiagnosticError' },
        { pat = 'sprintf%s*%(', msg = 'sprintf (buffer overflow)', hl = 'DiagnosticWarn' },
        { pat = 'scanf%s*%(', msg = 'scanf (unsafe input parsing)', hl = 'DiagnosticWarn' },
        { pat = 'popen%s*%(', msg = 'popen (command injection)', hl = 'DiagnosticWarn' },
        { pat = 'mktemp%s*%(', msg = 'mktemp (insecure temp file)', hl = 'DiagnosticWarn' },
        { pat = 'tmpnam%s*%(', msg = 'tmpnam (insecure temp name)', hl = 'DiagnosticWarn' }
    },
    python = {
        { pat = '%f[%w]eval%f[^%w]%(', msg = 'eval (code injection)', hl = 'DiagnosticError' },
        { pat = '%f[%w]exec%f[^%w]%(', msg = 'exec (code injection)', hl = 'DiagnosticError' },
        { pat = 'subprocess%.run%f[^%w]%(', msg = 'subprocess.run (command injection)', hl = 'DiagnosticWarn' },
        { pat = 'subprocess%.Popen%f[^%w]%(', msg = 'subprocess.Popen (command injection)', hl = 'DiagnosticWarn' },
        { pat = 'shell%s*=%s*True', msg = 'shell=True (command injection)', hl = 'DiagnosticWarn' },
        { pat = 'os%.system%f[^%w]%(', msg = 'os.system (command injection)', hl = 'DiagnosticError' },
        { pat = 'os%.popen%f[^%w]%(', msg = 'os.popen (command injection)', hl = 'DiagnosticWarn' },
        { pat = 'pickle%.loads%(', msg = 'pickle.loads (deserialization)', hl = 'DiagnosticError' },
        { pat = 'yaml%.load%f[^%w]%(', msg = 'yaml.load (unsafe deserialization)', hl = 'DiagnosticError' },
        { pat = 'verify%s*=%s*False', msg = 'SSL verification disabled', hl = 'DiagnosticWarn' },
        { pat = 'hashlib%.md5%f[^%w]%(', msg = 'MD5 used (weak hash)', hl = 'DiagnosticWarn' },
        { pat = 'hashlib%.sha1%f[^%w]%(', msg = 'SHA1 used (weak hash)', hl = 'DiagnosticWarn' }
    },
    javascript = {
        { pat = '%f[%w]eval%f[^%w]%(', msg = 'eval (code injection)', hl = 'DiagnosticError' },
        { pat = 'innerHTML%s*=', msg = 'innerHTML assignment (XSS)', hl = 'DiagnosticWarn' },
        { pat = 'document%.write%f[^%w]%(', msg = 'document.write (XSS)', hl = 'DiagnosticError' },
        { pat = '%f[%w]Function%f[^%w]%(', msg = 'Function constructor (code injection)', hl = 'DiagnosticError' },
        { pat = 'setTimeout%s*%(', msg = 'setTimeout with string (eval-like)', hl = 'DiagnosticWarn' },
        { pat = 'setInterval%s*%(', msg = 'setInterval with string (eval-like)', hl = 'DiagnosticWarn' },
        { pat = 'child_process%.exec%f[^%w]%(', msg = 'child_process.exec (command injection)', hl = 'DiagnosticWarn' },
        { pat = 'child_process%.execSync%f[^%w]%(', msg = 'child_process.execSync (command injection)', hl = 'DiagnosticWarn' },
        { pat = 'crypto%.createHash%s*%(%s*[\'"]md5[\'"]%s*%)', msg = 'MD5 used (weak hash)', hl = 'DiagnosticWarn' },
        { pat = 'crypto%.createHash%s*%(%s*[\'"]sha1[\'"]%s*%)', msg = 'SHA1 used (weak hash)', hl = 'DiagnosticWarn' }
    },
    lua = {
        { pat = '%f[%w]loadstring%f[^%w]%(', msg = 'loadstring (code injection)', hl = 'DiagnosticError' },
        { pat = '%f[%w]load%f[^%w]%(', msg = 'load (code injection)', hl = 'DiagnosticWarn' },
        { pat = 'os%.execute%f[^%w]%(', msg = 'os.execute (command injection)', hl = 'DiagnosticError' },
        { pat = 'io%.popen%f[^%w]%(', msg = 'io.popen (command injection)', hl = 'DiagnosticWarn' },
        { pat = '%f[%w]dofile%f[^%w]%(', msg = 'dofile (untrusted file execution)', hl = 'DiagnosticWarn' },
        { pat = '%f[%w]loadfile%f[^%w]%(', msg = 'loadfile (untrusted file execution)', hl = 'DiagnosticWarn' }
    },
    go = {
        { pat = 'exec%.Command%f[^%w]%(', msg = 'exec.Command (command injection)', hl = 'DiagnosticError' },
        { pat = 'http%.ListenAndServe%f[^%w]%(', msg = 'HTTP listener without TLS', hl = 'DiagnosticWarn' },
        { pat = 'template%.HTML%f[^%w]%(', msg = 'template.HTML (XSS sink)', hl = 'DiagnosticWarn' },
        { pat = 'md5%.New%f[^%w]%(', msg = 'MD5 used (weak hash)', hl = 'DiagnosticWarn' },
        { pat = 'sha1%.New%f[^%w]%(', msg = 'SHA1 used (weak hash)', hl = 'DiagnosticWarn' },
        { pat = 'sql%.Query%f[^%w]%(', msg = 'SQL query (potential injection)', hl = 'DiagnosticError' },
        { pat = 'sql%.Exec%f[^%w]%(', msg = 'SQL exec (potential injection)', hl = 'DiagnosticError' },
        { pat = 'fmt%.Sprintf%f[^%w]%(.*%%%s', msg = 'fmt.Sprintf with user input (format injection)', hl = 'DiagnosticWarn' },
        { pat = 'os%.Getenv%f[^%w]%(', msg = 'Environment variable access (audit usage)', hl = 'DiagnosticInfo' },
        { pat = 'ioutil%.WriteFile%f[^%w]%(.*0777', msg = 'File created with overly permissive mode', hl = 'DiagnosticWarn' },
        { pat = 'net%.Dial%f[^%w]%(', msg = 'Network connection without TLS', hl = 'DiagnosticWarn' },
        { pat = 'crypto/rand%.Read%f[^%w]%(', msg = 'Random number generation (ensure proper error handling)', hl = 'DiagnosticInfo' },
        { pat = 'unsafe%.Pointer%f[^%w]', msg = 'unsafe.Pointer usage (memory safety risk)', hl = 'DiagnosticWarn' },
        { pat = 'reflect%.ValueOf%f[^%w]%(', msg = 'Reflection usage (performance and security implications)', hl = 'DiagnosticInfo' },
        { pat = 'strconv%.Atoi%f[^%w]%(', msg = 'strconv.Atoi without error handling', hl = 'DiagnosticWarn' },
        { pat = 'json%.Unmarshal%f[^%w]%(', msg = 'JSON unmarshal (validate input and handle errors)', hl = 'DiagnosticInfo' },
        { pat = 'http%.Get%f[^%w]%(', msg = 'HTTP GET without timeout or TLS verification', hl = 'DiagnosticWarn' },
        { pat = 'log%.Fatal%f[^%w]%(', msg = 'log.Fatal (abrupt termination)', hl = 'DiagnosticWarn' },
        { pat = 'panic%f[^%w]%(', msg = 'panic() call (consider error return instead)', hl = 'DiagnosticWarn' }
    },
    default = {
        { pat = 'http://', msg = 'insecure HTTP (use HTTPS)', hl = 'DiagnosticWarn' },
        { pat = 'password%s*=', msg = 'hardcoded password', hl = 'DiagnosticError' },
        { pat = 'secret%s*=', msg = 'hardcoded secret', hl = 'DiagnosticError' },
        { pat = '[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]', msg = 'possible API key in code', hl = 'DiagnosticWarn' },
        { pat = '%-%-%-%-BEGIN RSA PRIVATE KEY%-%-%-%-', msg = 'private key material in source', hl = 'DiagnosticError' },
        { pat = '%-%-%-%-BEGIN PRIVATE KEY%-%-%-%-', msg = 'private key material in source', hl = 'DiagnosticError' }
    }
}
  return patterns_by_ft[ft] or patterns_by_ft.default
end

function M._get_security_explanation(pattern, matched_text, ft)
  local explanations = {
    ["eval (code injection)"] = {
      description = "The eval() function executes arbitrary code from strings, making it vulnerable to code injection attacks.",
      impact = "HIGH - Attackers can execute arbitrary code if they control the input",
      cwe = "CWE-94: Improper Control of Generation of Code",
      recommendation = "Use safer alternatives like JSON.parse() for data or specific parsing libraries",
      examples = {
        python = "Use ast.literal_eval() for safe evaluation of literals",
        javascript = "Use JSON.parse() for data, avoid eval() entirely"
      }
    },
    ["innerHTML assignment (XSS)"] = {
      description = "Direct innerHTML assignment can lead to Cross-Site Scripting (XSS) vulnerabilities",
      impact = "MEDIUM - Untrusted data can execute malicious scripts",
      cwe = "CWE-79: Cross-site Scripting",
      recommendation = "Use textContent for text or properly sanitize HTML",
      examples = {
        javascript = "element.textContent = userInput; // Safe for text content"
      }
    },
    ["hardcoded password"] = {
      description = "Hardcoded credentials in source code pose serious security risks",
      impact = "HIGH - Credentials exposed in version control and deployments",
      cwe = "CWE-798: Use of Hard-coded Credentials",
      recommendation = "Use environment variables or secure credential stores",
      examples = {
        general = "Use process.env.PASSWORD or similar environment variable access"
      }
    }
  }
  
  local explanation = explanations[pattern.msg] or {
    description = pattern.msg,
    impact = "Review required",
    recommendation = "Follow security best practices for this pattern"
  }
  
  local result = string.format("󰌾 Security Issue: %s\n\n", pattern.msg)
  result = result .. string.format("󰦨 Description: %s\n", explanation.description)
  if explanation.impact then
    result = result .. string.format("󰀪 Impact: %s\n", explanation.impact)
  end
  if explanation.cwe then
    result = result .. string.format("󰗃 CWE: %s\n", explanation.cwe)
  end
  result = result .. string.format("󰌶 Recommendation: %s\n", explanation.recommendation)
  
  if explanation.examples and explanation.examples[ft] then
    result = result .. string.format("\n󰦩 Example (%s):\n%s", ft, explanation.examples[ft])
  elseif explanation.examples and explanation.examples.general then
    result = result .. string.format("\n󰦩 Example:\n%s", explanation.examples.general)
  end
  
  return result
end

function M._get_security_actions(pattern, matched_text, ft)
  local actions = {}
  
  -- Always available actions
  table.insert(actions, ACTION_TYPES.allowlist)
  table.insert(actions, ACTION_TYPES.ignore_inline)
  table.insert(actions, ACTION_TYPES.explain)
  
  -- Conditional actions based on pattern type
  if pattern.msg:match("eval") or pattern.msg:match("innerHTML") then
    table.insert(actions, ACTION_TYPES.apply_fix)
    table.insert(actions, ACTION_TYPES.copy_snippet)
  end
  
  if pattern.hl == "DiagnosticError" then
    table.insert(actions, ACTION_TYPES.quick_docs)
  end
  
  return actions
end

function M._get_code_actions(func_info)
  local actions = {}
  
  table.insert(actions, ACTION_TYPES.explain)
  
  if func_info.complexity > 10 then
    table.insert(actions, ACTION_TYPES.refactor)
  end
  
  if func_info.lines > 50 then
    table.insert(actions, ACTION_TYPES.refactor)
  end
  
  return actions
end

function M._get_debug_actions(debug_type, matched_text)
  local actions = {}
  
  if debug_type == "debug_log" or debug_type == "debug_print" then
    table.insert(actions, ACTION_TYPES.ignore_inline)
    table.insert(actions, ACTION_TYPES.apply_fix) -- Remove debug statement
  elseif debug_type == "todo" or debug_type == "fixme" then
    table.insert(actions, ACTION_TYPES.explain)
    table.insert(actions, ACTION_TYPES.create_config) -- Create task/issue
  end
  
  return actions
end

function M._get_function_at_cursor(bufnr, cursor_pos)
  local line_nr = cursor_pos[1]
  local utils = require('traceback.lenses.utils')
  
  if not utils.ts_available(bufnr, { treesitter = true }) then
    return nil
  end
  
  local ft = vim.bo[bufnr].filetype
  local query = utils.get_ts_query(ft, 'functions')
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
        for name_id, name_node in query:iter_captures(node, bufnr) do
          if query.captures[name_id] == 'name' then
            func_name = utils.get_node_text(name_node, bufnr)
            break
          end
        end
        
        return {
          name = func_name,
          range = { start = { sr + 1, sc }, ["end"] = { er + 1, ec } },
          lines = er - sr + 1,
          complexity = M._calculate_complexity(node, bufnr)
        }
      end
    end
  end
  
  return nil
end

function M._calculate_complexity(node, bufnr)
  -- Simple complexity calculation based on control flow statements
  local complexity = 1
  local query_text = [[
    (if_statement) @if
    (while_statement) @while
    (for_statement) @for
    (try_statement) @try
    (case_statement) @case
  ]]
  
  local ft = vim.bo[bufnr].filetype
  local ok, query = pcall(vim.treesitter.query.parse, ft, query_text)
  if ok and query then
    for _ in query:iter_captures(node, bufnr) do
      complexity = complexity + 1
    end
  end
  
  return complexity
end

function M._get_severity_from_hl(hl_group)
  local severity_map = {
    DiagnosticError = "error",
    DiagnosticWarn = "warning",
    DiagnosticInfo = "info",
    DiagnosticHint = "hint"
  }
  return severity_map[hl_group] or "info"
end

function M._get_complexity_severity(complexity)
  if complexity > 15 then return "error"
  elseif complexity > 10 then return "warning"
  else return "info" end
end

function M.get_annotations_at_cursor(bufnr, cursor_pos)
  bufnr = bufnr or api.nvim_get_current_buf()
  cursor_pos = cursor_pos or api.nvim_win_get_cursor(0)
  
  -- Input validation
  if not validate_buffer(bufnr) then
    if cfg.error_handling then
  U.notify("Invalid buffer for annotations", vim.log.levels.DEBUG)
    end
    return {}
  end

  if not validate_position(cursor_pos) then
    if cfg.error_handling then
  U.notify("Invalid cursor position for annotations", vim.log.levels.DEBUG)
    end
    return {}
  end

  -- Ensure at least one provider is registered 
  if next(providers) == nil then
    if cfg.error_handling then
  U.notify("TraceBack: no providers registered. Call require('traceback.actions').setup() or enable auto_register_lens_providers in setup()", vim.log.levels.WARN)
    end
    pcall(M._register_default_providers)
  end

  local all_annotations = {}
  local start_time = os.clock()
  local timeout_seconds = (cfg.timeout_ms or 1000) / 1000
  
  -- Collect annotations from all registered providers
  for name, provider in pairs(providers) do
    -- Check timeout
    if os.clock() - start_time > timeout_seconds then
      if cfg.error_handling then
  U.notify("Annotation collection timeout", vim.log.levels.WARN)
      end
      break
    end
    
    local ok, annotations = pcall(provider, bufnr, cursor_pos)
    if ok and type(annotations) == "table" then
      for _, annotation in ipairs(annotations) do
        if annotation and type(annotation) == "table" then
          annotation.provider = name
          table.insert(all_annotations, annotation)
        end
      end
    elseif cfg.error_handling then
  U.notify("Provider " .. name .. " failed: " .. tostring(annotations), vim.log.levels.DEBUG)
    end
  end
  
  -- Limit results to prevent performance issues
  local max_annotations = cfg.max_annotations_per_provider * vim.tbl_count(providers)
  if #all_annotations > max_annotations then
    all_annotations = vim.list_slice(all_annotations, 1, max_annotations)
  end
  
  -- Sort by severity (error > warning > info) and then by priority
  table.sort(all_annotations, function(a, b)
    local severity_order = { error = 3, warning = 2, info = 1 }
    local a_severity = severity_order[a.severity] or 1
    local b_severity = severity_order[b.severity] or 1
    
    if a_severity ~= b_severity then
      return a_severity > b_severity
    end
    
    return (a.priority or 10) < (b.priority or 10)
  end)
  
  return all_annotations
end

function M.show_actions()
  local bufnr = api.nvim_get_current_buf()
  local cursor_pos = api.nvim_win_get_cursor(0)
  local annotations = M.get_annotations_at_cursor(bufnr, cursor_pos)
  
  if #annotations == 0 then
  U.notify("󰘖 No TraceBack annotations found at cursor", vim.log.levels.INFO)
    return
  end
  
  -- If multiple annotations, let user choose
  if #annotations > 1 then
    local items = {}
    for i, annotation in ipairs(annotations) do
      table.insert(items, string.format("%s %s [%s]", 
        M._get_severity_icon(annotation.severity),
        annotation.title,
        annotation.provider or "unknown"
      ))
    end
    
    vim.ui.select(items, {
      prompt = "󰒓 Select annotation:",
      format_item = function(item) return item end
    }, function(_, idx)
      if idx then
        M.show_actions_for_annotation(annotations[idx])
      end
    end)
  else
    M.show_actions_for_annotation(annotations[1])
  end
end

function M.show_actions_for_annotation(annotation)
  if not annotation.actions or #annotation.actions == 0 then
  U.notify("󰘖 No actions available for this annotation", vim.log.levels.INFO)
    return
  end
  
  local items = {}
  for _, action in ipairs(annotation.actions) do
    table.insert(items, string.format("%s %s - %s", 
      action.icon, action.title, action.desc
    ))
  end
  
  vim.ui.select(items, {
    prompt = string.format("󰒓 Actions for '%s':", annotation.title),
    format_item = function(item) return item end
  }, function(_, idx)
    if idx then
      M.execute_action(annotation.actions[idx], annotation)
    end
  end)
end

function M.execute_action(action, annotation)
  local action_handlers = {
    allowlist = M._handle_allowlist,
    ignore_inline = M._handle_ignore_inline,
    ignore_virtual = M._handle_ignore_virtual,
    explain = M._handle_explain,
    apply_fix = M._handle_apply_fix,
    refactor = M._handle_refactor,
    suppress_file = M._handle_suppress_file,
    create_config = M._handle_create_config,
    quick_docs = M._handle_quick_docs,
    copy_snippet = M._handle_copy_snippet
  }
  
  local handler = action_handlers[action.title:lower():gsub(" ", "_")]
  if handler then
    handler(annotation)
  else
  U.notify(string.format("󰘩 Action '%s' not implemented yet", action.title), vim.log.levels.WARN)
  end
end

-- Action handlers
function M._handle_allowlist(annotation)
  if annotation.type == "security" then
    local security_lens = require('traceback.lenses.lens_security')
    local pattern = annotation.matched_text or annotation.title
    security_lens.add_allow(pattern)
  U.notify(string.format("󰌾 Added '%s' to security allowlist", pattern), vim.log.levels.INFO)
    
    -- Re-render lenses to reflect the change
    require('traceback.lenses').render()
  else
  U.notify("󰘖 Allowlist action only available for security annotations", vim.log.levels.WARN)
  end
end

function M._handle_ignore_inline(annotation)
  local bufnr = api.nvim_get_current_buf()
  local line_nr = annotation.range.start[1]
  local ft = vim.bo[bufnr].filetype
  
  local comment_tokens = {
    lua = "--",
    python = "#",
    javascript = "//",
    typescript = "//",
    c = "//",
    cpp = "//",
    go = "//",
    rust = "//",
    java = "//",
    php = "//",
    ruby = "#",
    shell = "#",
    bash = "#",
    default = "#"
  }
  
  local comment_token = comment_tokens[ft] or comment_tokens.default
  local ignore_comment = string.format(" %s traceback-ignore: %s", comment_token, annotation.title)
  
  local line = api.nvim_buf_get_lines(bufnr, line_nr - 1, line_nr, false)[1]
  local new_line = line .. ignore_comment
  
  api.nvim_buf_set_lines(bufnr, line_nr - 1, line_nr, false, { new_line })
  U.notify("󰘖 Added inline ignore comment", vim.log.levels.INFO)
end

function M._handle_ignore_virtual(annotation)
  local bufnr = api.nvim_get_current_buf()
  local line_nr = annotation.range.start[1]
  
  api.nvim_buf_set_extmark(bufnr, ns_actions, line_nr - 1, 0, {
    virt_text = { { " 󰘕 traceback-ignore", "Comment" } },
    virt_text_pos = 'eol',
    hl_mode = 'combine'
  })
  
  U.notify("󰘕 Added virtual ignore marker", vim.log.levels.INFO)
end

function M._handle_explain(annotation)
  if annotation.message then
    -- Show in a floating window for better readability
    local lines = vim.split(annotation.message, "\n")
    local width = 0
    for _, line in ipairs(lines) do
      width = math.max(width, #line)
    end
    width = math.min(width, 80)
    
    local buf = api.nvim_create_buf(false, true)
    api.nvim_buf_set_lines(buf, 0, -1, false, lines)
    api.nvim_buf_set_option(buf, 'filetype', 'markdown')
    
    local win = api.nvim_open_win(buf, true, {
      relative = 'cursor',
      width = width,
      height = math.min(#lines, 20),
      col = 0,
      row = 1,
      border = 'rounded',
      style = 'minimal',
      title = " 󰋽 " .. annotation.title,
      title_pos = 'center'
    })
    
    -- Close window on escape or q
    vim.keymap.set('n', '<Esc>', function() api.nvim_win_close(win, true) end, { buffer = buf })
    vim.keymap.set('n', 'q', function() api.nvim_win_close(win, true) end, { buffer = buf })
  else
  U.notify("󰋽 " .. annotation.title, vim.log.levels.INFO)
  end
end

function M._handle_apply_fix(annotation)
  -- Enhanced fix templates with more comprehensive coverage
  local fixes = {
    ["eval (code injection)"] = {
      javascript = function(matched_text, context)
        if matched_text:match("JSON") then
          return "JSON.parse(" .. context.params .. ")"
        else
          return "// Use JSON.parse() for data or specific parsing libraries instead of eval()"
        end
      end,
      python = function(matched_text, context)
        return "ast.literal_eval(" .. context.params .. ")"
      end,
      lua = function(matched_text, context)
        return "-- Use specific parsing instead of loadstring: loadstring() removed"
      end
    },
    ["innerHTML assignment (XSS)"] = {
      javascript = function(matched_text, context)
        if context.is_text_only then
          return context.element .. ".textContent = " .. context.value
        else
          return context.element .. ".appendChild(document.createTextNode(" .. context.value .. "))"
        end
      end
    },
    ["system call (command injection)"] = {
      c = function(matched_text, context)
        return "// Use safer alternatives like execvp() with proper argument validation"
      end,
      python = function(matched_text, context)
        if context.params then
          return "subprocess.run([" .. context.params:gsub("%s+", "\", \"") .. "], check=True)"
        else
          return "subprocess.run(command_args, check=True)  # Use list format"
        end
      end,
      lua = function(matched_text, context)
        return "-- Use io.popen with proper validation or avoid shell execution"
      end
    },
    ["hardcoded password"] = {
      all = function(matched_text, context)
        local var_name = context.variable_name or "secret_value"
        local env_var = var_name:upper():gsub("PASSWORD", "PASS"):gsub("SECRET", "SEC")
        return string.format("%s = os.getenv('%s') or error('Environment variable %s not set')", 
                           var_name, env_var, env_var)
      end
    },
    ["strcpy (buffer overflow)"] = {
      c = function(matched_text, context)
        return "strncpy(" .. context.dest .. ", " .. context.src .. ", sizeof(" .. context.dest .. ") - 1)"
      end
    },
    ["sprintf (buffer overflow)"] = {
      c = function(matched_text, context)
        return "snprintf(" .. context.buffer .. ", sizeof(" .. context.buffer .. "), " .. context.format .. ", " .. context.args .. ")"
      end
    },
    ["console.log"] = {
      javascript = function(matched_text, context)
        if vim.bo.filetype == "javascript" and not context.is_debug_environment then
          return "// console.log removed for production"
        else
          return matched_text -- Keep in development
        end
      end
    },
    ["print() call"] = {
      python = function(matched_text, context)
        if context.args then
          return "logging.debug(" .. context.args .. ")"
        else
          return "# print() call removed"
        end
      end,
      lua = function(matched_text, context)
        if context.args then
          return "-- Debug: " .. matched_text:gsub("print", "-- print")
        else
          return "-- print() call removed"
        end
      end,
      go = function(matched_text, context)
        if context.args then
          return "log.Printf(\"Debug: %v\\n\", " .. context.args .. ")"
        else
          return "// fmt.Println call removed"
        end
      end
    },
    ["exec.Command (command injection)"] = {
      go = function(matched_text, context)
        return "// Use exec.CommandContext with proper validation and limited arguments\n" ..
               "ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)\n" ..
               "defer cancel()\n" ..
               "cmd := exec.CommandContext(ctx, command, validatedArgs...)"
      end
    },
    ["SQL query (potential injection)"] = {
      go = function(matched_text, context)
        return "// Use parameterized queries to prevent SQL injection\n" ..
               "rows, err := db.Query(\"SELECT * FROM table WHERE id = ?\", userID)"
      end
    },
    ["SQL exec (potential injection)"] = {
      go = function(matched_text, context)
        return "// Use parameterized statements to prevent SQL injection\n" ..
               "_, err := db.Exec(\"UPDATE table SET value = ? WHERE id = ?\", newValue, userID)"
      end
    },
    ["HTTP listener without TLS"] = {
      go = function(matched_text, context)
        return "// Use HTTPS with proper TLS configuration\n" ..
               "server := &http.Server{\n" ..
               "    Addr: \":8443\",\n" ..
               "    Handler: handler,\n" ..
               "    TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},\n" ..
               "}\n" ..
               "log.Fatal(server.ListenAndServeTLS(\"server.crt\", \"server.key\"))"
      end
    },
    ["template.HTML (XSS sink)"] = {
      go = function(matched_text, context)
        return "// Sanitize user input before rendering\n" ..
               "import \"html\"\n" ..
               "safeContent := html.EscapeString(userInput)\n" ..
               "// Use text/template instead of html/template for untrusted content"
      end
    },
    ["MD5 used (weak hash)"] = {
      go = function(matched_text, context)
        return "// Use SHA-256 or stronger hash algorithm\n" ..
               "import \"crypto/sha256\"\n" ..
               "hasher := sha256.New()\n" ..
               "hasher.Write(data)\n" ..
               "hash := hasher.Sum(nil)"
      end
    },
    ["SHA1 used (weak hash)"] = {
      go = function(matched_text, context)
        return "// Use SHA-256 or stronger hash algorithm\n" ..
               "import \"crypto/sha256\"\n" ..
               "hasher := sha256.New()\n" ..
               "hasher.Write(data)\n" ..
               "hash := hasher.Sum(nil)"
      end
    },
    ["Network connection without TLS"] = {
      go = function(matched_text, context)
        return "// Use TLS for secure connections\n" ..
               "import \"crypto/tls\"\n" ..
               "config := &tls.Config{MinVersion: tls.VersionTLS12}\n" ..
               "conn, err := tls.Dial(\"tcp\", address, config)"
      end
    },
    ["unsafe.Pointer usage (memory safety risk)"] = {
      go = function(matched_text, context)
        return "// Avoid unsafe.Pointer; use type-safe alternatives\n" ..
               "// Consider using interface{} or proper type conversion\n" ..
               "// If unavoidable, ensure proper bounds checking and validation"
      end
    },
    ["panic() call (consider error return instead)"] = {
      go = function(matched_text, context)
        return "// Return error instead of panic for better error handling\n" ..
               "if err != nil {\n" ..
               "    return fmt.Errorf(\"operation failed: %w\", err)\n" ..
               "}"
      end
    },
    ["HTTP GET without timeout or TLS verification"] = {
      go = function(matched_text, context)
        return "// Use HTTP client with proper timeout and TLS verification\n" ..
               "client := &http.Client{\n" ..
               "    Timeout: 30 * time.Second,\n" ..
               "    Transport: &http.Transport{\n" ..
               "        TLSClientConfig: &tls.Config{InsecureSkipVerify: false},\n" ..
               "    },\n" ..
               "}\n" ..
               "resp, err := client.Get(url)"
      end
    }
  }
  
  local bufnr = api.nvim_get_current_buf()
  local ft = vim.bo[bufnr].filetype
  local range = annotation.range
  
  -- Extract context from the matched text and surrounding code
  local context = M._extract_fix_context(bufnr, range, annotation)
  
  -- Try to find a fix for this specific issue
  local fix_function = nil
  local fix_templates = fixes[annotation.title]
  
  if fix_templates then
    fix_function = fix_templates[ft] or fix_templates.all
  end
  
  if fix_function and type(fix_function) == "function" then
    local old_text = api.nvim_buf_get_text(bufnr, 
      range.start[1] - 1, range.start[2],
      range["end"][1] - 1, range["end"][2], {})[1]
    
    local new_text = fix_function(old_text, context)
    
    -- Apply the fix with confirmation for significant changes
    if M._should_confirm_fix(old_text, new_text) then
      vim.ui.input({
        prompt = string.format("Apply fix?\nOld: %s\nNew: %s\n(y/N): ", old_text, new_text)
      }, function(input)
        if input and input:lower() == 'y' then
          M._apply_text_replacement(bufnr, range, new_text)
        end
      end)
    else
      M._apply_text_replacement(bufnr, range, new_text)
    end
  else
    -- Try to provide generic smart fixes
    M._handle_generic_smart_fix(annotation, context)
  end
end

function M._extract_fix_context(bufnr, range, annotation)
  local context = {}
  local line_nr = range.start[1]
  local line = api.nvim_buf_get_lines(bufnr, line_nr - 1, line_nr, false)[1]
  
  if not line then return context end
  
  -- Extract variable names, function parameters, etc.
  local matched_text = annotation.matched_text or ""
  
  -- Try to extract function parameters
  local params = line:match("%(([^%)]+)%)")
  if params then
    context.params = params
  end
  
  -- Try to extract variable assignments
  local var_name = line:match("([%w_]+)%s*=")
  if var_name then
    context.variable_name = var_name
  end
  
  -- For innerHTML cases, try to extract element and value
  if annotation.title:match("innerHTML") then
    local element = line:match("([%w_.]+)%.innerHTML")
    local value = line:match("innerHTML%s*=%s*(.+)")
    context.element = element or "element"
    context.value = value or "userInput"
    context.is_text_only = not (value and value:match("<"))
  end
  
  -- For buffer overflow cases, extract buffer names
  if annotation.title:match("buffer overflow") then
    local dest, src = line:match("%(([^,]+),%s*([^,%)]+)")
    context.dest = dest or "dest"
    context.src = src or "src"
  end
  
  -- Check if we're in a debug/development environment
  context.is_debug_environment = M._is_debug_environment(bufnr)
  
  -- Extract function context
  local utils = require('traceback.lenses.utils')
  local func_info = utils.get_function_at_line(bufnr, line_nr)
  if func_info then
    context.function_name = func_info.name
    context.in_function = true
  end
  
  return context
end

function M._should_confirm_fix(old_text, new_text)
  -- Confirm for significant changes or when removing code entirely
  if new_text:match("^%s*%-%-") or new_text:match("^%s*//") or new_text:match("^%s*#") then
    return true -- Commenting out code
  end
  if #new_text < #old_text * 0.5 then
    return true -- Significant reduction in code
  end
  if new_text:match("error%(") or new_text:match("throw") then
    return true -- Adding error conditions
  end
  return false
end

function M._apply_text_replacement(bufnr, range, new_text)
  -- Handle multiline replacements
  local lines = vim.split(new_text, "\n")
  
  api.nvim_buf_set_text(bufnr,
    range.start[1] - 1, range.start[2],
    range["end"][1] - 1, range["end"][2],
    lines)
  
  U.notify(string.format("󰁨 Applied fix: %s", lines[1]), vim.log.levels.INFO)
  
  -- If we added multiple lines, adjust cursor position
  if #lines > 1 then
    local cursor_pos = api.nvim_win_get_cursor(0)
    api.nvim_win_set_cursor(0, {cursor_pos[1] + #lines - 1, 0})
  end
end

function M._handle_generic_smart_fix(annotation, context)
  -- Generic smart fixes based on patterns
  local bufnr = api.nvim_get_current_buf()
  local range = annotation.range
  local line = api.nvim_buf_get_lines(bufnr, range.start[1] - 1, range.start[1], false)[1]
  
  -- Remove debug statements
  if annotation.type == "debug" then
    local comment_token = M._get_comment_token(vim.bo[bufnr].filetype)
    local new_line = comment_token .. " " .. line
    api.nvim_buf_set_lines(bufnr, range.start[1] - 1, range.start[1], false, { new_line })
  U.notify("󰁨 Commented out debug statement", vim.log.levels.INFO)
    return
  end
  
  -- Add TODO comments for complex issues
  if annotation.severity == "error" and not annotation.matched_text then
    local comment_token = M._get_comment_token(vim.bo[bufnr].filetype)
    local todo_line = comment_token .. " TODO: Fix " .. annotation.title
    api.nvim_buf_set_lines(bufnr, range.start[1] - 1, range.start[1] - 1, false, { todo_line })
    vim.notify("󰁨 Added TODO comment for manual review", vim.log.levels.INFO)
    return
  end
  
  vim.notify("󰘖 No automatic fix available for this issue", vim.log.levels.WARN)
end

function M._is_debug_environment(bufnr)
  local file_path = api.nvim_buf_get_name(bufnr)
  if file_path:match("test") or file_path:match("spec") or file_path:match("debug") then
    return true
  end
  
  -- Check for development indicators in the file
  local lines = api.nvim_buf_get_lines(bufnr, 0, 50, false) -- Check first 50 lines
  for _, line in ipairs(lines) do
    if line:match("NODE_ENV.*development") or line:match("DEBUG.*true") then
      return true
    end
  end
  
  return false
end

function M._get_comment_token(filetype)
  local comment_tokens = {
    lua = "--",
    python = "#",
    javascript = "//",
    typescript = "//",
    c = "//",
    cpp = "//",
    go = "//",
    rust = "//",
    java = "//",
    php = "//",
    ruby = "#",
    shell = "#",
    bash = "#",
    default = "#"
  }
  return comment_tokens[filetype] or comment_tokens.default
end

function M._handle_refactor(annotation)
  local bufnr = api.nvim_get_current_buf()
  local suggestions = M._generate_refactor_suggestions(bufnr, annotation)
  
  if #suggestions == 0 then
    vim.notify("󰘖 No refactoring suggestions available for this code", vim.log.levels.INFO)
    return
  end
  
  if #suggestions == 1 then
    M._apply_refactor_suggestion(bufnr, suggestions[1])
  else
    -- Multiple suggestions - let user choose
    local items = {}
    for _, suggestion in ipairs(suggestions) do
      table.insert(items, string.format("%s %s - %s", 
        suggestion.icon, suggestion.title, suggestion.description))
    end
    
    vim.ui.select(items, {
      prompt = "󰖷 Select refactoring:",
      format_item = function(item) return item end
    }, function(_, idx)
      if idx then
        M._apply_refactor_suggestion(bufnr, suggestions[idx])
      end
    end)
  end
end

function M._generate_refactor_suggestions(bufnr, annotation)
  local suggestions = {}
  local range = annotation.range
  local line_nr = range.start[1]
  local ft = vim.bo[bufnr].filetype
  
  -- Get the code to refactor
  local lines = api.nvim_buf_get_lines(bufnr, range.start[1] - 1, range["end"][1], false)
  local code = table.concat(lines, "\n")
  
  -- Function-level refactoring suggestions
  if annotation.type == "code" and annotation.title:match("Function:") then
    local func_info = M._get_function_at_cursor(bufnr, {line_nr, 0})
    if func_info then
      -- High complexity function
      if func_info.complexity > 10 then
        table.insert(suggestions, {
          icon = "󰖷",
          title = "Extract methods",
          description = "Break down complex function into smaller methods",
          type = "extract_methods",
          range = func_info.range,
          complexity = func_info.complexity
        })
      end
      
      -- Long function
      if func_info.lines > 30 then
        table.insert(suggestions, {
            icon = "󰏗",
          title = "Split function",
          description = "Divide long function into logical parts",
          type = "split_function", 
          range = func_info.range,
          lines = func_info.lines
        })
      end
      
      -- Add error handling if missing
      if not M._has_error_handling(bufnr, func_info.range) then
        table.insert(suggestions, {
          icon = "󰄄",
          title = "Add error handling",
          description = "Wrap function code with proper error handling",
          type = "add_error_handling",
          range = func_info.range
        })
      end
    end
  end
  
  -- Code pattern-based suggestions
  table.insert(suggestions, unpack(M._get_pattern_refactor_suggestions(code, ft, range)))
  
  -- Language-specific suggestions
  if ft == "lua" then
    table.insert(suggestions, unpack(M._get_lua_refactor_suggestions(code, range)))
  elseif ft == "javascript" or ft == "typescript" then
    table.insert(suggestions, unpack(M._get_js_refactor_suggestions(code, range)))
  elseif ft == "python" then
    table.insert(suggestions, unpack(M._get_python_refactor_suggestions(code, range)))
  end
  
  return suggestions
end

function M._get_pattern_refactor_suggestions(code, ft, range)
  local suggestions = {}
  
  -- Magic numbers
  if code:match("%d+%.%d+") or code:match("[^%w_]%d%d+[^%w_]") then
    table.insert(suggestions, {
      icon = "󰆉",
      title = "Extract constants",
      description = "Replace magic numbers with named constants",
      type = "extract_constants",
      range = range
    })
  end
  
  -- Repeated code patterns
  local lines = vim.split(code, "\n")
  local repeated_patterns = M._find_repeated_patterns(lines)
  if #repeated_patterns > 0 then
    table.insert(suggestions, {
      icon = "󰑃",
      title = "Extract common code",
      description = "Create helper functions for repeated patterns",
      type = "extract_common",
      range = range,
      patterns = repeated_patterns
    })
  end
  
  -- Long parameter lists
  if code:match("function[^%(]*%(([^%)]*,[^%)]*,[^%)]*,[^%)]*,)") then
    table.insert(suggestions, {
      icon = "󰏗",
      title = "Simplify parameters",
      description = "Use object/table parameter instead of long parameter list",
      type = "simplify_parameters",
      range = range
    })
  end
  
  -- Nested conditions
  local nesting_level = M._calculate_nesting_level(code)
  if nesting_level > 3 then
    table.insert(suggestions, {
      icon = "󰘞",
      title = "Reduce nesting",
      description = "Use early returns or guard clauses to reduce nesting",
      type = "reduce_nesting",
      range = range,
      nesting_level = nesting_level
    })
  end
  
  return suggestions
end

function M._get_lua_refactor_suggestions(code, range)
  local suggestions = {}
  
  -- Use local variables
  if code:match("%s+[^%s]+%s*=%s*[^%s]+") and not code:match("local") then
    table.insert(suggestions, {
      icon = "󰳽",
      title = "Add local keywords",
      description = "Declare variables as local for better performance",
      type = "add_local",
      range = range
    })
  end
  
  -- String concatenation optimization
  if code:match('%.%..*%.%..*%.%.') then
    table.insert(suggestions, {
      icon = "󰓩",
      title = "Optimize string concat",
      description = "Use table.concat for multiple string concatenations",
      type = "optimize_concat",
      range = range
    })
  end
  
  -- Table construction optimization
  if code:match("table%.insert%(.*table%.insert%(") then
    table.insert(suggestions, {
      icon = "󰒅",
      title = "Optimize table construction",
      description = "Use array-style table construction",
      type = "optimize_table",
      range = range
    })
  end
  
  return suggestions
end

function M._get_js_refactor_suggestions(code, range)
  local suggestions = {}
  
  -- Use const/let instead of var
  if code:match("var%s+") then
    table.insert(suggestions, {
      icon = "󰯳",
      title = "Modernize variables",
      description = "Replace var with const/let",
      type = "modernize_vars",
      range = range
    })
  end
  
  -- Arrow functions
  if code:match("function%s*%(") and not code:match("function%s+%w+") then
    table.insert(suggestions, {
      icon = "󰜎",
      title = "Use arrow functions",
      description = "Convert anonymous functions to arrow functions",
      type = "arrow_functions",
      range = range
    })
  end
  
  -- Template literals
  if code:match('"%s*%+') or code:match("'%s*%+") then
    table.insert(suggestions, {
      icon = "󰦸",
      title = "Use template literals",
      description = "Replace string concatenation with template literals",
      type = "template_literals",
      range = range
    })
  end
  
  -- Async/await over promises
  if code:match("%.then%(") and code:match("%.catch%(") then
    table.insert(suggestions, {
      icon = "󰃮",
      title = "Convert to async/await",
      description = "Replace .then()/.catch() with async/await",
      type = "async_await",
      range = range
    })
  end
  
  return suggestions
end

function M._get_python_refactor_suggestions(code, range)
  local suggestions = {}
  
  -- List comprehensions
  if code:match("for%s+.+%s+in%s+.+:") and code:match("%.append%(") then
    table.insert(suggestions, {
      icon = "󰦸",
      title = "Use list comprehension",
      description = "Replace for loop with list comprehension",
      type = "list_comprehension", 
      range = range
    })
  end
  
  -- F-strings
  if code:match('"%s*%%') or code:match("%.format%(") then
    table.insert(suggestions, {
      icon = "󰓎",
      title = "Use f-strings",
      description = "Modernize string formatting with f-strings",
      type = "f_strings",
      range = range
    })
  end
  
  -- Context managers
  if code:match("open%(") and not code:match("with%s+") then
    table.insert(suggestions, {
      icon = "󰯳",
      title = "Use context manager",
      description = "Wrap file operations with 'with' statement",
      type = "context_manager",
      range = range
    })
  end
  
  return suggestions
end

function M._apply_refactor_suggestion(bufnr, suggestion)
  local handlers = {
    extract_constants = M._refactor_extract_constants,
    extract_methods = M._refactor_extract_methods,
    split_function = M._refactor_split_function,
    add_error_handling = M._refactor_add_error_handling,
    extract_common = M._refactor_extract_common,
    simplify_parameters = M._refactor_simplify_parameters,
    reduce_nesting = M._refactor_reduce_nesting,
    add_local = M._refactor_add_local,
    optimize_concat = M._refactor_optimize_concat,
    optimize_table = M._refactor_optimize_table,
    modernize_vars = M._refactor_modernize_vars,
    arrow_functions = M._refactor_arrow_functions,
    template_literals = M._refactor_template_literals,
    async_await = M._refactor_async_await,
    list_comprehension = M._refactor_list_comprehension,
    f_strings = M._refactor_f_strings,
    context_manager = M._refactor_context_manager
  }
  
  local handler = handlers[suggestion.type]
  if handler then
    handler(bufnr, suggestion)
  else
    vim.notify(string.format("󰘩 Refactoring '%s' not fully implemented yet", suggestion.title), vim.log.levels.WARN)
    -- Show suggestion details for manual implementation
    M._show_refactor_guidance(suggestion)
  end
end

function M._show_refactor_guidance(suggestion)
  local guidance = {
    extract_constants = "Consider extracting magic numbers to named constants at the top of the file",
    extract_methods = "Look for logical blocks within the function that can be extracted to separate methods",
    split_function = "Consider breaking this function into smaller, single-purpose functions",
    add_error_handling = "Add try-catch blocks or validation for potential error conditions",
    reduce_nesting = "Use early returns, guard clauses, or extraction methods to reduce nesting"
  }
  
  local message = guidance[suggestion.type] or "Manual refactoring recommended for this pattern"
  vim.notify(string.format("󰗮 Guidance: %s", message), vim.log.levels.INFO)
end

-- Utility functions for refactoring analysis
function M._has_error_handling(bufnr, range)
  local lines = api.nvim_buf_get_lines(bufnr, range.start[1] - 1, range["end"][1], false)
  local code = table.concat(lines, "\n"):lower()
  
  return code:match("try") or code:match("catch") or code:match("error") or 
         code:match("pcall") or code:match("xpcall") or code:match("assert")
end

function M._find_repeated_patterns(lines)
  local patterns = {}
  local seen = {}
  
  for i, line in ipairs(lines) do
    local trimmed = line:match("^%s*(.-)%s*$") -- trim whitespace
    if #trimmed > 10 then -- Only consider substantial lines
      if seen[trimmed] then
        table.insert(patterns, {
          pattern = trimmed,
          lines = {seen[trimmed], i}
        })
      else
        seen[trimmed] = i
      end
    end
  end
  
  return patterns
end

function M._calculate_nesting_level(code)
  local level = 0
  local max_level = 0
  
  for char in code:gmatch(".") do
    if char == "{" or char == "(" then
      level = level + 1
      max_level = math.max(max_level, level)
    elseif char == "}" or char == ")" then
      level = level - 1
    end
  end
  
  return max_level
end

-- Simplified refactoring implementations (examples)
function M._refactor_add_local(bufnr, suggestion)
  local range = suggestion.range
  local lines = api.nvim_buf_get_lines(bufnr, range.start[1] - 1, range["end"][1], false)
  
  for i, line in ipairs(lines) do
    local new_line = line:gsub("(%s*)([%w_]+%s*=)", "%1local %2")
    if new_line ~= line then
      lines[i] = new_line
    end
  end
  
  api.nvim_buf_set_lines(bufnr, range.start[1] - 1, range["end"][1], false, lines)
  vim.notify("󰚰 Added local keywords to variable declarations", vim.log.levels.INFO)
end

function M._refactor_modernize_vars(bufnr, suggestion)
  local range = suggestion.range
  local lines = api.nvim_buf_get_lines(bufnr, range.start[1] - 1, range["end"][1], false)

  for i, line in ipairs(lines) do
    -- Simple heuristic: use const for assignments without reassignment
    if line:match("%f[%w]var%s+") and not line:match("=.*=") then
      lines[i] = line:gsub("%f[%w]var%s+", "const ")
    end
  end

  api.nvim_buf_set_lines(bufnr, range.start[1] - 1, range["end"][1], false, lines)
  vim.notify("󰚰 Modernized variable declarations", vim.log.levels.INFO)
end

function M._refactor_add_error_handling(bufnr, suggestion)
  local range = suggestion.range
  local lines = api.nvim_buf_get_lines(bufnr, range.start[1] - 1, range["end"][1], false)
  local ft = vim.bo[bufnr].filetype
  
  -- Add basic error handling wrapper based on language
  if ft == "lua" then
    table.insert(lines, 1, "  local ok, result = pcall(function()")
    table.insert(lines, "  end)")
    table.insert(lines, "  if not ok then")
    table.insert(lines, "    error('Function failed: ' .. tostring(result))")
    table.insert(lines, "  end")
    table.insert(lines, "  return result")
  elseif ft == "javascript" or ft == "typescript" then
    table.insert(lines, 1, "  try {")
    table.insert(lines, "  } catch (error) {")
    table.insert(lines, "    console.error('Function failed:', error);")
    table.insert(lines, "    throw error;")
    table.insert(lines, "  }")
  end
  
  api.nvim_buf_set_lines(bufnr, range.start[1] - 1, range["end"][1], false, lines)
  vim.notify("󰄄 Added error handling wrapper", vim.log.levels.INFO)
end

function M._handle_suppress_file(annotation)
  local bufnr = api.nvim_get_current_buf()
  local ft = vim.bo[bufnr].filetype
  
  local suppress_comments = {
    lua = "-- traceback-disable-file",
    python = "# traceback-disable-file",
    javascript = "/* traceback-disable-file */",
    default = "# traceback-disable-file"
  }
  
  local comment = suppress_comments[ft] or suppress_comments.default
  api.nvim_buf_set_lines(bufnr, 0, 0, false, { comment })
  
  vim.notify("󰩺 Added file-level suppression", vim.log.levels.INFO)
end

function M._handle_create_config(annotation)
  vim.notify("󰒓 Configuration creation will be implemented in future version", vim.log.levels.INFO)
end

function M._handle_quick_docs(annotation)
  local urls = {
    ["eval (code injection)"] = "https://owasp.org/www-community/attacks/Code_Injection",
    ["innerHTML assignment (XSS)"] = "https://owasp.org/www-community/attacks/xss/",
    ["hardcoded password"] = "https://cwe.mitre.org/data/definitions/798.html"
  }
  
  local url = urls[annotation.title]
  if url then
    vim.notify(string.format("󰋚 Opening documentation: %s", url), vim.log.levels.INFO)
    -- In a real implementation, you might open the URL in a browser
    -- For now, just copy to clipboard
    vim.fn.setreg('+', url)
    vim.notify("󰒅 URL copied to clipboard", vim.log.levels.INFO)
  else
    vim.notify("󰘖 No documentation URL available", vim.log.levels.WARN)
  end
end

function M._handle_copy_snippet(annotation)
  local snippets = {
    ["eval (code injection)"] = {
      javascript = "JSON.parse(userInput) // Safe for JSON data",
      python = "import ast; ast.literal_eval(userInput) # Safe for literals"
    },
    ["innerHTML assignment (XSS)"] = {
      javascript = "element.textContent = userInput; // Safe for text"
    }
  }
  
  local ft = vim.bo.filetype
  local snippet_map = snippets[annotation.title]
  
  if snippet_map and snippet_map[ft] then
    vim.fn.setreg('+', snippet_map[ft])
    vim.notify(string.format("󰒅 Copied secure snippet to clipboard: %s", snippet_map[ft]), vim.log.levels.INFO)
  else
    vim.notify("󰘖 No secure snippet available", vim.log.levels.WARN)
  end
end

function M._get_severity_icon(severity)
  local icons = {
    error = "󰅚",
    warning = "󰀪",
    info = "󰋽",
    hint = "󰌶"
  }
  return icons[severity] or "󰋽"
end

-- New suggestion functions
function M.show_suggestions_for_buffer()
  if not cfg.enable_smart_suggestions then
    vim.notify("󰘖 Smart suggestions are disabled", vim.log.levels.WARN)
    return
  end
  
  local bufnr = api.nvim_get_current_buf()
  local suggestions_engine = get_suggestions()
  if not suggestions_engine then
    vim.notify("󰧑 Suggestions engine not available", vim.log.levels.ERROR)
    return
  end
  
  local suggestions_ok, suggestions = pcall(suggestions_engine.get_suggestions_for_buffer, bufnr)
  if not suggestions_ok then
    if cfg.error_handling then
      vim.notify("Failed to get buffer suggestions: " .. tostring(suggestions), vim.log.levels.ERROR)
    end
    return
  end
  
  if #(suggestions or {}) == 0 then
    vim.notify("󰧑 No improvement suggestions found for this buffer", vim.log.levels.INFO)
    return
  end
  
  M._show_suggestions_picker(suggestions, "Buffer Improvement Suggestions")
end

function M.show_suggestions_for_function()
  if not cfg.enable_smart_suggestions then
    vim.notify("󰘖 Smart suggestions are disabled", vim.log.levels.WARN)
    return
  end
  
  local bufnr = api.nvim_get_current_buf()
  local cursor_pos = api.nvim_win_get_cursor(0)
  local suggestions_engine = get_suggestions()
  if not suggestions_engine then
    vim.notify("󰧑 Suggestions engine not available", vim.log.levels.ERROR)
    return
  end
  
  local suggestions_ok, suggestions = pcall(suggestions_engine.get_suggestions_for_function_at_cursor, bufnr, cursor_pos)
  if not suggestions_ok then
    if cfg.error_handling then
      vim.notify("Failed to get function suggestions: " .. tostring(suggestions), vim.log.levels.ERROR)
    end
    return
  end
  
  if #(suggestions or {}) == 0 then
    vim.notify("󰧑 No suggestions found for current function", vim.log.levels.INFO)
    return
  end
  
  M._show_suggestions_picker(suggestions, "Function Improvement Suggestions")
end

function M._show_suggestions_picker(suggestions, title)
  local items = {}
  
  for i, suggestion in ipairs(suggestions) do
    local confidence_text = string.format("%.0f%%", suggestion.confidence * 100)
    local item_text = string.format("%s %s [%s confidence, %s impact]", 
      M._get_suggestion_type_icon(suggestion.type),
      suggestion.title,
      confidence_text,
      suggestion.impact or "unknown"
    )
    table.insert(items, item_text)
  end
  
  vim.ui.select(items, {
    prompt = "󰧑 " .. title .. ":",
    format_item = function(item) return item end
  }, function(_, idx)
    if idx then
      M._handle_suggestion_selection(suggestions[idx])
    end
  end)
end

function M._get_suggestion_type_icon(suggestion_type)
  local icons = {
    security = "󰌾",
    refactor = "󰖷",
    performance = "󰓅",
    improvement = "󰧑",
    modernization = "󰚰"
  }
  return icons[suggestion_type] or "󰧑"
end

function M._handle_suggestion_selection(suggestion)
  -- Convert suggestion to annotation format for action handling
  local annotation = {
    id = "suggestion_selected",
    type = "suggestion",
    title = suggestion.title,
    message = M._format_suggestion_message(suggestion),
    range = suggestion.range,
    severity = M._suggestion_severity(suggestion),
    suggestion_data = suggestion,
    actions = M._get_suggestion_actions(suggestion)
  }
  
  M.show_actions_for_annotation(annotation)
end

function M._setup_keymaps()
  if not cfg.keymaps then return end
  
  local function map(lhs, rhs, desc)
    if lhs and lhs ~= '' then
      vim.keymap.set('n', lhs, rhs, { noremap = true, silent = true, desc = desc })
    end
  end
  
  map(cfg.keymaps.show_actions, M.show_actions, "TraceBack: Show actions for annotation at cursor")
  map(cfg.keymaps.quick_fix, function()
    local annotations = M.get_annotations_at_cursor()
    if #annotations > 0 then
      for _, action in ipairs(annotations[1].actions or {}) do
        if action.title:lower():match("fix") then
          M.execute_action(action, annotations[1])
          return
        end
      end
    end
    vim.notify("󰘖 No quick fix available", vim.log.levels.INFO)
  end, "TraceBack: Apply quick fix")
  
  map(cfg.keymaps.explain, function()
    local annotations = M.get_annotations_at_cursor()
    if #annotations > 0 then
      M._handle_explain(annotations[1])
    else
      vim.notify("󰘖 No annotations at cursor", vim.log.levels.INFO)
    end
  end, "TraceBack: Explain annotation at cursor")
  
  map(cfg.keymaps.allowlist, function()
    local annotations = M.get_annotations_at_cursor()
    if #annotations > 0 then
      M._handle_allowlist(annotations[1])
    else
      vim.notify("󰘖 No annotations at cursor", vim.log.levels.INFO)
    end
  end, "TraceBack: Add to allowlist")
  
  -- New suggestion-specific keymaps
  map(cfg.keymaps.suggest_improvements, function()
    M.show_suggestions_for_buffer()
  end, "TraceBack: Show improvement suggestions for buffer")
  
  map(cfg.keymaps.suggest_function, function()
    M.show_suggestions_for_function()
  end, "TraceBack: Show suggestions for current function")
end

function M._setup_commands()
  vim.api.nvim_create_user_command('TracebackActions', M.show_actions, {
    desc = "󰒓 Show TraceBack actions for annotation at cursor"
  })
  
  vim.api.nvim_create_user_command('TracebackQuickFix', function()
    local annotations = M.get_annotations_at_cursor()
    if #annotations > 0 then
      for _, action in ipairs(annotations[1].actions or {}) do
        if action.title:lower():match("fix") then
          M.execute_action(action, annotations[1])
          return
        end
      end
    end
    vim.notify("󰘖 No quick fix available", vim.log.levels.INFO)
  end, {
    desc = "󰁨 Apply quick fix for annotation at cursor"
  })
  
  vim.api.nvim_create_user_command('TracebackExplain', function()
    local annotations = M.get_annotations_at_cursor()
    if #annotations > 0 then
      M._handle_explain(annotations[1])
    else
      vim.notify("󰘖 No annotations at cursor", vim.log.levels.INFO)
    end
  end, {
    desc = "󰋽 Explain annotation at cursor"
  })
  
  vim.api.nvim_create_user_command('TracebackAllowlist', function(opts)
    if opts.args and opts.args ~= '' then
      -- Add specific pattern to allowlist
      local security_lens = require('traceback.lenses.lens_security')
      security_lens.add_allow(opts.args)
      vim.notify(string.format("󰌾 Added '%s' to allowlist", opts.args), vim.log.levels.INFO)
    else
      -- Add current annotation to allowlist
      local annotations = M.get_annotations_at_cursor()
      if #annotations > 0 then
        M._handle_allowlist(annotations[1])
      else
        vim.notify("󰘖 No annotations at cursor or no pattern specified", vim.log.levels.INFO)
      end
    end
  end, {
    nargs = '?',
    desc = "󰌾 Add pattern to allowlist"
  })
  
  vim.api.nvim_create_user_command('TracebackAnnotations', function()
    local bufnr = api.nvim_get_current_buf()
    local cursor_pos = api.nvim_win_get_cursor(0)
    local annotations = M.get_annotations_at_cursor(bufnr, cursor_pos)
    
    if #annotations == 0 then
      vim.notify("󰘖 No annotations found at cursor", vim.log.levels.INFO)
      return
    end
    
    print(string.format("Found %d annotation(s):", #annotations))
    for i, annotation in ipairs(annotations) do
      print(string.format("  %d. [%s] %s (%s)", i, annotation.severity, annotation.title, annotation.provider))
    end
  end, {
    desc = "󰒓 List all annotations at cursor"
  })
  
  -- New suggestion commands
  vim.api.nvim_create_user_command('TracebackSuggest', function(opts)
    local scope = opts.args or "cursor"
    if scope == "buffer" then
      M.show_suggestions_for_buffer()
    elseif scope == "function" then
      M.show_suggestions_for_function()
    else
      M.show_actions()
    end
  end, {
    nargs = '?',
    complete = function() return {'cursor', 'function', 'buffer'} end,
    desc = "󰧑 Show TraceBack suggestions - cursor/function/buffer scope"
  })
  
  vim.api.nvim_create_user_command('TracebackSuggestBuffer', M.show_suggestions_for_buffer, {
    desc = "󰧑 Show improvement suggestions for entire buffer"
  })
  
  vim.api.nvim_create_user_command('TracebackSuggestFunction', M.show_suggestions_for_function, {
    desc = "󰧑 Show suggestions for current function"
  })
  
  vim.api.nvim_create_user_command('TracebackRefactor', function()
    local annotations = M.get_annotations_at_cursor()
    for _, annotation in ipairs(annotations) do
      if annotation.type == "suggestion" and annotation.suggestion_data.type == "refactor" then
        M._handle_explain(annotation)
        return
      end
    end
    vim.notify("󰘖 No refactoring suggestions at cursor", vim.log.levels.INFO)
  end, {
    desc = "󰖷 Show refactoring suggestions for current location"
  })
end

-- Convenience functions for commands
function M.quick_fix_at_cursor()
  local annotations = M.get_annotations_at_cursor()
  if #annotations > 0 then
    for _, action in ipairs(annotations[1].actions or {}) do
      if action.title:lower():match("fix") then
        M.execute_action(action, annotations[1])
        return
      end
    end
  end
  vim.notify("󰘖 No quick fix available", vim.log.levels.INFO)
end

function M.explain_at_cursor()
  local annotations = M.get_annotations_at_cursor()
  if #annotations > 0 then
    M._handle_explain(annotations[1])
  else
    vim.notify("󰘖 No annotations at cursor", vim.log.levels.INFO)
  end
end

function M.allowlist_at_cursor()
  local annotations = M.get_annotations_at_cursor()
  if #annotations > 0 then
    M._handle_allowlist(annotations[1])
  else
    vim.notify("󰘖 No annotations at cursor", vim.log.levels.INFO)
  end
end

return M
