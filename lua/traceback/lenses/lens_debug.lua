local U = require('traceback.lenses.utils')

local M = {}

-- Compile/cache regex per ft
local compiled_cache = {}

-- Language-specific debug patterns with enhanced metadata
local function get_debug_patterns(ft)
  local base_patterns = {
    -- Universal patterns with priorities and confidence scoring
    { pattern = 'Exception', hl = 'DiagnosticError', icon = '󰅚', priority = 1, flags = '', capture = nil },
    { pattern = 'Traceback', hl = 'DiagnosticError', icon = '󰅚', priority = 1, flags = '', capture = nil },
    { pattern = '\\b(ERROR|Error)\\b', hl = 'DiagnosticError', icon = '󰅚', priority = 2, flags = '', capture = nil },
    { pattern = '\\b(WARN|WARNING|Warn|Warning)\\b', hl = 'DiagnosticWarn', icon = '󰀪', priority = 3, flags = '', capture = nil },
    { pattern = '\\b(INFO|Info)\\b', hl = 'DiagnosticInfo', icon = '󰋽', priority = 4, flags = '', capture = nil },
    { pattern = '\\b(DEBUG|Debug)\\b', hl = 'DiagnosticHint', icon = '󰌶', priority = 5, flags = '', capture = nil },
    { pattern = '\\bpanic\\b', hl = 'DiagnosticError', icon = '󰅚', priority = 1, flags = '', capture = nil },
    { pattern = '\\bfailed\\b', hl = 'DiagnosticWarn', icon = '󰀪', priority = 3, flags = 'i', capture = nil },
    { pattern = '\\bsuccess\\b', hl = 'DiagnosticOk', icon = '󰄴', priority = 6, flags = 'i', capture = nil },
    { pattern = '\\b(TODO|FIXME|HACK|XXX|NOTE)\\b', hl = 'DiagnosticWarn', icon = '󰞘', priority = 4, flags = '', capture = nil },
    -- Stack trace patterns with file:line capture
    { pattern = 'File "([^"]+)", line (\\d+)', hl = 'DiagnosticError', icon = '󰌶', priority = 1, flags = '', capture = 'file_line' },
    { pattern = '\\s+at ([^:]+):(\\d+):(\\d+)', hl = 'DiagnosticError', icon = '󰌶', priority = 1, flags = '', capture = 'file_line' },
    { pattern = '([\\w/.-]+):(\\d+):(\\d+):', hl = 'DiagnosticError', icon = '󰌶', priority = 2, flags = '', capture = 'file_line' },
  }

  local lang_specific = {
    python = {
      { pattern = '\\b(AssertionError|ValueError|TypeError|IndexError|KeyError|AttributeError|ImportError|FileNotFoundError)\\b', hl = 'DiagnosticError', icon = '󰅚', priority = 1, flags = '', capture = nil },
      { pattern = '\\bprint\\s*\\(', hl = 'DiagnosticHint', icon = '󰞘', priority = 5, flags = '', capture = nil },
      { pattern = '\\b(breakpoint|pdb\\.set_trace)\\s*\\(', hl = 'DiagnosticWarn', icon = '󰃤', priority = 2, flags = '', capture = nil },
      { pattern = '\\braise\\s+', hl = 'DiagnosticWarn', icon = '󰀪', priority = 3, flags = '', capture = nil },
      { pattern = '\\b(except|try)\\s*:', hl = 'DiagnosticInfo', icon = '󰋽', priority = 4, flags = '', capture = nil },
      { pattern = '\\blogging\\.(debug|info|warning|error|critical)\\s*\\(', hl = 'DiagnosticInfo', icon = '󰌶', priority = 4, flags = '', capture = nil },
    },
    javascript = {
      { pattern = '\\bconsole\\.(log|debug|info|warn|error|trace)\\s*\\(', hl = 'DiagnosticHint', icon = '󰞘', priority = 4, flags = '', capture = nil },
      { pattern = '\\bdebugger\\b', hl = 'DiagnosticWarn', icon = '󰃤', priority = 2, flags = '', capture = nil },
      { pattern = '\\b(try|catch|finally)\\s*[\\({]', hl = 'DiagnosticInfo', icon = '󰋽', priority = 4, flags = '', capture = nil },
      { pattern = '\\bthrow\\s+', hl = 'DiagnosticWarn', icon = '󰀪', priority = 3, flags = '', capture = nil },
    },
    typescript = {
      { pattern = '\\bconsole\\.(log|debug|info|warn|error|trace)\\s*\\(', hl = 'DiagnosticHint', icon = '󰞘', priority = 4, flags = '', capture = nil },
      { pattern = '\\bdebugger\\b', hl = 'DiagnosticWarn', icon = '󰃤', priority = 2, flags = '', capture = nil },
      { pattern = '\\b(try|catch|finally)\\s*[\\({]', hl = 'DiagnosticInfo', icon = '󰋽', priority = 4, flags = '', capture = nil },
    },
    lua = {
      { pattern = '\\bprint\\s*\\(', hl = 'DiagnosticHint', icon = '󰞘', priority = 5, flags = '', capture = nil },
      { pattern = '\\b(vim\\.inspect|vim\\.notify)\\s*\\(', hl = 'DiagnosticHint', icon = '󰞘', priority = 4, flags = '', capture = nil },
      { pattern = '\\brequire\\s*\\(\\s*["\']inspect["\']\\s*\\)', hl = 'DiagnosticInfo', icon = '󰌶', priority = 4, flags = '', capture = nil },
      { pattern = '\\b(error|assert)\\s*\\(', hl = 'DiagnosticWarn', icon = '󰀪', priority = 3, flags = '', capture = nil },
    },
    c = {
      { pattern = '\\b(printf|fprintf|puts)\\s*\\(', hl = 'DiagnosticHint', icon = '󰞘', priority = 5, flags = '', capture = nil },
      { pattern = '\\bmalloc\\s*\\(', hl = 'DiagnosticInfo', icon = '󰌶', priority = 4, flags = '', capture = nil },
      { pattern = '\\b(assert|abort)\\s*\\(', hl = 'DiagnosticWarn', icon = '󰀪', priority = 3, flags = '', capture = nil },
    },
    cpp = {
      { pattern = '\\b(std::cout|std::cerr|std::clog)\\s*<<', hl = 'DiagnosticHint', icon = '󰞘', priority = 5, flags = '', capture = nil },
      { pattern = '\\b(try|catch)\\s*[\\({]', hl = 'DiagnosticInfo', icon = '󰋽', priority = 4, flags = '', capture = nil },
      { pattern = '\\bthrow\\s+', hl = 'DiagnosticWarn', icon = '󰀪', priority = 3, flags = '', capture = nil },
    },
    go = {
      { pattern = '\\bfmt\\.(Print|Printf|Println)\\s*\\(', hl = 'DiagnosticHint', icon = '󰞘', priority = 5, flags = '', capture = nil },
      { pattern = '\\blog\\.(Print|Printf|Println|Fatal|Panic)\\s*\\(', hl = 'DiagnosticInfo', icon = '󰌶', priority = 4, flags = '', capture = nil },
      { pattern = '\\bdefer\\s+', hl = 'DiagnosticInfo', icon = '󰋽', priority = 4, flags = '', capture = nil },
      { pattern = '\\bpanic\\s*\\(', hl = 'DiagnosticError', icon = '󰅚', priority = 1, flags = '', capture = nil },
      { pattern = '\\bexec\\.Command\\s*\\(', hl = 'DiagnosticWarn', icon = '󰀪', priority = 2, flags = '', capture = nil },
      { pattern = '\\b(if|for|switch)\\s+', hl = 'DiagnosticHint', icon = '󰘦', priority = 6, flags = '', capture = nil },
      { pattern = '\\b(err\\s*!=\\s*nil)', hl = 'DiagnosticInfo', icon = '󰋽', priority = 3, flags = '', capture = nil },
      { pattern = '\\b(return\\s+[^,]*err)', hl = 'DiagnosticInfo', icon = '󰋽', priority = 3, flags = '', capture = nil },
    },
  }

  local patterns = vim.deepcopy(base_patterns)
  if lang_specific[ft] then
    vim.list_extend(patterns, lang_specific[ft])
  end
  
  return patterns
end

local function compile_patterns_for(ft)
  if compiled_cache[ft] then return compiled_cache[ft] end

  local raw = get_debug_patterns(ft)
  local compiled = {}
  for _, p in ipairs(raw) do
    local pattern, hl, icon = p.pattern, p.hl, p.icon or ''
    local priority = p.priority or 10
    local flags = p.flags or ''
    local capture = p.capture

    -- Build regex with flags
    local regex_src = pattern
    if flags:find('i') then regex_src = '(?i)' .. regex_src end

    local ok, rx = pcall(vim.regex, regex_src)
    if ok then
      table.insert(compiled, { rx = rx, hl = hl, icon = icon, priority = priority, capture = capture })
    else
      -- Fallback to plain lua pattern search (converted from regex)
      local lua_pattern = pattern:gsub('\\\\b', '%%f[%%w]'):gsub('\\\\B', ''):gsub('\\\\d', '%%d'):gsub('\\\\s', '%%s')
      table.insert(compiled, { raw = lua_pattern, hl = hl, icon = icon, priority = priority, capture = capture })
    end
  end

  compiled_cache[ft] = compiled
  return compiled
end

-- Helper: try to extract file and line from a capture group string
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

function M.render(bufnr, ns, cfg, from, to)
  local max_anno = cfg.max_annotations or 200
  local lines = vim.api.nvim_buf_get_lines(bufnr, from-1, to, false)
  local ft = vim.bo[bufnr].filetype
  local sc_ranges = (cfg.treesitter and U.ts_available(bufnr, cfg)) and U.ts_sc_ranges(bufnr, ft, from, to) or {}
  local patterns = compile_patterns_for(ft)
  local anno = 0

  for i, line in ipairs(lines) do
    local matches = {}
    for _, pat in ipairs(patterns) do
      local s, e, cap_text
      if pat.rx then
        local ok, start_byte, end_byte = pcall(function() return pat.rx:match_str(line) end)
        if ok and start_byte then
          s, e = start_byte + 1, end_byte
          cap_text = line:sub(s, e)
        end
      else
        local ss, ee = line:find(pat.raw)
        if ss then s, e = ss, ee; cap_text = line:sub(s, e) end
      end

      if s and not U.col_in_ranges((from+i-2), s-1, sc_ranges) then
        local score = pat.priority or 10
        -- Increase score if near a real diagnostic on this line
        local diags_on_line = vim.tbl_filter(function(d) return d.lnum == (from+i-2) end, vim.diagnostic.get(bufnr))
        if #diags_on_line > 0 then score = score + 5 end
        table.insert(matches, { 
          s = s-1, e = (e or s)-1, hl = pat.hl, icon = pat.icon, score = score, 
          capture = cap_text, capture_type = pat.capture 
        })
      end
    end

    -- Pick top match(es) by score, limit per line to 2
    table.sort(matches, function(a,b) return a.score > b.score end)
    for mi = 1, math.min(#matches, 2) do
      local m = matches[mi]
      local extmark_opts = {
        end_col = m.e,
        hl_group = m.hl,
        virt_text = {{m.icon, m.hl}},
        virt_text_pos = 'inline',
      }
      
      -- If this is a file:line capture, add metadata for quickfix
      if m.capture_type == 'file_line' then
        local file, line_nr = parse_file_line(m.capture)
        if file and line_nr then
          extmark_opts.id = 1000 + anno -- Stable ID for retrieval
          -- Store metadata in a global table for quickfix integration
          vim.g.traceback_file_line_captures = vim.g.traceback_file_line_captures or {}
          vim.g.traceback_file_line_captures[extmark_opts.id] = {
            file = file,
            line = line_nr,
            text = m.capture,
            bufnr = bufnr,
            lnum = from + i - 2
          }
        end
      end
      
      vim.api.nvim_buf_set_extmark(bufnr, ns, (from+i-2), m.s, extmark_opts)
      anno = anno + 1
      if anno >= max_anno then break end
    end
    if anno >= max_anno then break end
  end

  -- Add diagnostic summary (keep existing logic but improve formatting)
  local topline = from
  local diags = vim.diagnostic.get(bufnr)
  if #diags > 0 then
    local counts = { 
      [vim.diagnostic.severity.ERROR] = 0, 
      [vim.diagnostic.severity.WARN] = 0,
      [vim.diagnostic.severity.INFO] = 0,
      [vim.diagnostic.severity.HINT] = 0
    }
    for _, d in ipairs(diags) do 
      counts[d.severity] = (counts[d.severity] or 0) + 1 
    end
    
    -- Only show summary if there are actual diagnostics
    local total_diags = counts[vim.diagnostic.severity.ERROR] + counts[vim.diagnostic.severity.WARN] + 
                       counts[vim.diagnostic.severity.INFO] + counts[vim.diagnostic.severity.HINT]
    if total_diags > 0 then
      vim.api.nvim_buf_set_extmark(bufnr, ns, math.max(0, topline-1), 0, {
        virt_text = {{string.format(' 󰃤 E:%d W:%d I:%d H:%d', 
          counts[vim.diagnostic.severity.ERROR] or 0, 
          counts[vim.diagnostic.severity.WARN] or 0,
          counts[vim.diagnostic.severity.INFO] or 0,
          counts[vim.diagnostic.severity.HINT] or 0), 'DiagnosticInfo'}},
        virt_text_pos = 'right_align',
      })
    end
  end

  return anno
end

-- Helper function to populate quickfix with file:line captures
function M.populate_quickfix_with_captures(bufnr)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  local captures = vim.g.traceback_file_line_captures or {}
  local qf_items = {}
  
  for id, capture in pairs(captures) do
    if capture.bufnr == bufnr then
      table.insert(qf_items, {
        filename = capture.file,
        lnum = capture.line,
        text = capture.text,
        type = 'E'
      })
    end
  end
  
  if #qf_items > 0 then
    vim.fn.setqflist(qf_items, 'r')
    vim.cmd('copen')
    vim.notify(string.format('󰌶 Added %d stack trace entries to quickfix', #qf_items), vim.log.levels.INFO)
  else
    vim.notify('󰌶 No stack trace entries found in current buffer', vim.log.levels.INFO)
  end
end

return M
