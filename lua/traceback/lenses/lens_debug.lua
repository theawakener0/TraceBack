local U = require('traceback.lenses.utils')

local M = {}

-- Language-specific debug patterns
local function get_debug_patterns(ft)
  local base_patterns = {
    -- Universal patterns
    { 'Exception', 'DiagnosticError', '❌' },
    { 'Traceback', 'DiagnosticError', '📍' },
    { '%f[%w]ERROR%f[^%w]', 'DiagnosticError', '🚨' },
    { '%f[%w]WARN(?:ING)?%f[^%w]', 'DiagnosticWarn', '⚠️' },
    { '%f[%w]INFO%f[^%w]', 'DiagnosticInfo', 'ℹ️' },
    { '%f[%w]DEBUG%f[^%w]', 'DiagnosticHint', '🐛' },
    { 'panic', 'DiagnosticError', '💥' },
    { 'failed', 'DiagnosticWarn', '❌' },
    { 'success', 'DiagnosticOk', '✅' },
    { '%f[%w]TODO%f[^%w]', 'DiagnosticWarn', '📝' },
    { '%f[%w]FIXME%f[^%w]', 'DiagnosticError', '🔧' },
    { '%f[%w]HACK%f[^%w]', 'DiagnosticWarn', '🎃' },
    { '%f[%w]XXX%f[^%w]', 'DiagnosticError', '❗' },
    { '%f[%w]NOTE%f[^%w]', 'DiagnosticInfo', '📌' },
  }

  local lang_specific = {
    python = {
      { 'AssertionError', 'DiagnosticError', '🔴' },
      { 'ValueError', 'DiagnosticError', '💢' },
      { 'TypeError', 'DiagnosticError', '🎭' },
      { 'IndexError', 'DiagnosticError', '📍' },
      { 'KeyError', 'DiagnosticError', '🔑' },
      { 'AttributeError', 'DiagnosticError', '🏷️' },
      { 'ImportError', 'DiagnosticError', '📦' },
      { 'FileNotFoundError', 'DiagnosticError', '📁' },
      { 'print%(', 'DiagnosticHint', '🖨️' },
      { 'breakpoint%(', 'DiagnosticWarn', '🛑' },
      { 'pdb%.set_trace', 'DiagnosticWarn', '🔍' },
      { 'raise ', 'DiagnosticWarn', '💥' },
      { 'except ', 'DiagnosticInfo', '🛡️' },
      { 'try:', 'DiagnosticInfo', '🎯' },
    },
    javascript = {
      { 'console%.log', 'DiagnosticHint', '📝' },
      { 'console%.error', 'DiagnosticError', '🔴' },
      { 'console%.warn', 'DiagnosticWarn', '⚠️' },
      { 'console%.debug', 'DiagnosticHint', '🐛' },
      { 'console%.info', 'DiagnosticInfo', 'ℹ️' },
      { 'debugger', 'DiagnosticWarn', '🛑' },
      { 'TypeError', 'DiagnosticError', '🎭' },
      { 'ReferenceError', 'DiagnosticError', '🔗' },
      { 'SyntaxError', 'DiagnosticError', '📝' },
      { 'RangeError', 'DiagnosticError', '📏' },
      { 'throw new', 'DiagnosticWarn', '💥' },
      { 'try {', 'DiagnosticInfo', '🎯' },
      { 'catch', 'DiagnosticInfo', '🛡️' },
    },
    typescript = {
      { 'console%.log', 'DiagnosticHint', '📝' },
      { 'console%.error', 'DiagnosticError', '🔴' },
      { 'console%.warn', 'DiagnosticWarn', '⚠️' },
      { 'console%.debug', 'DiagnosticHint', '🐛' },
      { 'console%.info', 'DiagnosticInfo', 'ℹ️' },
      { 'debugger', 'DiagnosticWarn', '🛑' },
      { 'TypeError', 'DiagnosticError', '🎭' },
      { 'ReferenceError', 'DiagnosticError', '🔗' },
      { 'throw new', 'DiagnosticWarn', '💥' },
      { 'try {', 'DiagnosticInfo', '🎯' },
      { 'catch', 'DiagnosticInfo', '🛡️' },
    },
    lua = {
      { 'error%(', 'DiagnosticError', '🔴' },
      { 'assert%(', 'DiagnosticWarn', '🔍' },
      { 'print%(', 'DiagnosticHint', '🖨️' },
      { 'vim%.notify', 'DiagnosticInfo', '📢' },
      { 'vim%.print', 'DiagnosticHint', '🖨️' },
      { 'pcall', 'DiagnosticInfo', '🛡️' },
      { 'xpcall', 'DiagnosticInfo', '🛡️' },
      { 'require', 'DiagnosticInfo', '📦' },
    },
    c = {
      { 'printf%(', 'DiagnosticHint', '🖨️' },
      { 'fprintf%(', 'DiagnosticHint', '📝' },
      { 'sprintf%(', 'DiagnosticHint', '📝' },
      { 'assert%(', 'DiagnosticWarn', '🔍' },
      { 'abort%(', 'DiagnosticError', '💥' },
      { 'exit%(', 'DiagnosticWarn', '🚪' },
      { 'segmentation fault', 'DiagnosticError', '💀' },
      { 'memory leak', 'DiagnosticWarn', '🕳️' },
      { 'NULL', 'DiagnosticWarn', '⚫' },
      { 'malloc%(', 'DiagnosticInfo', '🧠' },
      { 'free%(', 'DiagnosticInfo', '🗑️' },
      { 'calloc%(', 'DiagnosticInfo', '🧠' },
      { 'realloc%(', 'DiagnosticInfo', '🧠' },
    },
    cpp = {
      { 'std::cout', 'DiagnosticHint', '🖨️' },
      { 'std::cerr', 'DiagnosticError', '🔴' },
      { 'std::clog', 'DiagnosticInfo', '📝' },
      { 'assert%(', 'DiagnosticWarn', '🔍' },
      { 'abort%(', 'DiagnosticError', '💥' },
      { 'exit%(', 'DiagnosticWarn', '🚪' },
      { 'throw', 'DiagnosticWarn', '💥' },
      { 'exception', 'DiagnosticError', '❌' },
      { 'nullptr', 'DiagnosticWarn', '⚫' },
      { 'segmentation fault', 'DiagnosticError', '💀' },
      { 'new ', 'DiagnosticInfo', '🆕' },
      { 'delete ', 'DiagnosticInfo', '🗑️' },
      { 'try {', 'DiagnosticInfo', '🎯' },
      { 'catch', 'DiagnosticInfo', '🛡️' },
    },
    go = {
      { 'fmt%.Print', 'DiagnosticHint', '🖨️' },
      { 'fmt%.Printf', 'DiagnosticHint', '🖨️' },
      { 'fmt%.Println', 'DiagnosticHint', '🖨️' },
      { 'log%.Print', 'DiagnosticInfo', '📝' },
      { 'log%.Printf', 'DiagnosticInfo', '📝' },
      { 'log%.Println', 'DiagnosticInfo', '📝' },
      { 'log%.Fatal', 'DiagnosticError', '💀' },
      { 'log%.Panic', 'DiagnosticError', '💥' },
      { 'panic%(', 'DiagnosticError', '💥' },
      { 'recover%(', 'DiagnosticWarn', '🛡️' },
      { 'if err != nil', 'DiagnosticWarn', '❗' },
      { 'errors%.New', 'DiagnosticError', '🆕' },
      { 'make%(', 'DiagnosticInfo', '🏗️' },
      { 'defer ', 'DiagnosticInfo', '⏰' },
    },
  }

  local patterns = vim.tbl_deep_extend('force', {}, base_patterns)
  if lang_specific[ft] then
    vim.list_extend(patterns, lang_specific[ft])
  end
  
  return patterns
end

function M.render(bufnr, ns, cfg, from, to)
  local max_anno = cfg.max_annotations
  local lines = vim.api.nvim_buf_get_lines(bufnr, from-1, to, false)
  local ft = vim.bo[bufnr].filetype
  local sc_ranges = (cfg.treesitter and U.ts_available(bufnr, cfg)) and U.ts_sc_ranges(bufnr, ft, from, to) or {}
  local patterns = get_debug_patterns(ft)
  local anno = 0
  
  for i, line in ipairs(lines) do
    for _, rule in ipairs(patterns) do
      local s, e = line:find(rule[1])
      if s and not U.col_in_ranges((from+i-2), s-1, sc_ranges) then
        local icon = rule[3] or '🐛'
        vim.api.nvim_buf_set_extmark(bufnr, ns, (from+i-2), s-1, { 
          end_col = e, 
          hl_group = rule[2],
          virt_text = {{icon, rule[2]}},
          virt_text_pos = 'inline',
        })
        anno = anno + 1
        if anno >= max_anno then break end
      end
    end
    if anno >= max_anno then break end
  end
  
  -- Add diagnostic summary
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
    vim.api.nvim_buf_set_extmark(bufnr, ns, math.max(0, topline-1), 0, {
      virt_text = {{string.format('🩺 E:%d W:%d I:%d H:%d', 
        counts[vim.diagnostic.severity.ERROR] or 0, 
        counts[vim.diagnostic.severity.WARN] or 0,
        counts[vim.diagnostic.severity.INFO] or 0,
        counts[vim.diagnostic.severity.HINT] or 0), 'DiagnosticInfo'}},
      virt_text_pos = 'right_align',
    })
  end
  
  return anno
end

return M
