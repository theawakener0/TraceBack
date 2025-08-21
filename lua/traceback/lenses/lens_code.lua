local U = require('traceback.lenses.utils')

local M = {}

local function ts_render(bufnr, ns, cfg, from, to)
  if not U.ts_available(bufnr, cfg) then return 0 end
  local ft = vim.bo[bufnr].filetype
  local ok, parser = pcall(vim.treesitter.get_parser, bufnr, ft)
  if not ok then return 0 end
  local q = U.get_ts_query(ft, 'functions')
  if not q then return 0 end
  local tree = parser:parse()[1]
  if not tree then return 0 end
  local root = tree:root()
  local anno = 0
  for match in q:iter_matches(root, bufnr, from-1, to) do
    local fn_node, name_node
    for id, node in pairs(match) do
      local cap = q.captures[id]
      if cap == 'fn' then fn_node = node end
      if cap == 'name' then name_node = node end
    end
    local name = name_node and U.get_node_text(name_node, bufnr) or 'function'
    local sr = fn_node and select(1, fn_node:range()) or (name_node and select(1, name_node:range()) or (from-1))
    local function count_complexity(n, depth)
      if not n or depth > 1000 then return 0 end
      local t = n:type()
      local incr = 0
      if t:find('if') or t:find('while') or t:find('for') or t:find('case') or t:find('switch') or t:find('elsif') then incr = 1 end
      local total = incr
      for child in n:iter_children() do total = total + count_complexity(child, depth+1) end
      return total
    end
    local complexity = 1 + (fn_node and count_complexity(fn_node, 0) or 0)
    vim.api.nvim_buf_set_extmark(bufnr, ns, sr, 0, {
      virt_text = {{string.format('󰘧 %s (C%02d)', name, complexity), 'Comment'}},
      virt_text_pos = 'eol',
    })
    anno = anno + 1
    if anno >= cfg.max_annotations then break end
  end
  return anno
end

local function regex_render(bufnr, ns, cfg, from, to)
  local ft = vim.bo[bufnr].filetype
  local lines = vim.api.nvim_buf_get_lines(bufnr, from-1, to, false)
  local func_patterns = {
    c = {'^%s*%w+%s+([%w%.%:_]+)%s*%(', '^%s*([%w%.%:_]+)%s*%('},
    cpp = {'^%s*%w+%s+([%w%.%:_]+)%s*%(', '^%s*([%w%.%:_]+)%s*%('},
    lua = {'^%s*local%s+function%s+([%w%.%:_]+)%s*%(', '^%s*function%s+([%w%.%:_]+)%s*%('},
    python = {'^%s*def%s+([%w_]+)%s*%('},
    javascript = {'^%s*function%s+([%w_]+)%s*%(', '^%s*const%s+([%w_]+)%s*=%s*%([^)]*%)%s*=>'},
    typescript = {'^%s*function%s+([%w_]+)%s*%('},
    go = {'^%s*func%s+([%w%.%:_]+)%s*%('},
    default = {'^%s*function%s+([%w_]+)%s*%('},
  }
  local pats = func_patterns[ft] or func_patterns.default
  local anno = 0
  for i, line in ipairs(lines) do
    for _, pat in ipairs(pats) do
      local name = line:match(pat)
      if name then
        local lookahead_end = math.min(#lines, i+30)
        local window = table.concat({unpack(lines, i, lookahead_end)}, '\n')
        local complexity = 1
        for _ in window:gmatch('%f[%w]if%f[^%w]') do complexity = complexity + 1 end
        for _ in window:gmatch('%f[%w]for%f[^%w]') do complexity = complexity + 1 end
        for _ in window:gmatch('%f[%w]while%f[^%w]') do complexity = complexity + 1 end
        for _ in window:gmatch('%f[%w]case%f[^%w]') do complexity = complexity + 1 end
        vim.api.nvim_buf_set_extmark(bufnr, ns, (from+i-2), 0, {
          virt_text = {{string.format('󰘧 %s (C%02d)', name, complexity), 'Comment'}},
          virt_text_pos = 'eol',
        })
        anno = anno + 1
        if anno >= cfg.max_annotations then return anno end
        break
      end
    end
  end
  return anno
end

function M.render(bufnr, ns, cfg, from, to)
  local n = 0
  if cfg.treesitter and U.ts_available(bufnr, cfg) then
    n = ts_render(bufnr, ns, cfg, from, to)
    if n >= cfg.max_annotations then return n end
  end
  n = n + regex_render(bufnr, ns, cfg, from, to)
  return n
end

return M
