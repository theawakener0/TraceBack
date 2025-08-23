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
    local complexity_icon = complexity > 10 and '󰝣' or (complexity > 5 and '󰝤' or '󰝥')
    vim.api.nvim_buf_set_extmark(bufnr, ns, sr, 0, {
      virt_text = {{string.format('%s 󰌵 %s (C%02d)', complexity_icon, name, complexity), 'Comment'}},
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
    c = {
      '^%s*%w+%s+([%w%.%:_]+)%s*%(', -- type func_name(
      '^%s*([%w%.%:_]+)%s*%(', -- func_name(
      '^%s*static%s+%w+%s+([%w%.%:_]+)%s*%(', -- static type func_name(
      '^%s*inline%s+%w+%s+([%w%.%:_]+)%s*%(', -- inline type func_name(
    },
    cpp = {
      '^%s*%w+%s+([%w%.%:_]+)%s*%(', -- type func_name(
      '^%s*([%w%.%:_]+)%s*%(', -- func_name(
      '^%s*static%s+%w+%s+([%w%.%:_]+)%s*%(', -- static type func_name(
      '^%s*inline%s+%w+%s+([%w%.%:_]+)%s*%(', -- inline type func_name(
      '^%s*virtual%s+%w+%s+([%w%.%:_]+)%s*%(', -- virtual type func_name(
      '^%s*template%s*<.*>%s*%w+%s+([%w%.%:_]+)%s*%(', -- template functions
      '^%s*([%w_:]+)::[%w_]+%s*%(', -- Class::method(
    },
    lua = {
      '^%s*local%s+function%s+([%w%.%:_]+)%s*%(', -- local function name(
      '^%s*function%s+([%w%.%:_]+)%s*%(', -- function name(
      '^%s*([%w%.%:_]+)%s*=%s*function%s*%(', -- name = function(
      '^%s*local%s+([%w%.%:_]+)%s*=%s*function%s*%(', -- local name = function(
      '^%s*M%.([%w_]+)%s*=%s*function', -- M.func = function
    },
    python = {
      '^%s*def%s+([%w_]+)%s*%(', -- def func_name(
      '^%s*async%s+def%s+([%w_]+)%s*%(', -- async def func_name(
      '^%s*class%s+([%w_]+)%s*[%(:]', -- class ClassName
      '^%s*@[%w_.]+%s*$', -- decorators (will need special handling)
    },
    javascript = {
      '^%s*function%s+([%w_]+)%s*%(', -- function name(
      '^%s*const%s+([%w_]+)%s*=%s*%([^)]*%)%s*=>', -- const name = () =>
      '^%s*let%s+([%w_]+)%s*=%s*%([^)]*%)%s*=>', -- let name = () =>
      '^%s*var%s+([%w_]+)%s*=%s*%([^)]*%)%s*=>', -- var name = () =>
      '^%s*([%w_]+)%s*:%s*function%s*%(', -- name: function(
      '^%s*([%w_]+)%s*:%s*%([^)]*%)%s*=>', -- name: () =>
      '^%s*async%s+function%s+([%w_]+)%s*%(', -- async function name(
      '^%s*([%w_]+)%s*=%s*async%s*%([^)]*%)%s*=>', -- name = async () =>
    },
    typescript = {
      '^%s*function%s+([%w_]+)%s*%(', -- function name(
      '^%s*const%s+([%w_]+)%s*=%s*%([^)]*%)%s*=>', -- const name = () =>
      '^%s*let%s+([%w_]+)%s*=%s*%([^)]*%)%s*=>', -- let name = () =>
      '^%s*([%w_]+)%s*:%s*%([^)]*%)%s*=>', -- name: () =>
      '^%s*async%s+function%s+([%w_]+)%s*%(', -- async function name(
      '^%s*([%w_]+)%s*=%s*async%s*%([^)]*%)%s*=>', -- name = async () =>
      '^%s*export%s+function%s+([%w_]+)%s*%(', -- export function name(
      '^%s*class%s+([%w_]+)', -- class ClassName
      '^%s*interface%s+([%w_]+)', -- interface InterfaceName
    },
    go = {
      '^%s*func%s+([%w%.%:_]+)%s*%(', -- func name(
      '^%s*func%s*%([^)]*%)%s*([%w%.%:_]+)%s*%(', -- func (receiver) name(
      '^%s*type%s+([%w_]+)%s+struct', -- type Name struct
      '^%s*type%s+([%w_]+)%s+interface', -- type Name interface
    },
    default = {'^%s*function%s+([%w_]+)%s*%('},
  }
  
  local pats = func_patterns[ft] or func_patterns.default
  local anno = 0
  
  for i, line in ipairs(lines) do
    local name = nil
    for _, pat in ipairs(pats) do
      name = line:match(pat)
      if name then break end
    end
    
    if name then
      -- Calculate complexity
      local lookahead_end = math.min(#lines, i+50) -- Look ahead more lines
      local window = table.concat({unpack(lines, i, lookahead_end)}, '\n')
      local complexity = 1
      
      -- Language-specific complexity patterns
      local complexity_patterns = {
        c = {'%f[%w]if%f[^%w]', '%f[%w]for%f[^%w]', '%f[%w]while%f[^%w]', '%f[%w]switch%f[^%w]', '%f[%w]case%f[^%w]'},
        cpp = {'%f[%w]if%f[^%w]', '%f[%w]for%f[^%w]', '%f[%w]while%f[^%w]', '%f[%w]switch%f[^%w]', '%f[%w]case%f[^%w]', '%f[%w]try%f[^%w]', '%f[%w]catch%f[^%w]'},
        lua = {'%f[%w]if%f[^%w]', '%f[%w]for%f[^%w]', '%f[%w]while%f[^%w]', '%f[%w]repeat%f[^%w]', '%f[%w]elseif%f[^%w]'},
        python = {'%f[%w]if%f[^%w]', '%f[%w]for%f[^%w]', '%f[%w]while%f[^%w]', '%f[%w]elif%f[^%w]', '%f[%w]try%f[^%w]', '%f[%w]except%f[^%w]'},
        javascript = {'%f[%w]if%f[^%w]', '%f[%w]for%f[^%w]', '%f[%w]while%f[^%w]', '%f[%w]switch%f[^%w]', '%f[%w]case%f[^%w]', '%f[%w]try%f[^%w]', '%f[%w]catch%f[^%w]'},
        typescript = {'%f[%w]if%f[^%w]', '%f[%w]for%f[^%w]', '%f[%w]while%f[^%w]', '%f[%w]switch%f[^%w]', '%f[%w]case%f[^%w]', '%f[%w]try%f[^%w]', '%f[%w]catch%f[^%w]'},
        go = {'%f[%w]if%f[^%w]', '%f[%w]for%f[^%w]', '%f[%w]switch%f[^%w]', '%f[%w]case%f[^%w]', '%f[%w]select%f[^%w]'},
        default = {'%f[%w]if%f[^%w]', '%f[%w]for%f[^%w]', '%f[%w]while%f[^%w]', '%f[%w]case%f[^%w]'}
      }
      
      local patterns = complexity_patterns[ft] or complexity_patterns.default
      for _, pattern in ipairs(patterns) do
        for _ in window:gmatch(pattern) do 
          complexity = complexity + 1 
        end
      end
      
      -- Function type classification
      local func_type = '󰌵'
      if name:match('^test') or name:match('Test$') then
        func_type = ''
      elseif name:match('^get') or name:match('Get') then
        func_type = ''
      elseif name:match('^set') or name:match('Set') then
        func_type = ''
      elseif name:match('^init') or name:match('Init') or name:match('new') or name:match('New') then
        func_type = ''
      elseif name:match('^main$') then
        func_type = ''
      elseif name:match('^handle') or name:match('Handle') or name:match('Handler') then
        func_type = ''
      end
      
      local complexity_icon = complexity > 15 and '' or (complexity > 10 and '' or (complexity > 5 and '' or ''))
      
      vim.api.nvim_buf_set_extmark(bufnr, ns, (from+i-2), 0, {
        virt_text = {{string.format('%s %s %s (C%02d)', complexity_icon, func_type, name, complexity), 'Comment'}},
        virt_text_pos = 'eol',
      })
      anno = anno + 1
      if anno >= cfg.max_annotations then return anno end
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
