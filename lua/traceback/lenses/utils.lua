local U = {}

function U.get_viewport()
  local w = vim.api.nvim_get_current_win()
  local info = vim.fn.getwininfo(w)[1]
  return info.topline, info.botline
end

function U.ts_available(bufnr, cfg)
  if not (cfg.treesitter == nil or cfg.treesitter) then return false end
  return pcall(vim.treesitter.get_parser, bufnr)
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
      ]],
      python = [[ (function_definition name: (identifier) @name) @fn ]],
      javascript = [[
        (function_declaration name: (identifier) @name) @fn
        (method_definition name: (property_identifier) @name) @fn
      ]],
      typescript = [[
        (function_declaration name: (identifier) @name) @fn
        (method_definition name: (property_identifier) @name) @fn
      ]],
      go = [[
        (function_declaration name: (identifier) @name) @fn
        (method_declaration name: (field_identifier) @name) @fn
      ]],
    },
    sc = {
      lua = [[ (comment) @c (string) @s ]],
      python = [[ (comment) @c (string) @s ]],
      javascript = [[ (comment) @c (string) @s ]],
      typescript = [[ (comment) @c (string) @s ]],
      go = [[ (comment) @c (interpreted_string_literal) @s (raw_string_literal) @s ]],
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
