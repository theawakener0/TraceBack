local U = require('traceback.lenses.utils')

local M = {}

function M.render(bufnr, ns, cfg, from, to)
  local max_anno = cfg.max_annotations
  local lines = vim.api.nvim_buf_get_lines(bufnr, from-1, to, false)
  local ft = vim.bo[bufnr].filetype
  local sc_ranges = (cfg.treesitter and U.ts_available(bufnr, cfg)) and U.ts_sc_ranges(bufnr, ft, from, to) or {}
  local patterns = {
    { 'Exception', 'DiagnosticError' },
    { 'Traceback', 'DiagnosticError' },
    { '%f[%w]ERROR%f[^%w]', 'DiagnosticError' },
    { '%f[%w]WARN(?:ING)?%f[^%w]', 'DiagnosticWarn' },
    { 'panic', 'DiagnosticError' },
    { 'failed', 'DiagnosticWarn' },
  }
  local anno = 0
  for i, line in ipairs(lines) do
    for _, rule in ipairs(patterns) do
      local s, e = line:find(rule[1])
      if s and not U.col_in_ranges((from+i-2), s-1, sc_ranges) then
        vim.api.nvim_buf_set_extmark(bufnr, ns, (from+i-2), s-1, { end_col = e, hl_group = rule[2] })
        anno = anno + 1
        if anno >= max_anno then break end
      end
    end
    if anno >= max_anno then break end
  end
  local topline = from
  local diags = vim.diagnostic.get(bufnr)
  if #diags > 0 then
    local counts = { [vim.diagnostic.severity.ERROR]=0, [vim.diagnostic.severity.WARN]=0 }
    for _, d in ipairs(diags) do counts[d.severity] = (counts[d.severity] or 0) + 1 end
    vim.api.nvim_buf_set_extmark(bufnr, ns, math.max(0, topline-1), 0, {
      virt_text = {{string.format(' diag E:%d W:%d', counts[vim.diagnostic.severity.ERROR] or 0, counts[vim.diagnostic.severity.WARN] or 0), 'DiagnosticInfo'}},
      virt_text_pos = 'right_align',
    })
  end
  return anno
end

return M
