local M = {}

-- Render LSP diagnostics as a lens: per-line messages and a header summary
-- Contract:
--   render(bufnr, ns, cfg, from, to) -> number of annotations rendered

local severity_map = {
  [vim.diagnostic.severity.ERROR] = { hl = 'DiagnosticError', icon = '󰅚' },
  [vim.diagnostic.severity.WARN]  = { hl = 'DiagnosticWarn',  icon = '󰀪' },
  [vim.diagnostic.severity.INFO]  = { hl = 'DiagnosticInfo',  icon = '󰋽' },
  [vim.diagnostic.severity.HINT]  = { hl = 'DiagnosticHint',  icon = '󰌶' },
}

local function truncate(str, max)
  if not str then return '' end
  if #str <= max then return str end
  return str:sub(1, math.max(0, max - 1)) .. '…'
end

function M.render(bufnr, ns, cfg, from, to)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  local diags = vim.diagnostic.get(bufnr)
  if not diags or #diags == 0 then return 0 end

  -- Group diagnostics by starting line (1-based for convenience)
  local per_line = {}
  local counts = {
    [vim.diagnostic.severity.ERROR] = 0,
    [vim.diagnostic.severity.WARN] = 0,
    [vim.diagnostic.severity.INFO] = 0,
    [vim.diagnostic.severity.HINT] = 0,
  }

  for _, d in ipairs(diags) do
    counts[d.severity] = (counts[d.severity] or 0) + 1
    local lnum = (d.lnum or 0) + 1
    if lnum >= from and lnum <= to then
      per_line[lnum] = per_line[lnum] or {}
      table.insert(per_line[lnum], d)
    end
  end

  local anno = 0
  -- Render summary at the top line of the scan window (right aligned)
  local total = (counts[vim.diagnostic.severity.ERROR] or 0)
              + (counts[vim.diagnostic.severity.WARN] or 0)
              + (counts[vim.diagnostic.severity.INFO] or 0)
              + (counts[vim.diagnostic.severity.HINT] or 0)
  if total > 0 then
    vim.api.nvim_buf_set_extmark(bufnr, ns, math.max(0, from - 1), 0, {
      virt_text = {{
        string.format(' 󰃤 E:%d W:%d I:%d H:%d',
          counts[vim.diagnostic.severity.ERROR] or 0,
          counts[vim.diagnostic.severity.WARN] or 0,
          counts[vim.diagnostic.severity.INFO] or 0,
          counts[vim.diagnostic.severity.HINT] or 0
        ), 'DiagnosticInfo'}
      },
      virt_text_pos = 'right_align',
    })
    anno = anno + 1
  end

  -- Render per-line messages at end-of-line
  local max_per_line = (cfg and cfg.lsp_max_per_line) or 1  -- show the top N severity messages per line
  for lnum, list in pairs(per_line) do
    if anno >= (cfg and cfg.max_annotations or math.huge) then break end
    table.sort(list, function(a, b)
      return (a.severity or vim.diagnostic.severity.HINT) < (b.severity or vim.diagnostic.severity.HINT)
    end)
    local shown = 0
    for _, d in ipairs(list) do
      if anno >= (cfg and cfg.max_annotations or math.huge) then break end
      if shown >= max_per_line then break end
      local sev = severity_map[d.severity] or severity_map[vim.diagnostic.severity.HINT]
      local msg = (d.message or '')
      local code = (type(d.code) == 'string' and d.code)
                  or (type(d.user_data) == 'table' and d.user_data.lsp and d.user_data.lsp.code)
                  or nil
      local src = d.source or (d.user_data and d.user_data.lsp and d.user_data.lsp.source) or nil
      local parts = { msg }
      if (cfg and cfg.lsp_show_codes) and code and code ~= '' then table.insert(parts, string.format('[%s]', code)) end
      if (cfg and cfg.lsp_show_source) and src and src ~= '' then table.insert(parts, string.format('(%s)', src)) end
      local text = table.concat(parts, ' ')
      text = truncate(text:gsub('%s+', ' '), (cfg and cfg.lsp_truncate) or 120)
      vim.api.nvim_buf_set_extmark(bufnr, ns, lnum - 1, 0, {
        virt_text = {{' ' .. sev.icon .. ' ' .. text, sev.hl}},
        virt_text_pos = 'eol',
        hl_mode = 'combine',
      })
      anno = anno + 1
      shown = shown + 1
    end
    -- Indicate there are more diagnostics on this line
    local extra = #list - shown
    if extra > 0 then
      local sev = severity_map[list[shown+1].severity] or severity_map[vim.diagnostic.severity.HINT]
      vim.api.nvim_buf_set_extmark(bufnr, ns, lnum - 1, 0, {
        virt_text = {{string.format(' +%d', extra), sev.hl}},
        virt_text_pos = 'eol',
      })
      anno = anno + 1
    end
  end

  return anno
end

return M
