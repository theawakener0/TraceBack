local M = {}

-- Enhanced LSP diagnostics lens with improved rendering and grouping
-- Contract:
--   render(bufnr, ns, cfg, from, to) -> number of annotations rendered

local severity_map = {
  [vim.diagnostic.severity.ERROR] = { hl = 'DiagnosticError', icon = '󰅚', priority = 1 },
  [vim.diagnostic.severity.WARN]  = { hl = 'DiagnosticWarn',  icon = '󰀪', priority = 2 },
  [vim.diagnostic.severity.INFO]  = { hl = 'DiagnosticInfo',  icon = '󰋽', priority = 3 },
  [vim.diagnostic.severity.HINT]  = { hl = 'DiagnosticHint',  icon = '󰌶', priority = 4 },
}

local function truncate(str, max)
  if not str then return '' end
  if #str <= max then return str end
  return str:sub(1, math.max(0, max - 1)) .. '…'
end

local function group_by_source(diagnostics)
  local by_source = {}
  for _, d in ipairs(diagnostics) do
    local source = d.source or (d.user_data and d.user_data.lsp and d.user_data.lsp.source) or 'unknown'
    by_source[source] = by_source[source] or {}
    table.insert(by_source[source], d)
  end
  return by_source
end

local function get_severity_color(severity, is_summary)
  local base = severity_map[severity] or severity_map[vim.diagnostic.severity.HINT]
  if is_summary then
    return base.hl .. 'Summary'  -- Allow for custom summary highlights
  end
  return base.hl
end

local function format_diagnostic_message(d, cfg)
  local msg = (d.message or ''):gsub('%s+', ' '):gsub('^%s+', ''):gsub('%s+$', '')
  local code = (type(d.code) == 'string' and d.code)
              or (type(d.user_data) == 'table' and d.user_data.lsp and d.user_data.lsp.code)
              or nil
  local src = d.source or (d.user_data and d.user_data.lsp and d.user_data.lsp.source) or nil
  
  local parts = { msg }
  if (cfg and cfg.lsp_show_codes) and code and code ~= '' then 
    table.insert(parts, string.format('󰌗 %s', code)) 
  end
  if (cfg and cfg.lsp_show_source) and src and src ~= '' then 
    table.insert(parts, string.format('󰒢 %s', src)) 
  end
  
  local text = table.concat(parts, ' ')
  return truncate(text, (cfg and cfg.lsp_truncate) or 120)
end

function M.render(bufnr, ns, cfg, from, to)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  local diags = vim.diagnostic.get(bufnr)
  if not diags or #diags == 0 then return 0 end

  -- Enhanced grouping: by line and by source
  local per_line = {}
  local counts = {
    [vim.diagnostic.severity.ERROR] = 0,
    [vim.diagnostic.severity.WARN] = 0,
    [vim.diagnostic.severity.INFO] = 0,
    [vim.diagnostic.severity.HINT] = 0,
  }
  local by_source = group_by_source(diags)

  for _, d in ipairs(diags) do
    counts[d.severity] = (counts[d.severity] or 0) + 1
    local lnum = (d.lnum or 0) + 1
    if lnum >= from and lnum <= to then
      per_line[lnum] = per_line[lnum] or {}
      table.insert(per_line[lnum], d)
    end
  end

  local anno = 0
  local total = (counts[vim.diagnostic.severity.ERROR] or 0)
              + (counts[vim.diagnostic.severity.WARN] or 0)
              + (counts[vim.diagnostic.severity.INFO] or 0)
              + (counts[vim.diagnostic.severity.HINT] or 0)

  -- Enhanced summary with source breakdown if enabled
  if total > 0 then
    local summary_text = string.format('󰃤 E:%d W:%d I:%d H:%d',
      counts[vim.diagnostic.severity.ERROR] or 0,
      counts[vim.diagnostic.severity.WARN] or 0,
      counts[vim.diagnostic.severity.INFO] or 0,
      counts[vim.diagnostic.severity.HINT] or 0
    )
    
    -- Add source count if multiple sources and feature enabled
    if (cfg and cfg.lsp_show_source_summary) and vim.tbl_count(by_source) > 1 then
      summary_text = summary_text .. string.format(' 󰒢 %d sources', vim.tbl_count(by_source))
    end
    
    vim.api.nvim_buf_set_extmark(bufnr, ns, math.max(0, from - 1), 0, {
      virt_text = {{' ' .. summary_text, get_severity_color(vim.diagnostic.severity.INFO, true)}},
      virt_text_pos = 'right_align',
    })
    anno = anno + 1
  end

  -- Enhanced per-line rendering with better grouping and overflow handling
  local max_per_line = (cfg and cfg.lsp_max_per_line) or 2
  local show_overflow = (cfg and cfg.lsp_show_overflow) ~= false
  
  for lnum, list in pairs(per_line) do
    if anno >= (cfg and cfg.max_annotations or math.huge) then break end
    
    -- Sort by severity priority, then by message length (shorter first for readability)
    table.sort(list, function(a, b)
      local a_sev = severity_map[a.severity] or severity_map[vim.diagnostic.severity.HINT]
      local b_sev = severity_map[b.severity] or severity_map[vim.diagnostic.severity.HINT]
      if a_sev.priority ~= b_sev.priority then
        return a_sev.priority < b_sev.priority
      end
      return #(a.message or '') < #(b.message or '')
    end)
    
    local shown = 0
    local virt_text_chunks = {}
    
    -- Render top diagnostics
    for _, d in ipairs(list) do
      if anno >= (cfg and cfg.max_annotations or math.huge) then break end
      if shown >= max_per_line then break end
      
      local sev = severity_map[d.severity] or severity_map[vim.diagnostic.severity.HINT]
      local text = format_diagnostic_message(d, cfg)
      
      if shown == 0 then
        table.insert(virt_text_chunks, {' ' .. sev.icon .. ' ' .. text, sev.hl})
      else
        table.insert(virt_text_chunks, {' │ ' .. sev.icon .. ' ' .. text, sev.hl})
      end
      
      shown = shown + 1
    end
    
    -- Show overflow indicator with appropriate styling
    local extra = #list - shown
    if show_overflow and extra > 0 then
      local next_sev = severity_map[list[shown+1].severity] or severity_map[vim.diagnostic.severity.HINT]
      table.insert(virt_text_chunks, {string.format(' │ 󰇘 +%d more', extra), next_sev.hl})
    end
    
    if #virt_text_chunks > 0 then
      vim.api.nvim_buf_set_extmark(bufnr, ns, lnum - 1, 0, {
        virt_text = virt_text_chunks,
        virt_text_pos = 'eol',
        hl_mode = 'combine',
      })
      anno = anno + 1
    end
  end

  return anno
end

return M
