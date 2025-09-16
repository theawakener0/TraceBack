local M = {}
local U = require('traceback.utils')

-- This module exposes a picker; we also register a proper telescope extension if loaded elsewhere.

local function format_item(idx, s)
  local time = os.date('%H:%M:%S', math.floor((s.ts or 0)/1000))
  local file = s.file ~= '' and vim.fn.fnamemodify(s.file, ':t') or '[No Name]'
  local first = (s.lines[1] or ''):gsub('%s+', ' ')
  -- Truncate first line preview if too long
  if #first > 50 then
    first = first:sub(1, 47) .. '...'
  end
  local icon = idx == 1 and '󰐃' or '󰥔'  -- Latest snapshot gets pin icon, others get clock
  local line_count = (s.lines and #s.lines) or 0
  return string.format('%s #%03d %s %s · %dL — %s', icon, idx, time, file, line_count, first)
end

function M.timeline_items(bufnr)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  local tl = require('traceback.core').timeline(bufnr)
  local items = {}
  -- Reverse the order so newest snapshots (highest numbers) appear first
  for i = #tl.snapshots, 1, -1 do
    local s = tl.snapshots[i]
    local display_idx = i -- Keep original index for restore
    table.insert(items, { display = format_item(display_idx, s), ordinal = display_idx, idx = display_idx, snapshot = s })
  end
  return items
end

function M.timeline_picker()
  local ok, pickers = pcall(require, 'telescope.pickers')
  if not ok then
    -- telescope not available; silently return to avoid noisy notifications
    return
  end
  local finders = require('telescope.finders')
  local conf = require('telescope.config').values
  local actions = require('telescope.actions')
  local action_state = require('telescope.actions.state')
  local previewers = require('telescope.previewers')

  local cur_buf = vim.api.nvim_get_current_buf()
  local items = M.timeline_items(cur_buf)
  if #items == 0 then
    -- no snapshots; keep quiet per notification policy
    return
  end
  
  -- picker configuration can be customized via require('traceback').setup({ telescope = { theme = 'ivy', layout_config = {...} } })
  local cfg = {}
  pcall(function()
    local init = require('traceback.init')
    local c = init.get_config and init.get_config() or {}
    cfg = type(c.telescope) == 'table' and c.telescope or {}
  end)
  local themes = require('telescope.themes')

  -- Helper: choose the best buffer to restore into
  local function resolve_target_buf(snapshot)
    -- Prefer original buffer if still valid
    if snapshot and snapshot.bufnr and vim.api.nvim_buf_is_valid(snapshot.bufnr) then
      return snapshot.bufnr
    end
    -- Next, try to find a loaded buffer visiting the same file
    local file = snapshot and snapshot.file
    if file and file ~= '' then
      for _, b in ipairs(vim.api.nvim_list_bufs()) do
        if vim.api.nvim_buf_is_loaded(b) and vim.api.nvim_buf_get_name(b) == file then
          return b
        end
      end
    end
    -- Fallback: current buffer
    return cur_buf
  end

  local theme = (cfg.theme == 'dropdown') and themes.get_dropdown or themes.get_ivy
  local layout_config = cfg.layout_config or { height = 0.4, preview_width = 0.6 }
  pickers.new(theme({
    layout_config = layout_config,
  }), {
    prompt_title = '󰈙 TraceBack Timeline (' .. #items .. ' snapshots)',
    finder = finders.new_table {
      results = items,
      entry_maker = function(e) return { value = e, display = e.display, ordinal = tostring(e.ordinal) } end,
    },
    sorter = conf.generic_sorter({}),
    results_title = string.format("Showing All %d Snapshots", #items),
    previewer = previewers.new_buffer_previewer({
      define_preview = function(self, entry)
        local s = entry.value.snapshot
        vim.api.nvim_buf_set_lines(self.state.bufnr, 0, -1, false, s.lines)
        -- Try to set an appropriate filetype for nicer highlighting in the preview
        local ft = nil
        if s.file and s.file ~= '' and vim.filetype and vim.filetype.match then
          pcall(function()
            ft = vim.filetype.match({ filename = s.file })
          end)
        end
        if not ft then
          -- fallback to current buffer's filetype
          ft = vim.bo[cur_buf].filetype
        end
        if ft and ft ~= '' then
          pcall(function()
            vim.api.nvim_buf_set_option(self.state.bufnr, 'filetype', ft)
          end)
        end
      end,
    }),
    attach_mappings = function(prompt_bufnr, map)
      local restore = function()
        local selection = action_state.get_selected_entry()
        if selection then
          local s = selection.value.snapshot
          -- ensure we restore into a sensible target buffer
          local target_buf = resolve_target_buf(s)
          local core = require('traceback.core')
          local restored_ok = core.restore(selection.value.idx, target_buf)
          if restored_ok then
            -- success: keep quiet per policy
          else
            U.notify('󰡼 Failed to restore snapshot #' .. selection.value.idx, vim.log.levels.ERROR)
          end
        end
      end
      local diff_with_current = function()
        local selection = action_state.get_selected_entry()
        if not selection then return end
        local s = selection.value.snapshot
        -- open a vertical diff: left = snapshot, right = current buffer
        local snapshot_buf = vim.api.nvim_create_buf(false, true)
        vim.api.nvim_buf_set_lines(snapshot_buf, 0, -1, false, s.lines)
        -- try to set filetype for better highlighting
        pcall(function()
          local ft = nil
          if s.file and s.file ~= '' and vim.filetype and vim.filetype.match then
            ft = vim.filetype.match({ filename = s.file })
          end
          ft = ft or vim.bo[cur_buf].filetype
          if ft and ft ~= '' then vim.api.nvim_buf_set_option(snapshot_buf, 'filetype', ft) end
        end)
        -- open split and enable diff mode
        vim.cmd('vsplit')
        local right_win = vim.api.nvim_get_current_win()
        local right_buf = cur_buf
        vim.api.nvim_win_set_buf(right_win, right_buf)
        vim.cmd('leftabove vsplit')
        local left_win = vim.api.nvim_get_current_win()
        vim.api.nvim_win_set_buf(left_win, snapshot_buf)
        vim.cmd('wincmd l')
        vim.cmd('diffthis')
        vim.cmd('wincmd h')
        vim.cmd('diffthis')
      end
      map('i', '<CR>', function()
        restore()
        actions.close(prompt_bufnr)
      end)
      map('n', '<CR>', function()
        restore()
        actions.close(prompt_bufnr)
      end)
      -- Optional: quick restore without closing picker
      map('i', '<C-r>', function()
        restore()
      end)
      map('n', '<C-r>', function()
        restore()
      end)
      -- Diff with current buffer
      map('i', '<C-d>', function()
        diff_with_current()
      end)
      map('n', 'd', function()
        diff_with_current()
      end)
      return true
    end,
  }):find()
end

-- Simple lenses picker to quickly toggle lenses
function M.lenses_picker()
  local ok, pickers = pcall(require, 'telescope.pickers')
  if not ok then return end
  local finders = require('telescope.finders')
  local conf = require('telescope.config').values
  local actions = require('telescope.actions')
  local action_state = require('telescope.actions.state')
  local lenses = require('traceback.lenses')
  local state = {
    code = true, lsp = true, security = true,
  }
  pcall(function()
    -- crude read: render toggles live; we only need to know keys
  end)
  local entries = {
    { key = 'code', label = '󰌵 Code lens' },
    { key = 'lsp', label = '󰒡 LSP lens' },
    { key = 'security', label = '󰌾 Security lens' },
  }
  for _, e in ipairs(entries) do e.display = e.label end
  pickers.new({}, {
    prompt_title = '󰍉 TraceBack Lenses',
    finder = finders.new_table {
      results = entries,
      entry_maker = function(e)
        return { value = e, display = e.display, ordinal = e.key }
      end,
    },
    sorter = conf.generic_sorter({}),
    attach_mappings = function(prompt_bufnr, map)
      local toggle = function()
        local selection = action_state.get_selected_entry()
        if not selection then return end
        vim.cmd('TracebackLensesToggle ' .. selection.value.key)
      end
      map('i', '<CR>', function() toggle() end)
      map('n', '<CR>', function() toggle() end)
      map('n', 't', function() toggle() end)
      return true
    end,
  }):find()
end

-- Combined History picker (TraceBack snapshots + Vim undo tree entries)
function M.history_picker()
  local ok, pickers = pcall(require, 'telescope.pickers')
  if not ok then return end
  local finders = require('telescope.finders')
  local conf = require('telescope.config').values
  local actions = require('telescope.actions')
  local action_state = require('telescope.actions.state')
  local themes = require('telescope.themes')

  local cur_buf = vim.api.nvim_get_current_buf()
  local tb_items = M.timeline_items(cur_buf)
  local undo = require('traceback.undo')
  local undo_entries = undo.entries(cur_buf)

  local items = {}
  for _, e in ipairs(tb_items) do
    table.insert(items, { kind = 'snapshot', display = e.display, ordinal = 'S' .. tostring(e.idx), idx = e.idx, snapshot = e.snapshot })
  end
  for _, u in ipairs(undo_entries) do
    local disp = undo.format_entry(u)
    table.insert(items, { kind = 'undo', display = disp, ordinal = 'U' .. tostring(u.seq), seq = u.seq, entry = u })
  end

  if #items == 0 then return end

  -- config
  local cfg = {}
  pcall(function()
    local init = require('traceback.init')
    local c = init.get_config and init.get_config() or {}
    cfg = type(c.telescope) == 'table' and c.telescope or {}
  end)
  local theme = (cfg.theme == 'dropdown') and themes.get_dropdown or themes.get_ivy
  local layout_config = cfg.layout_config or { height = 0.5 }

  pickers.new(theme({ layout_config = layout_config }), {
    prompt_title = '󰔚 TraceBack History (Snapshots + Undo)',
    finder = finders.new_table {
      results = items,
      entry_maker = function(e) return { value = e, display = e.display, ordinal = e.ordinal } end,
    },
    sorter = conf.generic_sorter({}),
    attach_mappings = function(prompt_bufnr, map)
      local act = function()
        local selection = action_state.get_selected_entry()
        if not selection then return end
        local v = selection.value
        if v.kind == 'snapshot' then
          local ok_restore = require('traceback.core').restore(v.idx)
          if not ok_restore then U.notify('Failed to restore snapshot #' .. tostring(v.idx), vim.log.levels.ERROR) end
        elseif v.kind == 'undo' then
          require('traceback.undo').goto_seq(v.seq)
        end
      end
      map('i', '<CR>', function() act(); actions.close(prompt_bufnr) end)
      map('n', '<CR>', function() act(); actions.close(prompt_bufnr) end)
      return true
    end,
  }):find()
end

return M
