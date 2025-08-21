local M = {}

-- This module exposes a picker; we also register a proper telescope extension if loaded elsewhere.

local function format_item(idx, s)
  local time = os.date('%H:%M:%S', math.floor((s.ts or 0)/1000))
  local file = s.file ~= '' and vim.fn.fnamemodify(s.file, ':t') or '[No Name]'
  local first = (s.lines[1] or ''):gsub('%s+', ' ')
  return string.format('#%03d %s %s — %s', idx, time, file, first)
end

function M.timeline_items(bufnr)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  local tl = require('traceback.core').timeline(bufnr)
  local items = {}
  for i, s in ipairs(tl.snapshots) do
    table.insert(items, { display = format_item(i, s), ordinal = i, idx = i, snapshot = s })
  end
  return items
end

function M.timeline_picker()
  local ok, pickers = pcall(require, 'telescope.pickers')
  if not ok then
    vim.notify('[traceback] Telescope not found', vim.log.levels.WARN)
    return
  end
  local finders = require('telescope.finders')
  local conf = require('telescope.config').values
  local actions = require('telescope.actions')
  local action_state = require('telescope.actions.state')

  local items = M.timeline_items()
  pickers.new({}, {
    prompt_title = 'Traceback Timeline',
    finder = finders.new_table {
      results = items,
      entry_maker = function(e) return { value = e, display = e.display, ordinal = tostring(e.ordinal) } end,
    },
    sorter = conf.generic_sorter({}),
    previewer = require('telescope.previewers').new_buffer_previewer({
      define_preview = function(self, entry)
        local s = entry.value.snapshot
        vim.api.nvim_buf_set_lines(self.state.bufnr, 0, -1, false, s.lines)
      end,
    }),
    attach_mappings = function(prompt_bufnr, map)
      local restore = function()
        local selection = action_state.get_selected_entry()
        if selection then
          require('traceback.core').restore(selection.value.idx)
        end
      end
      map('i', '<CR>', function()
        restore()
        actions.close(prompt_bufnr)
      end)
      map('n', '<CR>', function()
        restore()
        actions.close(prompt_bufnr)
      end)
      return true
    end,
  }):find()
end

return M
