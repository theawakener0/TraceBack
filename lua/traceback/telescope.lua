local M = {}

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
  return string.format('%s #%03d %s %s — %s', icon, idx, time, file, first)
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
  if #items == 0 then
    vim.notify('󰗌 No snapshots available for current buffer', vim.log.levels.INFO)
    return
  end
  
  pickers.new({}, {
    prompt_title = '󰈙 TraceBack Timeline (' .. #items .. ' snapshots)',
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
          local s = selection.value.snapshot
          -- ensure we restore into the buffer that was snapshotted (fallback to current buffer)
          local target_buf = (s and s.bufnr) and s.bufnr or vim.api.nvim_get_current_buf()
          local core = require('traceback.core')
          local restored_ok = core.restore(selection.value.idx, target_buf)
          if restored_ok then
            vim.notify('󰒮 Restored snapshot #' .. selection.value.idx, vim.log.levels.INFO)
          else
            vim.notify('󰡼 Failed to restore snapshot #' .. selection.value.idx, vim.log.levels.ERROR)
          end
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

function M.suggestions_picker()
  local ok, pickers = pcall(require, 'telescope.pickers')
  if not ok then
    vim.notify('[traceback] Telescope not found', vim.log.levels.WARN)
    return
  end
  local finders = require('telescope.finders')
  local conf = require('telescope.config').values
  local actions = require('telescope.actions')
  local action_state = require('telescope.actions.state')
  local previewers = require('telescope.previewers')

  -- Get suggestions for current buffer
  local bufnr = vim.api.nvim_get_current_buf()
  local suggestions_ok, suggestions_module = pcall(require, 'traceback.suggestions')
  if not suggestions_ok then
    vim.notify('󰧑 Suggestions module not available', vim.log.levels.ERROR)
    return
  end

  local suggestions_result = suggestions_module.get_suggestions_for_buffer(bufnr)
  if not suggestions_result or #suggestions_result == 0 then
    vim.notify('󰧑 No improvement suggestions found for this buffer', vim.log.levels.INFO)
    return
  end

  -- Format suggestions for picker
  local items = {}
  for i, suggestion in ipairs(suggestions_result) do
    local confidence_text = string.format("%.0f%%", (suggestion.confidence or 0.5) * 100)
    local severity_icon = suggestion.type == "security" and "󰌾" or 
                         suggestion.type == "refactor" and "󰖷" or
                         suggestion.type == "performance" and "󰓅" or "󰧑"
    
    local display = string.format("%s %s [%s confidence, %s impact]", 
      severity_icon,
      suggestion.title or "Unnamed suggestion",
      confidence_text,
      suggestion.impact or "unknown"
    )
    
    table.insert(items, { 
      display = display, 
      ordinal = suggestion.title or ("suggestion_" .. i),
      suggestion = suggestion,
      idx = i 
    })
  end
  
  pickers.new({}, {
    prompt_title = '󰧑 TraceBack Buffer Suggestions (' .. #items .. ' found)',
    finder = finders.new_table {
      results = items,
      entry_maker = function(e) 
        return { 
          value = e, 
          display = e.display, 
          ordinal = e.ordinal
        } 
      end,
    },
    sorter = conf.generic_sorter({}),
    previewer = previewers.new_buffer_previewer({
      define_preview = function(self, entry)
        local suggestion = entry.value.suggestion
        local preview_lines = {}
        
        -- Title and basic info
        table.insert(preview_lines, "# " .. (suggestion.title or "Suggestion"))
        table.insert(preview_lines, "")
        table.insert(preview_lines, "**Type:** " .. (suggestion.type or "unknown"))
        if suggestion.confidence then
          table.insert(preview_lines, "**Confidence:** " .. string.format("%.1f%%", suggestion.confidence * 100))
        end
        if suggestion.impact then
          table.insert(preview_lines, "**Impact:** " .. suggestion.impact)
        end
        table.insert(preview_lines, "")
        
        -- Description
        if suggestion.description then
          table.insert(preview_lines, "## Description")
          table.insert(preview_lines, suggestion.description)
          table.insert(preview_lines, "")
        end
        
        -- Suggestion details
        if suggestion.suggestion then
          table.insert(preview_lines, "## Suggestion")
          table.insert(preview_lines, suggestion.suggestion)
          table.insert(preview_lines, "")
        end
        
        -- Code location
        if suggestion.range then
          local start_line = suggestion.range.start and suggestion.range.start[1] or 1
          local end_line = suggestion.range["end"] and suggestion.range["end"][1] or start_line
          table.insert(preview_lines, "## Location")
          table.insert(preview_lines, string.format("Lines %d-%d", start_line, end_line))
          table.insert(preview_lines, "")
        end
        
        -- Replacement code if available
        if suggestion.replacement then
          table.insert(preview_lines, "## Suggested Replacement")
          table.insert(preview_lines, "```" .. (vim.bo[bufnr].filetype or ""))
          table.insert(preview_lines, suggestion.replacement)
          table.insert(preview_lines, "```")
          table.insert(preview_lines, "")
        end
        
        -- CWE or security info
        if suggestion.cwe then
          table.insert(preview_lines, "## Security Reference")
          table.insert(preview_lines, suggestion.cwe)
          table.insert(preview_lines, "")
        end
        
        vim.api.nvim_buf_set_lines(self.state.bufnr, 0, -1, false, preview_lines)
        vim.api.nvim_buf_set_option(self.state.bufnr, 'filetype', 'markdown')
      end,
    }),
    attach_mappings = function(prompt_bufnr, map)
      local apply_suggestion = function()
        local selection = action_state.get_selected_entry()
        if selection then
          local suggestion = selection.value.suggestion
          -- Convert to annotation format and show actions
          local actions_module = require('traceback.actions')
          local annotation = {
            id = "suggestion_picker_" .. selection.value.idx,
            type = "suggestion",
            title = suggestion.title,
            message = actions_module._format_suggestion_message(suggestion),
            range = suggestion.range,
            severity = actions_module._suggestion_severity(suggestion),
            suggestion_data = suggestion,
            actions = actions_module._get_suggestion_actions(suggestion)
          }
          actions.close(prompt_bufnr)
          actions_module.show_actions_for_annotation(annotation)
        end
      end
      
      map('i', '<CR>', apply_suggestion)
      map('n', '<CR>', apply_suggestion)
      
      -- Quick apply fix mapping
      map('i', '<C-a>', function()
        local selection = action_state.get_selected_entry()
        if selection and selection.value.suggestion.replacement then
          local suggestion = selection.value.suggestion
          local range = suggestion.range
          if range then
            vim.api.nvim_buf_set_text(bufnr,
              range.start[1] - 1, range.start[2] or 0,
              range["end"][1] - 1, range["end"][2] or -1,
              vim.split(suggestion.replacement, '\n'))
            vim.notify("󰁨 Applied suggestion: " .. suggestion.title, vim.log.levels.INFO)
          end
        end
        actions.close(prompt_bufnr)
      end)
      
      return true
    end,
  }):find()
end

return M
