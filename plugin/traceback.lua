if vim.g.loaded_traceback then return end
vim.g.loaded_traceback = true

local ok, tb = pcall(require, 'traceback')
if not ok then return end

-- Defer default setup until VimEnter so <Leader> mappings use the user's leader value.
-- If the user has already called require('traceback').setup({...}), skip auto-setup.
vim.api.nvim_create_autocmd('VimEnter', {
    once = true,
    callback = function()
        if vim.g.traceback_setup_called then return end
        pcall(function() tb.setup({}) end)
    end,
})
