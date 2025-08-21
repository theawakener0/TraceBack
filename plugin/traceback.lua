if vim.g.loaded_traceback then return end
vim.g.loaded_traceback = true

local ok, tb = pcall(require, 'traceback')
if not ok then return end

-- default setup on load; users can call setup() with options too
vim.schedule(function()
    tb.setup({})
end)
