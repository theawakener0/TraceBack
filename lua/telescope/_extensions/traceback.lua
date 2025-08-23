local tb_telescope = require('traceback.telescope')

return require('telescope').register_extension({
  exports = {
    timeline = tb_telescope.timeline_picker,
    suggestions = tb_telescope.suggestions_picker,
  },
})
