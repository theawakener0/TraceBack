local tb_telescope = require('traceback.telescope')

return require('telescope').register_extension({
  exports = {
    timeline = tb_telescope.timeline_picker,
    lenses = tb_telescope.lenses_picker,
    history = tb_telescope.history_picker,
  },
})
