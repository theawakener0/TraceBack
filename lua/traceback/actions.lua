-- traceback.actions has been removed.
--
-- As part of the refactor to reduce notification noise and simplify the
-- plugin, the code actions UI and the separate suggestions engine were
-- deprecated and removed. There is no replacement API.
--
-- Use lenses and Telescope pickers instead:
--   - :Telescope traceback timeline  -- timeline with preview/diff
--   - :Telescope traceback lenses    -- toggle code|lsp|security lenses
--   - :TracebackReplayCancel         -- cancel an ongoing replay
--
-- See README.md and :h traceback for current documentation.

error("traceback.actions has been removed. See README and :h traceback for current features.")
