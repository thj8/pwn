--- @meta _
-- THIS FILE IS GENERATED
-- DO NOT EDIT
error('Cannot require a meta file')

vim.api = {}

--- @private
--- @param buffer integer
--- @param keys boolean
--- @param dot boolean
--- @return string
function vim.api.nvim__buf_debug_extmarks(buffer, keys, dot) end

--- @private
--- @param buffer integer
--- @return table<string,any>
function vim.api.nvim__buf_stats(buffer) end

--- @private
--- EXPERIMENTAL: this API may change in the future.
---
--- Sets info for the completion item at the given index. If the info text was
--- shown in a window, returns the window and buffer ids, or empty dict if not
--- shown.
---
--- @param index integer Completion candidate index
--- @param opts vim.api.keyset.complete_set Optional parameters.
---             • info: (string) info text.
--- @return table<string,any>
function vim.api.nvim__complete_set(index, opts) end

--- @private
--- @return string
function vim.api.nvim__get_lib_dir() end

--- @private
--- Find files in runtime directories
---
--- @param pat any[] pattern of files to search for
--- @param all boolean whether to return all matches or only the first
--- @param opts vim.api.keyset.runtime is_lua: only search Lua subdirs
--- @return string[]
function vim.api.nvim__get_runtime(pat, all, opts) end

--- @private
--- Returns object given as argument.
---
--- This API function is used for testing. One should not rely on its presence
--- in plugins.
---
--- @param obj any Object to return.
--- @return any
function vim.api.nvim__id(obj) end

--- @private
--- Returns array given as argument.
---
--- This API function is used for testing. One should not rely on its presence
--- in plugins.
---
--- @param arr any[] Array to return.
--- @return any[]
function vim.api.nvim__id_array(arr) end

--- @private
--- Returns dictionary given as argument.
---
--- This API function is used for testing. One should not rely on its presence
--- in plugins.
---
--- @param dct table<string,any> Dictionary to return.
--- @return table<string,any>
function vim.api.nvim__id_dictionary(dct) end

--- @private
--- Returns floating-point value given as argument.
---
--- This API function is used for testing. One should not rely on its presence
--- in plugins.
---
--- @param flt number Value to return.
--- @return number
function vim.api.nvim__id_float(flt) end

--- @private
--- NB: if your UI doesn't use hlstate, this will not return hlstate first
--- time.
---
--- @param grid integer
--- @param row integer
--- @param col integer
--- @return any[]
function vim.api.nvim__inspect_cell(grid, row, col) end

--- @private
--- For testing. The condition in schar_cache_clear_if_full is hard to reach,
--- so this function can be used to force a cache clear in a test.
---
function vim.api.nvim__invalidate_glyph_cache() end

--- @private
--- EXPERIMENTAL: this API may change in the future.
---
--- Instruct Nvim to redraw various components.
---
--- @param opts vim.api.keyset.redraw Optional parameters.
---             • win: Target a specific `window-ID` as described below.
---             • buf: Target a specific buffer number as described below.
---             • flush: Update the screen with pending updates.
---             • valid: When present mark `win`, `buf`, or all windows for
---               redraw. When `true`, only redraw changed lines (useful for
---               decoration providers). When `false`, forcefully redraw.
---             • range: Redraw a range in `buf`, the buffer in `win` or the
---               current buffer (useful for decoration providers). Expects a
---               tuple `[first, last]` with the first and last line number of
---               the range, 0-based end-exclusive `api-indexing`.
---             • cursor: Immediately update cursor position on the screen in
---               `win` or the current window.
---             • statuscolumn: Redraw the 'statuscolumn' in `buf`, `win` or
---               all windows.
---             • statusline: Redraw the 'statusline' in `buf`, `win` or all
---               windows.
---             • winbar: Redraw the 'winbar' in `buf`, `win` or all windows.
---             • tabline: Redraw the 'tabline'.
function vim.api.nvim__redraw(opts) end

--- @private
--- @return any[]
function vim.api.nvim__runtime_inspect() end

--- @private
--- @param path string
function vim.api.nvim__screenshot(path) end

--- @private
--- Gets internal stats.
---
--- @return table<string,any>
function vim.api.nvim__stats() end

--- @private
--- @param str string
--- @return any
function vim.api.nvim__unpack(str) end

--- @private
--- EXPERIMENTAL: this API will change in the future.
---
--- Scopes a namespace to the a window, so extmarks in the namespace will be
--- active only in the given window.
---
--- @param window integer Window handle, or 0 for current window
--- @param ns_id integer Namespace
--- @return boolean
function vim.api.nvim__win_add_ns(window, ns_id) end

--- @private
--- EXPERIMENTAL: this API will change in the future.
---
--- Unscopes a namespace (un-binds it from the given scope).
---
--- @param window integer Window handle, or 0 for current window
--- @param ns_id integer the namespace to remove
--- @return boolean
function vim.api.nvim__win_del_ns(window, ns_id) end

--- @private
--- EXPERIMENTAL: this API will change in the future.
---
--- Gets the namespace scopes for a given window.
---
--- @param window integer Window handle, or 0 for current window
--- @return integer[]
function vim.api.nvim__win_get_ns(window) end

--- Adds a highlight to buffer.
---
--- Useful for plugins that dynamically generate highlights to a buffer (like
--- a semantic highlighter or linter). The function adds a single highlight to
--- a buffer. Unlike `matchaddpos()` highlights follow changes to line
--- numbering (as lines are inserted/removed above the highlighted line), like
--- signs and marks do.
---
--- Namespaces are used for batch deletion/updating of a set of highlights. To
--- create a namespace, use `nvim_create_namespace()` which returns a
--- namespace id. Pass it in to this function as `ns_id` to add highlights to
--- the namespace. All highlights in the same namespace can then be cleared
--- with single call to `nvim_buf_clear_namespace()`. If the highlight never
--- will be deleted by an API call, pass `ns_id = -1`.
---
--- As a shorthand, `ns_id = 0` can be used to create a new namespace for the
--- highlight, the allocated id is then returned. If `hl_group` is the empty
--- string no highlight is added, but a new `ns_id` is still returned. This is
--- supported for backwards compatibility, new code should use
--- `nvim_create_namespace()` to create a new empty namespace.
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param ns_id integer namespace to use or -1 for ungrouped highlight
--- @param hl_group string Name of the highlight group to use
--- @param line integer Line to highlight (zero-indexed)
--- @param col_start integer Start of (byte-indexed) column range to highlight
--- @param col_end integer End of (byte-indexed) column range to highlight, or -1 to
---                highlight to end of line
--- @return integer
function vim.api.nvim_buf_add_highlight(buffer, ns_id, hl_group, line, col_start, col_end) end

--- Activates buffer-update events on a channel, or as Lua callbacks.
---
--- Example (Lua): capture buffer updates in a global `events` variable (use
--- "vim.print(events)" to see its contents):
---
--- ```lua
---     events = {}
---     vim.api.nvim_buf_attach(0, false, {
---       on_lines = function(...)
---         table.insert(events, {...})
---       end,
---     })
--- ```
---
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param send_buffer boolean True if the initial notification should contain the
---                    whole buffer: first notification will be
---                    `nvim_buf_lines_event`. Else the first notification
---                    will be `nvim_buf_changedtick_event`. Not for Lua
---                    callbacks.
--- @param opts vim.api.keyset.buf_attach Optional parameters.
---             • on_lines: Lua callback invoked on change. Return a truthy
---               value (not `false` or `nil`) to detach. Args:
---               • the string "lines"
---               • buffer handle
---               • b:changedtick
---               • first line that changed (zero-indexed)
---               • last line that was changed
---               • last line in the updated range
---               • byte count of previous contents
---               • deleted_codepoints (if `utf_sizes` is true)
---               • deleted_codeunits (if `utf_sizes` is true)
---             • on_bytes: Lua callback invoked on change. This callback
---               receives more granular information about the change compared
---               to on_lines. Return a truthy value (not `false` or `nil`) to
---               detach. Args:
---               • the string "bytes"
---               • buffer handle
---               • b:changedtick
---               • start row of the changed text (zero-indexed)
---               • start column of the changed text
---               • byte offset of the changed text (from the start of the
---                 buffer)
---               • old end row of the changed text (offset from start row)
---               • old end column of the changed text (if old end row = 0,
---                 offset from start column)
---               • old end byte length of the changed text
---               • new end row of the changed text (offset from start row)
---               • new end column of the changed text (if new end row = 0,
---                 offset from start column)
---               • new end byte length of the changed text
---             • on_changedtick: Lua callback invoked on changedtick
---               increment without text change. Args:
---               • the string "changedtick"
---               • buffer handle
---               • b:changedtick
---             • on_detach: Lua callback invoked on detach. Args:
---               • the string "detach"
---               • buffer handle
---             • on_reload: Lua callback invoked on reload. The entire buffer
---               content should be considered changed. Args:
---               • the string "reload"
---               • buffer handle
---             • utf_sizes: include UTF-32 and UTF-16 size of the replaced
---               region, as args to `on_lines`.
---             • preview: also attach to command preview (i.e. 'inccommand')
---               events.
--- @return boolean
function vim.api.nvim_buf_attach(buffer, send_buffer, opts) end

--- call a function with buffer as temporary current buffer
---
--- This temporarily switches current buffer to "buffer". If the current
--- window already shows "buffer", the window is not switched If a window
--- inside the current tabpage (including a float) already shows the buffer
--- One of these windows will be set as current window temporarily. Otherwise
--- a temporary scratch window (called the "autocmd window" for historical
--- reasons) will be used.
---
--- This is useful e.g. to call Vimscript functions that only work with the
--- current buffer/window currently, like `termopen()`.
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param fun function Function to call inside the buffer (currently Lua callable
---            only)
--- @return any
function vim.api.nvim_buf_call(buffer, fun) end

--- @deprecated
--- @param buffer integer
--- @param ns_id integer
--- @param line_start integer
--- @param line_end integer
function vim.api.nvim_buf_clear_highlight(buffer, ns_id, line_start, line_end) end

--- Clears `namespace`d objects (highlights, `extmarks`, virtual text) from a
--- region.
---
--- Lines are 0-indexed. `api-indexing` To clear the namespace in the entire
--- buffer, specify line_start=0 and line_end=-1.
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param ns_id integer Namespace to clear, or -1 to clear all namespaces.
--- @param line_start integer Start of range of lines to clear
--- @param line_end integer End of range of lines to clear (exclusive) or -1 to clear
---                 to end of buffer.
function vim.api.nvim_buf_clear_namespace(buffer, ns_id, line_start, line_end) end

--- Creates a buffer-local command `user-commands`.
---
--- @param buffer integer Buffer handle, or 0 for current buffer.
--- @param name string
--- @param command any
--- @param opts vim.api.keyset.user_command
function vim.api.nvim_buf_create_user_command(buffer, name, command, opts) end

--- Removes an `extmark`.
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param ns_id integer Namespace id from `nvim_create_namespace()`
--- @param id integer Extmark id
--- @return boolean
function vim.api.nvim_buf_del_extmark(buffer, ns_id, id) end

--- Unmaps a buffer-local `mapping` for the given mode.
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param mode string
--- @param lhs string
function vim.api.nvim_buf_del_keymap(buffer, mode, lhs) end

--- Deletes a named mark in the buffer. See `mark-motions`.
---
--- @param buffer integer Buffer to set the mark on
--- @param name string Mark name
--- @return boolean
function vim.api.nvim_buf_del_mark(buffer, name) end

--- Delete a buffer-local user-defined command.
---
--- Only commands created with `:command-buffer` or
--- `nvim_buf_create_user_command()` can be deleted with this function.
---
--- @param buffer integer Buffer handle, or 0 for current buffer.
--- @param name string Name of the command to delete.
function vim.api.nvim_buf_del_user_command(buffer, name) end

--- Removes a buffer-scoped (b:) variable
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param name string Variable name
function vim.api.nvim_buf_del_var(buffer, name) end

--- Deletes the buffer. See `:bwipeout`
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param opts vim.api.keyset.buf_delete Optional parameters. Keys:
---             • force: Force deletion and ignore unsaved changes.
---             • unload: Unloaded only, do not delete. See `:bunload`
function vim.api.nvim_buf_delete(buffer, opts) end

--- Gets a changed tick of a buffer
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @return integer
function vim.api.nvim_buf_get_changedtick(buffer) end

--- Gets a map of buffer-local `user-commands`.
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param opts vim.api.keyset.get_commands Optional parameters. Currently not used.
--- @return table<string,any>
function vim.api.nvim_buf_get_commands(buffer, opts) end

--- Gets the position (0-indexed) of an `extmark`.
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param ns_id integer Namespace id from `nvim_create_namespace()`
--- @param id integer Extmark id
--- @param opts vim.api.keyset.get_extmark Optional parameters. Keys:
---             • details: Whether to include the details dict
---             • hl_name: Whether to include highlight group name instead of
---               id, true if omitted
--- @return vim.api.keyset.get_extmark_item
function vim.api.nvim_buf_get_extmark_by_id(buffer, ns_id, id, opts) end

--- Gets `extmarks` in "traversal order" from a `charwise` region defined by
--- buffer positions (inclusive, 0-indexed `api-indexing`).
---
--- Region can be given as (row,col) tuples, or valid extmark ids (whose
--- positions define the bounds). 0 and -1 are understood as (0,0) and (-1,-1)
--- respectively, thus the following are equivalent:
---
--- ```lua
---     vim.api.nvim_buf_get_extmarks(0, my_ns, 0, -1, {})
---     vim.api.nvim_buf_get_extmarks(0, my_ns, {0,0}, {-1,-1}, {})
--- ```
---
--- If `end` is less than `start`, traversal works backwards. (Useful with
--- `limit`, to get the first marks prior to a given position.)
---
--- Note: when using extmark ranges (marks with a end_row/end_col position)
--- the `overlap` option might be useful. Otherwise only the start position of
--- an extmark will be considered.
---
--- Note: legacy signs placed through the `:sign` commands are implemented as
--- extmarks and will show up here. Their details array will contain a
--- `sign_name` field.
---
--- Example:
---
--- ```lua
---     local api = vim.api
---     local pos = api.nvim_win_get_cursor(0)
---     local ns  = api.nvim_create_namespace('my-plugin')
---     -- Create new extmark at line 1, column 1.
---     local m1  = api.nvim_buf_set_extmark(0, ns, 0, 0, {})
---     -- Create new extmark at line 3, column 1.
---     local m2  = api.nvim_buf_set_extmark(0, ns, 2, 0, {})
---     -- Get extmarks only from line 3.
---     local ms  = api.nvim_buf_get_extmarks(0, ns, {2,0}, {2,0}, {})
---     -- Get all marks in this buffer + namespace.
---     local all = api.nvim_buf_get_extmarks(0, ns, 0, -1, {})
---     vim.print(ms)
--- ```
---
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param ns_id integer Namespace id from `nvim_create_namespace()` or -1 for all
---              namespaces
--- @param start any Start of range: a 0-indexed (row, col) or valid extmark id
---              (whose position defines the bound). `api-indexing`
--- @param end_ any End of range (inclusive): a 0-indexed (row, col) or valid
---             extmark id (whose position defines the bound). `api-indexing`
--- @param opts vim.api.keyset.get_extmarks Optional parameters. Keys:
---             • limit: Maximum number of marks to return
---             • details: Whether to include the details dict
---             • hl_name: Whether to include highlight group name instead of
---               id, true if omitted
---             • overlap: Also include marks which overlap the range, even if
---               their start position is less than `start`
---             • type: Filter marks by type: "highlight", "sign", "virt_text"
---               and "virt_lines"
--- @return vim.api.keyset.get_extmark_item[]
function vim.api.nvim_buf_get_extmarks(buffer, ns_id, start, end_, opts) end

--- Gets a list of buffer-local `mapping` definitions.
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param mode string Mode short-name ("n", "i", "v", ...)
--- @return vim.api.keyset.keymap[]
function vim.api.nvim_buf_get_keymap(buffer, mode) end

--- Gets a line-range from the buffer.
---
--- Indexing is zero-based, end-exclusive. Negative indices are interpreted as
--- length+1+index: -1 refers to the index past the end. So to get the last
--- element use start=-2 and end=-1.
---
--- Out-of-bounds indices are clamped to the nearest valid value, unless
--- `strict_indexing` is set.
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param start integer First line index
--- @param end_ integer Last line index, exclusive
--- @param strict_indexing boolean Whether out-of-bounds should be an error.
--- @return string[]
function vim.api.nvim_buf_get_lines(buffer, start, end_, strict_indexing) end

--- Returns a `(row,col)` tuple representing the position of the named mark.
--- "End of line" column position is returned as `v:maxcol` (big number). See
--- `mark-motions`.
---
--- Marks are (1,0)-indexed. `api-indexing`
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param name string Mark name
--- @return integer[]
function vim.api.nvim_buf_get_mark(buffer, name) end

--- Gets the full file name for the buffer
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @return string
function vim.api.nvim_buf_get_name(buffer) end

--- @deprecated
--- @param buffer integer
--- @return integer
function vim.api.nvim_buf_get_number(buffer) end

--- Returns the byte offset of a line (0-indexed). `api-indexing`
---
--- Line 1 (index=0) has offset 0. UTF-8 bytes are counted. EOL is one byte.
--- 'fileformat' and 'fileencoding' are ignored. The line index just after the
--- last line gives the total byte-count of the buffer. A final EOL byte is
--- counted if it would be written, see 'eol'.
---
--- Unlike `line2byte()`, throws error for out-of-bounds indexing. Returns -1
--- for unloaded buffer.
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param index integer Line index
--- @return integer
function vim.api.nvim_buf_get_offset(buffer, index) end

--- @deprecated
--- @param buffer integer
--- @param name string
--- @return any
function vim.api.nvim_buf_get_option(buffer, name) end

--- Gets a range from the buffer.
---
--- This differs from `nvim_buf_get_lines()` in that it allows retrieving only
--- portions of a line.
---
--- Indexing is zero-based. Row indices are end-inclusive, and column indices
--- are end-exclusive.
---
--- Prefer `nvim_buf_get_lines()` when retrieving entire lines.
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param start_row integer First line index
--- @param start_col integer Starting column (byte offset) on first line
--- @param end_row integer Last line index, inclusive
--- @param end_col integer Ending column (byte offset) on last line, exclusive
--- @param opts vim.api.keyset.empty Optional parameters. Currently unused.
--- @return string[]
function vim.api.nvim_buf_get_text(buffer, start_row, start_col, end_row, end_col, opts) end

--- Gets a buffer-scoped (b:) variable.
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param name string Variable name
--- @return any
function vim.api.nvim_buf_get_var(buffer, name) end

--- Checks if a buffer is valid and loaded. See `api-buffer` for more info
--- about unloaded buffers.
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @return boolean
function vim.api.nvim_buf_is_loaded(buffer) end

--- Checks if a buffer is valid.
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @return boolean
function vim.api.nvim_buf_is_valid(buffer) end

--- Returns the number of lines in the given buffer.
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @return integer
function vim.api.nvim_buf_line_count(buffer) end

--- Creates or updates an `extmark`.
---
--- By default a new extmark is created when no id is passed in, but it is
--- also possible to create a new mark by passing in a previously unused id or
--- move an existing mark by passing in its id. The caller must then keep
--- track of existing and unused ids itself. (Useful over RPC, to avoid
--- waiting for the return value.)
---
--- Using the optional arguments, it is possible to use this to highlight a
--- range of text, and also to associate virtual text to the mark.
---
--- If present, the position defined by `end_col` and `end_row` should be
--- after the start position in order for the extmark to cover a range. An
--- earlier end position is not an error, but then it behaves like an empty
--- range (no highlighting).
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param ns_id integer Namespace id from `nvim_create_namespace()`
--- @param line integer Line where to place the mark, 0-based. `api-indexing`
--- @param col integer Column where to place the mark, 0-based. `api-indexing`
--- @param opts vim.api.keyset.set_extmark Optional parameters.
---             • id : id of the extmark to edit.
---             • end_row : ending line of the mark, 0-based inclusive.
---             • end_col : ending col of the mark, 0-based exclusive.
---             • hl_group : name of the highlight group used to highlight
---               this mark.
---             • hl_eol : when true, for a multiline highlight covering the
---               EOL of a line, continue the highlight for the rest of the
---               screen line (just like for diff and cursorline highlight).
---             • virt_text : virtual text to link to this mark. A list of
---               `[text, highlight]` tuples, each representing a text chunk
---               with specified highlight. `highlight` element can either be
---               a single highlight group, or an array of multiple highlight
---               groups that will be stacked (highest priority last). A
---               highlight group can be supplied either as a string or as an
---               integer, the latter which can be obtained using
---               `nvim_get_hl_id_by_name()`.
---             • virt_text_pos : position of virtual text. Possible values:
---               • "eol": right after eol character (default).
---               • "overlay": display over the specified column, without
---                 shifting the underlying text.
---               • "right_align": display right aligned in the window.
---               • "inline": display at the specified column, and shift the
---                 buffer text to the right as needed.
---             • virt_text_win_col : position the virtual text at a fixed
---               window column (starting from the first text column of the
---               screen line) instead of "virt_text_pos".
---             • virt_text_hide : hide the virtual text when the background
---               text is selected or hidden because of scrolling with
---               'nowrap' or 'smoothscroll'. Currently only affects "overlay"
---               virt_text.
---             • virt_text_repeat_linebreak : repeat the virtual text on
---               wrapped lines.
---             • hl_mode : control how highlights are combined with the
---               highlights of the text. Currently only affects virt_text
---               highlights, but might affect `hl_group` in later versions.
---               • "replace": only show the virt_text color. This is the
---                 default.
---               • "combine": combine with background text color.
---               • "blend": blend with background text color. Not supported
---                 for "inline" virt_text.
---             • virt_lines : virtual lines to add next to this mark This
---               should be an array over lines, where each line in turn is an
---               array over `[text, highlight]` tuples. In general, buffer
---               and window options do not affect the display of the text. In
---               particular 'wrap' and 'linebreak' options do not take
---               effect, so the number of extra screen lines will always
---               match the size of the array. However the 'tabstop' buffer
---               option is still used for hard tabs. By default lines are
---               placed below the buffer line containing the mark.
---             • virt_lines_above: place virtual lines above instead.
---             • virt_lines_leftcol: Place extmarks in the leftmost column of
---               the window, bypassing sign and number columns.
---             • ephemeral : for use with `nvim_set_decoration_provider()`
---               callbacks. The mark will only be used for the current redraw
---               cycle, and not be permantently stored in the buffer.
---             • right_gravity : boolean that indicates the direction the
---               extmark will be shifted in when new text is inserted (true
---               for right, false for left). Defaults to true.
---             • end_right_gravity : boolean that indicates the direction the
---               extmark end position (if it exists) will be shifted in when
---               new text is inserted (true for right, false for left).
---               Defaults to false.
---             • undo_restore : Restore the exact position of the mark if
---               text around the mark was deleted and then restored by undo.
---               Defaults to true.
---             • invalidate : boolean that indicates whether to hide the
---               extmark if the entirety of its range is deleted. For hidden
---               marks, an "invalid" key is added to the "details" array of
---               `nvim_buf_get_extmarks()` and family. If "undo_restore" is
---               false, the extmark is deleted instead.
---             • priority: a priority value for the highlight group, sign
---               attribute or virtual text. For virtual text, item with
---               highest priority is drawn last. For example treesitter
---               highlighting uses a value of 100.
---             • strict: boolean that indicates extmark should not be placed
---               if the line or column value is past the end of the buffer or
---               end of the line respectively. Defaults to true.
---             • sign_text: string of length 1-2 used to display in the sign
---               column.
---             • sign_hl_group: name of the highlight group used to highlight
---               the sign column text.
---             • number_hl_group: name of the highlight group used to
---               highlight the number column.
---             • line_hl_group: name of the highlight group used to highlight
---               the whole line.
---             • cursorline_hl_group: name of the highlight group used to
---               highlight the sign column text when the cursor is on the
---               same line as the mark and 'cursorline' is enabled.
---             • conceal: string which should be either empty or a single
---               character. Enable concealing similar to `:syn-conceal`. When
---               a character is supplied it is used as `:syn-cchar`.
---               "hl_group" is used as highlight for the cchar if provided,
---               otherwise it defaults to `hl-Conceal`.
---             • spell: boolean indicating that spell checking should be
---               performed within this extmark
---             • ui_watched: boolean that indicates the mark should be drawn
---               by a UI. When set, the UI will receive win_extmark events.
---               Note: the mark is positioned by virt_text attributes. Can be
---               used together with virt_text.
---             • url: A URL to associate with this extmark. In the TUI, the
---               OSC 8 control sequence is used to generate a clickable
---               hyperlink to this URL.
---             • scoped: boolean (EXPERIMENTAL) enables "scoping" for the
---               extmark. See `nvim__win_add_ns()`
--- @return integer
function vim.api.nvim_buf_set_extmark(buffer, ns_id, line, col, opts) end

--- Sets a buffer-local `mapping` for the given mode.
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param mode string
--- @param lhs string
--- @param rhs string
--- @param opts vim.api.keyset.keymap
function vim.api.nvim_buf_set_keymap(buffer, mode, lhs, rhs, opts) end

--- Sets (replaces) a line-range in the buffer.
---
--- Indexing is zero-based, end-exclusive. Negative indices are interpreted as
--- length+1+index: -1 refers to the index past the end. So to change or
--- delete the last element use start=-2 and end=-1.
---
--- To insert lines at a given index, set `start` and `end` to the same index.
--- To delete a range of lines, set `replacement` to an empty array.
---
--- Out-of-bounds indices are clamped to the nearest valid value, unless
--- `strict_indexing` is set.
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param start integer First line index
--- @param end_ integer Last line index, exclusive
--- @param strict_indexing boolean Whether out-of-bounds should be an error.
--- @param replacement string[] Array of lines to use as replacement
function vim.api.nvim_buf_set_lines(buffer, start, end_, strict_indexing, replacement) end

--- Sets a named mark in the given buffer, all marks are allowed
--- file/uppercase, visual, last change, etc. See `mark-motions`.
---
--- Marks are (1,0)-indexed. `api-indexing`
---
--- @param buffer integer Buffer to set the mark on
--- @param name string Mark name
--- @param line integer Line number
--- @param col integer Column/row number
--- @param opts vim.api.keyset.empty Optional parameters. Reserved for future use.
--- @return boolean
function vim.api.nvim_buf_set_mark(buffer, name, line, col, opts) end

--- Sets the full file name for a buffer, like `:file_f`
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param name string Buffer name
function vim.api.nvim_buf_set_name(buffer, name) end

--- @deprecated
--- @param buffer integer
--- @param name string
--- @param value any
function vim.api.nvim_buf_set_option(buffer, name, value) end

--- Sets (replaces) a range in the buffer
---
--- This is recommended over `nvim_buf_set_lines()` when only modifying parts
--- of a line, as extmarks will be preserved on non-modified parts of the
--- touched lines.
---
--- Indexing is zero-based. Row indices are end-inclusive, and column indices
--- are end-exclusive.
---
--- To insert text at a given `(row, column)` location, use
--- `start_row = end_row = row` and `start_col = end_col = col`. To delete the
--- text in a range, use `replacement = {}`.
---
--- Prefer `nvim_buf_set_lines()` if you are only adding or deleting entire
--- lines.
---
--- Prefer `nvim_put()` if you want to insert text at the cursor position.
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param start_row integer First line index
--- @param start_col integer Starting column (byte offset) on first line
--- @param end_row integer Last line index, inclusive
--- @param end_col integer Ending column (byte offset) on last line, exclusive
--- @param replacement string[] Array of lines to use as replacement
function vim.api.nvim_buf_set_text(buffer, start_row, start_col, end_row, end_col, replacement) end

--- Sets a buffer-scoped (b:) variable
---
--- @param buffer integer Buffer handle, or 0 for current buffer
--- @param name string Variable name
--- @param value any Variable value
function vim.api.nvim_buf_set_var(buffer, name, value) end

--- @deprecated
--- @param buffer integer
--- @param src_id integer
--- @param line integer
--- @param chunks any[]
--- @param opts vim.api.keyset.empty
--- @return integer
function vim.api.nvim_buf_set_virtual_text(buffer, src_id, line, chunks, opts) end

--- Calls a Vimscript `Dictionary-function` with the given arguments.
---
--- On execution error: fails with Vimscript error, updates v:errmsg.
---
--- @param dict any Dictionary, or String evaluating to a Vimscript `self` dict
--- @param fn string Name of the function defined on the Vimscript dict
--- @param args any[] Function arguments packed in an Array
--- @return any
function vim.api.nvim_call_dict_function(dict, fn, args) end

--- Calls a Vimscript function with the given arguments.
---
--- On execution error: fails with Vimscript error, updates v:errmsg.
---
--- @param fn string Function to call
--- @param args any[] Function arguments packed in an Array
--- @return any
function vim.api.nvim_call_function(fn, args) end

--- Send data to channel `id`. For a job, it writes it to the stdin of the
--- process. For the stdio channel `channel-stdio`, it writes to Nvim's
--- stdout. For an internal terminal instance (`nvim_open_term()`) it writes
--- directly to terminal output. See `channel-bytes` for more information.
---
--- This function writes raw data, not RPC messages. If the channel was
--- created with `rpc=true` then the channel expects RPC messages, use
--- `vim.rpcnotify()` and `vim.rpcrequest()` instead.
---
--- @param chan integer id of the channel
--- @param data string data to write. 8-bit clean: can contain NUL bytes.
function vim.api.nvim_chan_send(chan, data) end

--- Clears all autocommands selected by {opts}. To delete autocmds see
--- `nvim_del_autocmd()`.
---
--- @param opts vim.api.keyset.clear_autocmds Parameters
---             • event: (string|table) Examples:
---               • event: "pat1"
---               • event: { "pat1" }
---               • event: { "pat1", "pat2", "pat3" }
---             • pattern: (string|table)
---               • pattern or patterns to match exactly.
---                 • For example, if you have `*.py` as that pattern for the
---                   autocmd, you must pass `*.py` exactly to clear it.
---                   `test.py` will not match the pattern.
---               • defaults to clearing all patterns.
---               • NOTE: Cannot be used with {buffer}
---             • buffer: (bufnr)
---               • clear only `autocmd-buflocal` autocommands.
---               • NOTE: Cannot be used with {pattern}
---             • group: (string|int) The augroup name or id.
---               • NOTE: If not passed, will only delete autocmds not in any
---                 group.
function vim.api.nvim_clear_autocmds(opts) end

--- Executes an Ex command.
---
--- Unlike `nvim_command()` this command takes a structured Dictionary instead
--- of a String. This allows for easier construction and manipulation of an Ex
--- command. This also allows for things such as having spaces inside a
--- command argument, expanding filenames in a command that otherwise doesn't
--- expand filenames, etc. Command arguments may also be Number, Boolean or
--- String.
---
--- The first argument may also be used instead of count for commands that
--- support it in order to make their usage simpler with `vim.cmd()`. For
--- example, instead of `vim.cmd.bdelete{ count = 2 }`, you may do
--- `vim.cmd.bdelete(2)`.
---
--- On execution error: fails with Vimscript error, updates v:errmsg.
---
--- @param cmd vim.api.keyset.cmd Command to execute. Must be a Dictionary that can contain the
---            same values as the return value of `nvim_parse_cmd()` except
---            "addr", "nargs" and "nextcmd" which are ignored if provided.
---            All values except for "cmd" are optional.
--- @param opts vim.api.keyset.cmd_opts Optional parameters.
---             • output: (boolean, default false) Whether to return command
---               output.
--- @return string
function vim.api.nvim_cmd(cmd, opts) end

--- Executes an Ex command.
---
--- On execution error: fails with Vimscript error, updates v:errmsg.
---
--- Prefer using `nvim_cmd()` or `nvim_exec2()` over this. To evaluate
--- multiple lines of Vim script or an Ex command directly, use
--- `nvim_exec2()`. To construct an Ex command using a structured format and
--- then execute it, use `nvim_cmd()`. To modify an Ex command before
--- evaluating it, use `nvim_parse_cmd()` in conjunction with `nvim_cmd()`.
---
--- @param command string Ex command string
function vim.api.nvim_command(command) end

--- @deprecated
--- @param command string
--- @return string
function vim.api.nvim_command_output(command) end

--- Create or get an autocommand group `autocmd-groups`.
---
--- To get an existing group id, do:
---
--- ```lua
---     local id = vim.api.nvim_create_augroup("MyGroup", {
---         clear = false
---     })
--- ```
---
---
--- @param name string String: The name of the group
--- @param opts vim.api.keyset.create_augroup Dictionary Parameters
---             • clear (bool) optional: defaults to true. Clear existing
---               commands if the group already exists `autocmd-groups`.
--- @return integer
function vim.api.nvim_create_augroup(name, opts) end

--- Creates an `autocommand` event handler, defined by `callback` (Lua
--- function or Vimscript function name string) or `command` (Ex command
--- string).
---
--- Example using Lua callback:
---
--- ```lua
---     vim.api.nvim_create_autocmd({"BufEnter", "BufWinEnter"}, {
---       pattern = {"*.c", "*.h"},
---       callback = function(ev)
---         print(string.format('event fired: %s', vim.inspect(ev)))
---       end
---     })
--- ```
---
--- Example using an Ex command as the handler:
---
--- ```lua
---     vim.api.nvim_create_autocmd({"BufEnter", "BufWinEnter"}, {
---       pattern = {"*.c", "*.h"},
---       command = "echo 'Entering a C or C++ file'",
---     })
--- ```
---
--- Note: `pattern` is NOT automatically expanded (unlike with `:autocmd`),
--- thus names like "$HOME" and "~" must be expanded explicitly:
---
--- ```lua
---     pattern = vim.fn.expand("~") .. "/some/path/*.py"
--- ```
---
---
--- @param event any (string|array) Event(s) that will trigger the handler
---              (`callback` or `command`).
--- @param opts vim.api.keyset.create_autocmd Options dict:
---             • group (string|integer) optional: autocommand group name or
---               id to match against.
---             • pattern (string|array) optional: pattern(s) to match
---               literally `autocmd-pattern`.
---             • buffer (integer) optional: buffer number for buffer-local
---               autocommands `autocmd-buflocal`. Cannot be used with
---               {pattern}.
---             • desc (string) optional: description (for documentation and
---               troubleshooting).
---             • callback (function|string) optional: Lua function (or
---               Vimscript function name, if string) called when the event(s)
---               is triggered. Lua callback can return a truthy value (not
---               `false` or `nil`) to delete the autocommand. Receives one
---               argument, a table with these keys:              *event-args*
---               • id: (number) autocommand id
---               • event: (string) name of the triggered event
---                 `autocmd-events`
---               • group: (number|nil) autocommand group id, if any
---               • file: (string) <afile> (not expanded to a full path)
---               • match: (string) <amatch> (expanded to a full path)
---               • buf: (number) <abuf>
---               • data: (any) arbitrary data passed from
---                 `nvim_exec_autocmds()`                        *event-data*
---             • command (string) optional: Vim command to execute on event.
---               Cannot be used with {callback}
---             • once (boolean) optional: defaults to false. Run the
---               autocommand only once `autocmd-once`.
---             • nested (boolean) optional: defaults to false. Run nested
---               autocommands `autocmd-nested`.
--- @return integer
function vim.api.nvim_create_autocmd(event, opts) end

--- Creates a new, empty, unnamed buffer.
---
--- @param listed boolean Sets 'buflisted'
--- @param scratch boolean Creates a "throwaway" `scratch-buffer` for temporary work
---                (always 'nomodified'). Also sets 'nomodeline' on the
---                buffer.
--- @return integer
function vim.api.nvim_create_buf(listed, scratch) end

--- Creates a new namespace or gets an existing one.               *namespace*
---
--- Namespaces are used for buffer highlights and virtual text, see
--- `nvim_buf_add_highlight()` and `nvim_buf_set_extmark()`.
---
--- Namespaces can be named or anonymous. If `name` matches an existing
--- namespace, the associated id is returned. If `name` is an empty string a
--- new, anonymous namespace is created.
---
--- @param name string Namespace name or empty string
--- @return integer
function vim.api.nvim_create_namespace(name) end

--- Creates a global `user-commands` command.
---
--- For Lua usage see `lua-guide-commands-create`.
---
--- Example:
---
--- ```vim
---     :call nvim_create_user_command('SayHello', 'echo "Hello world!"', {'bang': v:true})
---     :SayHello
---     Hello world!
--- ```
---
---
--- @param name string Name of the new user command. Must begin with an uppercase
---             letter.
--- @param command any Replacement command to execute when this user command is
---                executed. When called from Lua, the command can also be a
---                Lua function. The function is called with a single table
---                argument that contains the following keys:
---                • name: (string) Command name
---                • args: (string) The args passed to the command, if any
---                  <args>
---                • fargs: (table) The args split by unescaped whitespace
---                  (when more than one argument is allowed), if any <f-args>
---                • nargs: (string) Number of arguments `:command-nargs`
---                • bang: (boolean) "true" if the command was executed with a
---                  ! modifier <bang>
---                • line1: (number) The starting line of the command range
---                  <line1>
---                • line2: (number) The final line of the command range
---                  <line2>
---                • range: (number) The number of items in the command range:
---                  0, 1, or 2 <range>
---                • count: (number) Any count supplied <count>
---                • reg: (string) The optional register, if specified <reg>
---                • mods: (string) Command modifiers, if any <mods>
---                • smods: (table) Command modifiers in a structured format.
---                  Has the same structure as the "mods" key of
---                  `nvim_parse_cmd()`.
--- @param opts vim.api.keyset.user_command Optional `command-attributes`.
---             • Set boolean attributes such as `:command-bang` or
---               `:command-bar` to true (but not `:command-buffer`, use
---               `nvim_buf_create_user_command()` instead).
---             • "complete" `:command-complete` also accepts a Lua function
---               which works like `:command-completion-customlist`.
---             • Other parameters:
---               • desc: (string) Used for listing the command when a Lua
---                 function is used for {command}.
---               • force: (boolean, default true) Override any previous
---                 definition.
---               • preview: (function) Preview callback for 'inccommand'
---                 `:command-preview`
function vim.api.nvim_create_user_command(name, command, opts) end

--- Delete an autocommand group by id.
---
--- To get a group id one can use `nvim_get_autocmds()`.
---
--- NOTE: behavior differs from `:augroup-delete`. When deleting a group,
--- autocommands contained in this group will also be deleted and cleared.
--- This group will no longer exist.
---
--- @param id integer Integer The id of the group.
function vim.api.nvim_del_augroup_by_id(id) end

--- Delete an autocommand group by name.
---
--- NOTE: behavior differs from `:augroup-delete`. When deleting a group,
--- autocommands contained in this group will also be deleted and cleared.
--- This group will no longer exist.
---
--- @param name string String The name of the group.
function vim.api.nvim_del_augroup_by_name(name) end

--- Deletes an autocommand by id.
---
--- @param id integer Integer Autocommand id returned by `nvim_create_autocmd()`
function vim.api.nvim_del_autocmd(id) end

--- Deletes the current line.
---
function vim.api.nvim_del_current_line() end

--- Unmaps a global `mapping` for the given mode.
---
--- To unmap a buffer-local mapping, use `nvim_buf_del_keymap()`.
---
--- @param mode string
--- @param lhs string
function vim.api.nvim_del_keymap(mode, lhs) end

--- Deletes an uppercase/file named mark. See `mark-motions`.
---
--- @param name string Mark name
--- @return boolean
function vim.api.nvim_del_mark(name) end

--- Delete a user-defined command.
---
--- @param name string Name of the command to delete.
function vim.api.nvim_del_user_command(name) end

--- Removes a global (g:) variable.
---
--- @param name string Variable name
function vim.api.nvim_del_var(name) end

--- Echo a message.
---
--- @param chunks any[] A list of `[text, hl_group]` arrays, each representing a
---               text chunk with specified highlight. `hl_group` element can
---               be omitted for no highlight.
--- @param history boolean if true, add to `message-history`.
--- @param opts vim.api.keyset.echo_opts Optional parameters.
---             • verbose: Message was printed as a result of 'verbose' option
---               if Nvim was invoked with -V3log_file, the message will be
---               redirected to the log_file and suppressed from direct
---               output.
function vim.api.nvim_echo(chunks, history, opts) end

--- Writes a message to the Vim error buffer. Does not append "\n", the
--- message is buffered (won't display) until a linefeed is written.
---
--- @param str string Message
function vim.api.nvim_err_write(str) end

--- Writes a message to the Vim error buffer. Appends "\n", so the buffer is
--- flushed (and displayed).
---
--- @param str string Message
function vim.api.nvim_err_writeln(str) end

--- Evaluates a Vimscript `expression`. Dictionaries and Lists are recursively
--- expanded.
---
--- On execution error: fails with Vimscript error, updates v:errmsg.
---
--- @param expr string Vimscript expression string
--- @return any
function vim.api.nvim_eval(expr) end

--- Evaluates statusline string.
---
--- @param str string Statusline string (see 'statusline').
--- @param opts vim.api.keyset.eval_statusline Optional parameters.
---             • winid: (number) `window-ID` of the window to use as context
---               for statusline.
---             • maxwidth: (number) Maximum width of statusline.
---             • fillchar: (string) Character to fill blank spaces in the
---               statusline (see 'fillchars'). Treated as single-width even
---               if it isn't.
---             • highlights: (boolean) Return highlight information.
---             • use_winbar: (boolean) Evaluate winbar instead of statusline.
---             • use_tabline: (boolean) Evaluate tabline instead of
---               statusline. When true, {winid} is ignored. Mutually
---               exclusive with {use_winbar}.
---             • use_statuscol_lnum: (number) Evaluate statuscolumn for this
---               line number instead of statusline.
--- @return table<string,any>
function vim.api.nvim_eval_statusline(str, opts) end

--- @deprecated
--- @param src string
--- @param output boolean
--- @return string
function vim.api.nvim_exec(src, output) end

--- Executes Vimscript (multiline block of Ex commands), like anonymous
--- `:source`.
---
--- Unlike `nvim_command()` this function supports heredocs, script-scope
--- (s:), etc.
---
--- On execution error: fails with Vimscript error, updates v:errmsg.
---
--- @param src string Vimscript code
--- @param opts vim.api.keyset.exec_opts Optional parameters.
---             • output: (boolean, default false) Whether to capture and
---               return all (non-error, non-shell `:!`) output.
--- @return table<string,any>
function vim.api.nvim_exec2(src, opts) end

--- Execute all autocommands for {event} that match the corresponding {opts}
--- `autocmd-execute`.
---
--- @param event any (String|Array) The event or events to execute
--- @param opts vim.api.keyset.exec_autocmds Dictionary of autocommand options:
---             • group (string|integer) optional: the autocommand group name
---               or id to match against. `autocmd-groups`.
---             • pattern (string|array) optional: defaults to "*"
---               `autocmd-pattern`. Cannot be used with {buffer}.
---             • buffer (integer) optional: buffer number `autocmd-buflocal`.
---               Cannot be used with {pattern}.
---             • modeline (bool) optional: defaults to true. Process the
---               modeline after the autocommands <nomodeline>.
---             • data (any): arbitrary data to send to the autocommand
---               callback. See `nvim_create_autocmd()` for details.
function vim.api.nvim_exec_autocmds(event, opts) end

--- Sends input-keys to Nvim, subject to various quirks controlled by `mode`
--- flags. This is a blocking call, unlike `nvim_input()`.
---
--- On execution error: does not fail, but updates v:errmsg.
---
--- To input sequences like <C-o> use `nvim_replace_termcodes()` (typically
--- with escape_ks=false) to replace `keycodes`, then pass the result to
--- nvim_feedkeys().
---
--- Example:
---
--- ```vim
---     :let key = nvim_replace_termcodes("<C-o>", v:true, v:false, v:true)
---     :call nvim_feedkeys(key, 'n', v:false)
--- ```
---
---
--- @param keys string to be typed
--- @param mode string behavior flags, see `feedkeys()`
--- @param escape_ks boolean If true, escape K_SPECIAL bytes in `keys`. This should be
---                  false if you already used `nvim_replace_termcodes()`, and
---                  true otherwise.
function vim.api.nvim_feedkeys(keys, mode, escape_ks) end

--- Gets the option information for all options.
---
--- The dictionary has the full option names as keys and option metadata
--- dictionaries as detailed at `nvim_get_option_info2()`.
---
--- @return table<string,any>
function vim.api.nvim_get_all_options_info() end

--- Get all autocommands that match the corresponding {opts}.
---
--- These examples will get autocommands matching ALL the given criteria:
---
--- ```lua
---     -- Matches all criteria
---     autocommands = vim.api.nvim_get_autocmds({
---       group = "MyGroup",
---       event = {"BufEnter", "BufWinEnter"},
---       pattern = {"*.c", "*.h"}
---     })
---
---     -- All commands from one group
---     autocommands = vim.api.nvim_get_autocmds({
---       group = "MyGroup",
---     })
--- ```
---
--- NOTE: When multiple patterns or events are provided, it will find all the
--- autocommands that match any combination of them.
---
--- @param opts vim.api.keyset.get_autocmds Dictionary with at least one of the following:
---             • group (string|integer): the autocommand group name or id to
---               match against.
---             • event (string|array): event or events to match against
---               `autocmd-events`.
---             • pattern (string|array): pattern or patterns to match against
---               `autocmd-pattern`. Cannot be used with {buffer}
---             • buffer: Buffer number or list of buffer numbers for buffer
---               local autocommands `autocmd-buflocal`. Cannot be used with
---               {pattern}
--- @return vim.api.keyset.get_autocmds.ret[]
function vim.api.nvim_get_autocmds(opts) end

--- Gets information about a channel.
---
--- @param chan integer channel_id, or 0 for current channel
--- @return table<string,any>
function vim.api.nvim_get_chan_info(chan) end

--- Returns the 24-bit RGB value of a `nvim_get_color_map()` color name or
--- "#rrggbb" hexadecimal string.
---
--- Example:
---
--- ```vim
---     :echo nvim_get_color_by_name("Pink")
---     :echo nvim_get_color_by_name("#cbcbcb")
--- ```
---
---
--- @param name string Color name or "#rrggbb" string
--- @return integer
function vim.api.nvim_get_color_by_name(name) end

--- Returns a map of color names and RGB values.
---
--- Keys are color names (e.g. "Aqua") and values are 24-bit RGB color values
--- (e.g. 65535).
---
--- @return table<string,integer>
function vim.api.nvim_get_color_map() end

--- Gets a map of global (non-buffer-local) Ex commands.
---
--- Currently only `user-commands` are supported, not builtin Ex commands.
---
--- @param opts vim.api.keyset.get_commands Optional parameters. Currently only supports {"builtin":false}
--- @return table<string,any>
function vim.api.nvim_get_commands(opts) end

--- Gets a map of the current editor state.
---
--- @param opts vim.api.keyset.context Optional parameters.
---             • types: List of `context-types` ("regs", "jumps", "bufs",
---               "gvars", …) to gather, or empty for "all".
--- @return table<string,any>
function vim.api.nvim_get_context(opts) end

--- Gets the current buffer.
---
--- @return integer
function vim.api.nvim_get_current_buf() end

--- Gets the current line.
---
--- @return string
function vim.api.nvim_get_current_line() end

--- Gets the current tabpage.
---
--- @return integer
function vim.api.nvim_get_current_tabpage() end

--- Gets the current window.
---
--- @return integer
function vim.api.nvim_get_current_win() end

--- Gets all or specific highlight groups in a namespace.
---
--- @param ns_id integer Get highlight groups for namespace ns_id
---              `nvim_get_namespaces()`. Use 0 to get global highlight groups
---              `:highlight`.
--- @param opts vim.api.keyset.get_highlight Options dict:
---             • name: (string) Get a highlight definition by name.
---             • id: (integer) Get a highlight definition by id.
---             • link: (boolean, default true) Show linked group name instead
---               of effective definition `:hi-link`.
---             • create: (boolean, default true) When highlight group doesn't
---               exist create it.
--- @return vim.api.keyset.hl_info
function vim.api.nvim_get_hl(ns_id, opts) end

--- @deprecated
--- @param hl_id integer
--- @param rgb boolean
--- @return table<string,any>
function vim.api.nvim_get_hl_by_id(hl_id, rgb) end

--- @deprecated
--- @param name string
--- @param rgb boolean
--- @return table<string,any>
function vim.api.nvim_get_hl_by_name(name, rgb) end

--- Gets a highlight group by name
---
--- similar to `hlID()`, but allocates a new ID if not present.
---
--- @param name string
--- @return integer
function vim.api.nvim_get_hl_id_by_name(name) end

--- Gets the active highlight namespace.
---
--- @param opts vim.api.keyset.get_ns Optional parameters
---             • winid: (number) `window-ID` for retrieving a window's
---               highlight namespace. A value of -1 is returned when
---               `nvim_win_set_hl_ns()` has not been called for the window
---               (or was called with a namespace of -1).
--- @return integer
function vim.api.nvim_get_hl_ns(opts) end

--- Gets a list of global (non-buffer-local) `mapping` definitions.
---
--- @param mode string Mode short-name ("n", "i", "v", ...)
--- @return vim.api.keyset.keymap[]
function vim.api.nvim_get_keymap(mode) end

--- Returns a `(row, col, buffer, buffername)` tuple representing the position
--- of the uppercase/file named mark. "End of line" column position is
--- returned as `v:maxcol` (big number). See `mark-motions`.
---
--- Marks are (1,0)-indexed. `api-indexing`
---
--- @param name string Mark name
--- @param opts vim.api.keyset.empty Optional parameters. Reserved for future use.
--- @return vim.api.keyset.get_mark
function vim.api.nvim_get_mark(name, opts) end

--- Gets the current mode. `mode()` "blocking" is true if Nvim is waiting for
--- input.
---
--- @return vim.api.keyset.get_mode
function vim.api.nvim_get_mode() end

--- Gets existing, non-anonymous `namespace`s.
---
--- @return table<string,integer>
function vim.api.nvim_get_namespaces() end

--- @deprecated
--- @param name string
--- @return any
function vim.api.nvim_get_option(name) end

--- @deprecated
--- @param name string
--- @return vim.api.keyset.get_option_info
function vim.api.nvim_get_option_info(name) end

--- Gets the option information for one option from arbitrary buffer or window
---
--- Resulting dictionary has keys:
--- • name: Name of the option (like 'filetype')
--- • shortname: Shortened name of the option (like 'ft')
--- • type: type of option ("string", "number" or "boolean")
--- • default: The default value for the option
--- • was_set: Whether the option was set.
--- • last_set_sid: Last set script id (if any)
--- • last_set_linenr: line number where option was set
--- • last_set_chan: Channel where option was set (0 for local)
--- • scope: one of "global", "win", or "buf"
--- • global_local: whether win or buf option has a global value
--- • commalist: List of comma separated values
--- • flaglist: List of single char flags
---
--- When {scope} is not provided, the last set information applies to the
--- local value in the current buffer or window if it is available, otherwise
--- the global value information is returned. This behavior can be disabled by
--- explicitly specifying {scope} in the {opts} table.
---
--- @param name string Option name
--- @param opts vim.api.keyset.option Optional parameters
---             • scope: One of "global" or "local". Analogous to `:setglobal`
---               and `:setlocal`, respectively.
---             • win: `window-ID`. Used for getting window local options.
---             • buf: Buffer number. Used for getting buffer local options.
---               Implies {scope} is "local".
--- @return vim.api.keyset.get_option_info
function vim.api.nvim_get_option_info2(name, opts) end

--- Gets the value of an option. The behavior of this function matches that of
--- `:set`: the local value of an option is returned if it exists; otherwise,
--- the global value is returned. Local values always correspond to the
--- current buffer or window, unless "buf" or "win" is set in {opts}.
---
--- @param name string Option name
--- @param opts vim.api.keyset.option Optional parameters
---             • scope: One of "global" or "local". Analogous to `:setglobal`
---               and `:setlocal`, respectively.
---             • win: `window-ID`. Used for getting window local options.
---             • buf: Buffer number. Used for getting buffer local options.
---               Implies {scope} is "local".
---             • filetype: `filetype`. Used to get the default option for a
---               specific filetype. Cannot be used with any other option.
---               Note: this will trigger `ftplugin` and all `FileType`
---               autocommands for the corresponding filetype.
--- @return any
function vim.api.nvim_get_option_value(name, opts) end

--- Gets info describing process `pid`.
---
--- @param pid integer
--- @return any
function vim.api.nvim_get_proc(pid) end

--- Gets the immediate children of process `pid`.
---
--- @param pid integer
--- @return any[]
function vim.api.nvim_get_proc_children(pid) end

--- Find files in runtime directories
---
--- "name" can contain wildcards. For example
--- nvim_get_runtime_file("colors/*.vim", true) will return all color scheme
--- files. Always use forward slashes (/) in the search pattern for
--- subdirectories regardless of platform.
---
--- It is not an error to not find any files. An empty array is returned then.
---
--- @param name string pattern of files to search for
--- @param all boolean whether to return all matches or only the first
--- @return string[]
function vim.api.nvim_get_runtime_file(name, all) end

--- Gets a global (g:) variable.
---
--- @param name string Variable name
--- @return any
function vim.api.nvim_get_var(name) end

--- Gets a v: variable.
---
--- @param name string Variable name
--- @return any
function vim.api.nvim_get_vvar(name) end

--- Queues raw user-input. Unlike `nvim_feedkeys()`, this uses a low-level
--- input buffer and the call is non-blocking (input is processed
--- asynchronously by the eventloop).
---
--- On execution error: does not fail, but updates v:errmsg.
---
--- @param keys string to be typed
--- @return integer
function vim.api.nvim_input(keys) end

--- Send mouse event from GUI.
---
--- Non-blocking: does not wait on any result, but queues the event to be
--- processed soon by the event loop.
---
--- @param button string Mouse button: one of "left", "right", "middle", "wheel",
---               "move", "x1", "x2".
--- @param action string For ordinary buttons, one of "press", "drag", "release". For
---               the wheel, one of "up", "down", "left", "right". Ignored for
---               "move".
--- @param modifier string String of modifiers each represented by a single char. The
---                 same specifiers are used as for a key press, except that
---                 the "-" separator is optional, so "C-A-", "c-a" and "CA"
---                 can all be used to specify Ctrl+Alt+click.
--- @param grid integer Grid number if the client uses `ui-multigrid`, else 0.
--- @param row integer Mouse row-position (zero-based, like redraw events)
--- @param col integer Mouse column-position (zero-based, like redraw events)
function vim.api.nvim_input_mouse(button, action, modifier, grid, row, col) end

--- Gets the current list of buffer handles
---
--- Includes unlisted (unloaded/deleted) buffers, like `:ls!`. Use
--- `nvim_buf_is_loaded()` to check if a buffer is loaded.
---
--- @return integer[]
function vim.api.nvim_list_bufs() end

--- Get information about all open channels.
---
--- @return any[]
function vim.api.nvim_list_chans() end

--- Gets the paths contained in `runtime-search-path`.
---
--- @return string[]
function vim.api.nvim_list_runtime_paths() end

--- Gets the current list of tabpage handles.
---
--- @return integer[]
function vim.api.nvim_list_tabpages() end

--- Gets a list of dictionaries representing attached UIs.
---
--- @return any[]
function vim.api.nvim_list_uis() end

--- Gets the current list of window handles.
---
--- @return integer[]
function vim.api.nvim_list_wins() end

--- Sets the current editor state from the given `context` map.
---
--- @param dict table<string,any> `Context` map.
--- @return any
function vim.api.nvim_load_context(dict) end

--- Notify the user with a message
---
--- Relays the call to vim.notify . By default forwards your message in the
--- echo area but can be overridden to trigger desktop notifications.
---
--- @param msg string Message to display to the user
--- @param log_level integer The log level
--- @param opts table<string,any> Reserved for future use.
--- @return any
function vim.api.nvim_notify(msg, log_level, opts) end

--- Open a terminal instance in a buffer
---
--- By default (and currently the only option) the terminal will not be
--- connected to an external process. Instead, input send on the channel will
--- be echoed directly by the terminal. This is useful to display ANSI
--- terminal sequences returned as part of a rpc message, or similar.
---
--- Note: to directly initiate the terminal using the right size, display the
--- buffer in a configured window before calling this. For instance, for a
--- floating display, first create an empty buffer using `nvim_create_buf()`,
--- then display it using `nvim_open_win()`, and then call this function. Then
--- `nvim_chan_send()` can be called immediately to process sequences in a
--- virtual terminal having the intended size.
---
--- @param buffer integer the buffer to use (expected to be empty)
--- @param opts vim.api.keyset.open_term Optional parameters.
---             • on_input: Lua callback for input sent, i e keypresses in
---               terminal mode. Note: keypresses are sent raw as they would
---               be to the pty master end. For instance, a carriage return is
---               sent as a "\r", not as a "\n". `textlock` applies. It is
---               possible to call `nvim_chan_send()` directly in the callback
---               however. `["input", term, bufnr, data]`
---             • force_crlf: (boolean, default true) Convert "\n" to "\r\n".
--- @return integer
function vim.api.nvim_open_term(buffer, opts) end

--- Opens a new split window, or a floating window if `relative` is specified,
--- or an external window (managed by the UI) if `external` is specified.
---
--- Floats are windows that are drawn above the split layout, at some anchor
--- position in some other window. Floats can be drawn internally or by
--- external GUI with the `ui-multigrid` extension. External windows are only
--- supported with multigrid GUIs, and are displayed as separate top-level
--- windows.
---
--- For a general overview of floats, see `api-floatwin`.
---
--- The `width` and `height` of the new window must be specified when opening
--- a floating window, but are optional for normal windows.
---
--- If `relative` and `external` are omitted, a normal "split" window is
--- created. The `win` property determines which window will be split. If no
--- `win` is provided or `win == 0`, a window will be created adjacent to the
--- current window. If -1 is provided, a top-level split will be created.
--- `vertical` and `split` are only valid for normal windows, and are used to
--- control split direction. For `vertical`, the exact direction is determined
--- by `'splitright'` and `'splitbelow'`. Split windows cannot have
--- `bufpos`/`row`/`col`/`border`/`title`/`footer` properties.
---
--- With relative=editor (row=0,col=0) refers to the top-left corner of the
--- screen-grid and (row=Lines-1,col=Columns-1) refers to the bottom-right
--- corner. Fractional values are allowed, but the builtin implementation
--- (used by non-multigrid UIs) will always round down to nearest integer.
---
--- Out-of-bounds values, and configurations that make the float not fit
--- inside the main editor, are allowed. The builtin implementation truncates
--- values so floats are fully within the main screen grid. External GUIs
--- could let floats hover outside of the main window like a tooltip, but this
--- should not be used to specify arbitrary WM screen positions.
---
--- Example (Lua): window-relative float
---
--- ```lua
---     vim.api.nvim_open_win(0, false,
---       {relative='win', row=3, col=3, width=12, height=3})
--- ```
---
--- Example (Lua): buffer-relative float (travels as buffer is scrolled)
---
--- ```lua
---     vim.api.nvim_open_win(0, false,
---       {relative='win', width=12, height=3, bufpos={100,10}})
--- ```
---
--- Example (Lua): vertical split left of the current window
---
--- ```lua
---     vim.api.nvim_open_win(0, false, {
---       split = 'left',
---       win = 0
---     })
--- ```
---
---
--- @param buffer integer Buffer to display, or 0 for current buffer
--- @param enter boolean Enter the window (make it the current window)
--- @param config vim.api.keyset.win_config Map defining the window configuration. Keys:
---               • relative: Sets the window layout to "floating", placed at
---                 (row,col) coordinates relative to:
---                 • "editor" The global editor grid
---                 • "win" Window given by the `win` field, or current
---                   window.
---                 • "cursor" Cursor position in current window.
---                 • "mouse" Mouse position
---               • win: `window-ID` window to split, or relative window when
---                 creating a float (relative="win").
---               • anchor: Decides which corner of the float to place at
---                 (row,col):
---                 • "NW" northwest (default)
---                 • "NE" northeast
---                 • "SW" southwest
---                 • "SE" southeast
---               • width: Window width (in character cells). Minimum of 1.
---               • height: Window height (in character cells). Minimum of 1.
---               • bufpos: Places float relative to buffer text (only when
---                 relative="win"). Takes a tuple of zero-indexed
---                 `[line, column]`. `row` and `col` if given are applied
---                 relative to this position, else they default to:
---                 • `row=1` and `col=0` if `anchor` is "NW" or "NE"
---                 • `row=0` and `col=0` if `anchor` is "SW" or "SE" (thus
---                   like a tooltip near the buffer text).
---               • row: Row position in units of "screen cell height", may be
---                 fractional.
---               • col: Column position in units of "screen cell width", may
---                 be fractional.
---               • focusable: Enable focus by user actions (wincmds, mouse
---                 events). Defaults to true. Non-focusable windows can be
---                 entered by `nvim_set_current_win()`.
---               • external: GUI should display the window as an external
---                 top-level window. Currently accepts no other positioning
---                 configuration together with this.
---               • zindex: Stacking order. floats with higher `zindex` go on
---                 top on floats with lower indices. Must be larger than
---                 zero. The following screen elements have hard-coded
---                 z-indices:
---                 • 100: insert completion popupmenu
---                 • 200: message scrollback
---                 • 250: cmdline completion popupmenu (when
---                   wildoptions+=pum) The default value for floats are 50.
---                   In general, values below 100 are recommended, unless
---                   there is a good reason to overshadow builtin elements.
---               • style: (optional) Configure the appearance of the window.
---                 Currently only supports one value:
---                 • "minimal" Nvim will display the window with many UI
---                   options disabled. This is useful when displaying a
---                   temporary float where the text should not be edited.
---                   Disables 'number', 'relativenumber', 'cursorline',
---                   'cursorcolumn', 'foldcolumn', 'spell' and 'list'
---                   options. 'signcolumn' is changed to `auto` and
---                   'colorcolumn' is cleared. 'statuscolumn' is changed to
---                   empty. The end-of-buffer region is hidden by setting
---                   `eob` flag of 'fillchars' to a space char, and clearing
---                   the `hl-EndOfBuffer` region in 'winhighlight'.
---               • border: Style of (optional) window border. This can either
---                 be a string or an array. The string values are
---                 • "none": No border (default).
---                 • "single": A single line box.
---                 • "double": A double line box.
---                 • "rounded": Like "single", but with rounded corners
---                   ("╭" etc.).
---                 • "solid": Adds padding by a single whitespace cell.
---                 • "shadow": A drop shadow effect by blending with the
---                   background.
---                 • If it is an array, it should have a length of eight or
---                   any divisor of eight. The array will specify the eight
---                   chars building up the border in a clockwise fashion
---                   starting with the top-left corner. As an example, the
---                   double box style could be specified as:
--- ```
---                   [ "╔", "═" ,"╗", "║", "╝", "═", "╚", "║" ].
--- ```
---
---                   If the number of chars are less than eight, they will be
---                   repeated. Thus an ASCII border could be specified as
--- ```
---                   [ "/", "-", \"\\\\\", "|" ],
--- ```
---
---                   or all chars the same as
--- ```
---                   [ "x" ].
--- ```
---
---                 An empty string can be used to turn off a specific border,
---                 for instance,
--- ```
---                  [ "", "", "", ">", "", "", "", "<" ]
--- ```
---
---                 will only make vertical borders but not horizontal ones.
---                 By default, `FloatBorder` highlight is used, which links
---                 to `WinSeparator` when not defined. It could also be
---                 specified by character:
--- ```
---                  [ ["+", "MyCorner"], ["x", "MyBorder"] ].
--- ```
---
---               • title: Title (optional) in window border, string or list.
---                 List should consist of `[text, highlight]` tuples. If
---                 string, the default highlight group is `FloatTitle`.
---               • title_pos: Title position. Must be set with `title`
---                 option. Value can be one of "left", "center", or "right".
---                 Default is `"left"`.
---               • footer: Footer (optional) in window border, string or
---                 list. List should consist of `[text, highlight]` tuples.
---                 If string, the default highlight group is `FloatFooter`.
---               • footer_pos: Footer position. Must be set with `footer`
---                 option. Value can be one of "left", "center", or "right".
---                 Default is `"left"`.
---               • noautocmd: If true then all autocommands are blocked for
---                 the duration of the call.
---               • fixed: If true when anchor is NW or SW, the float window
---                 would be kept fixed even if the window would be truncated.
---               • hide: If true the floating window will be hidden.
---               • vertical: Split vertically `:vertical`.
---               • split: Split direction: "left", "right", "above", "below".
--- @return integer
function vim.api.nvim_open_win(buffer, enter, config) end

--- Writes a message to the Vim output buffer. Does not append "\n", the
--- message is buffered (won't display) until a linefeed is written.
---
--- @param str string Message
function vim.api.nvim_out_write(str) end

--- Parse command line.
---
--- Doesn't check the validity of command arguments.
---
--- @param str string Command line string to parse. Cannot contain "\n".
--- @param opts vim.api.keyset.empty Optional parameters. Reserved for future use.
--- @return vim.api.keyset.parse_cmd
function vim.api.nvim_parse_cmd(str, opts) end

--- Parse a Vimscript expression.
---
--- @param expr string Expression to parse. Always treated as a single line.
--- @param flags string Flags:
---              • "m" if multiple expressions in a row are allowed (only the
---                first one will be parsed),
---              • "E" if EOC tokens are not allowed (determines whether they
---                will stop parsing process or be recognized as an
---                operator/space, though also yielding an error).
---              • "l" when needing to start parsing with lvalues for ":let"
---                or ":for". Common flag sets:
---              • "m" to parse like for `":echo"`.
---              • "E" to parse like for `"<C-r>="`.
---              • empty string for ":call".
---              • "lm" to parse for ":let".
--- @param highlight boolean If true, return value will also include "highlight" key
---                  containing array of 4-tuples (arrays) (Integer, Integer,
---                  Integer, String), where first three numbers define the
---                  highlighted region and represent line, starting column
---                  and ending column (latter exclusive: one should highlight
---                  region [start_col, end_col)).
--- @return table<string,any>
function vim.api.nvim_parse_expression(expr, flags, highlight) end

--- Pastes at cursor, in any mode.
---
--- Invokes the `vim.paste` handler, which handles each mode appropriately.
--- Sets redo/undo. Faster than `nvim_input()`. Lines break at LF ("\n").
---
--- Errors ('nomodifiable', `vim.paste()` failure, …) are reflected in `err`
--- but do not affect the return value (which is strictly decided by
--- `vim.paste()`). On error, subsequent calls are ignored ("drained") until
--- the next paste is initiated (phase 1 or -1).
---
--- @param data string Multiline input. May be binary (containing NUL bytes).
--- @param crlf boolean Also break lines at CR and CRLF.
--- @param phase integer -1: paste in a single call (i.e. without streaming). To
---              "stream" a paste, call `nvim_paste` sequentially with these
---              `phase` values:
---              • 1: starts the paste (exactly once)
---              • 2: continues the paste (zero or more times)
---              • 3: ends the paste (exactly once)
--- @return boolean
function vim.api.nvim_paste(data, crlf, phase) end

--- Puts text at cursor, in any mode.
---
--- Compare `:put` and `p` which are always linewise.
---
--- @param lines string[] `readfile()`-style list of lines. `channel-lines`
--- @param type string Edit behavior: any `getregtype()` result, or:
---             • "b" `blockwise-visual` mode (may include width, e.g. "b3")
---             • "c" `charwise` mode
---             • "l" `linewise` mode
---             • "" guess by contents, see `setreg()`
--- @param after boolean If true insert after cursor (like `p`), or before (like `P`).
--- @param follow boolean If true place cursor at end of inserted text.
function vim.api.nvim_put(lines, type, after, follow) end

--- Replaces terminal codes and `keycodes` (<CR>, <Esc>, ...) in a string with
--- the internal representation.
---
--- @param str string String to be converted.
--- @param from_part boolean Legacy Vim parameter. Usually true.
--- @param do_lt boolean Also translate <lt>. Ignored if `special` is false.
--- @param special boolean Replace `keycodes`, e.g. <CR> becomes a "\r" char.
--- @return string
function vim.api.nvim_replace_termcodes(str, from_part, do_lt, special) end

--- Selects an item in the completion popup menu.
---
--- If neither `ins-completion` nor `cmdline-completion` popup menu is active
--- this API call is silently ignored. Useful for an external UI using
--- `ui-popupmenu` to control the popup menu with the mouse. Can also be used
--- in a mapping; use <Cmd> `:map-cmd` or a Lua mapping to ensure the mapping
--- doesn't end completion mode.
---
--- @param item integer Index (zero-based) of the item to select. Value of -1 selects
---             nothing and restores the original text.
--- @param insert boolean For `ins-completion`, whether the selection should be
---               inserted in the buffer. Ignored for `cmdline-completion`.
--- @param finish boolean Finish the completion and dismiss the popup menu. Implies
---               {insert}.
--- @param opts vim.api.keyset.empty Optional parameters. Reserved for future use.
function vim.api.nvim_select_popupmenu_item(item, insert, finish, opts) end

--- Sets the current buffer.
---
--- @param buffer integer Buffer handle
function vim.api.nvim_set_current_buf(buffer) end

--- Changes the global working directory.
---
--- @param dir string Directory path
function vim.api.nvim_set_current_dir(dir) end

--- Sets the current line.
---
--- @param line string Line contents
function vim.api.nvim_set_current_line(line) end

--- Sets the current tabpage.
---
--- @param tabpage integer Tabpage handle
function vim.api.nvim_set_current_tabpage(tabpage) end

--- Sets the current window.
---
--- @param window integer Window handle
function vim.api.nvim_set_current_win(window) end

--- Set or change decoration provider for a `namespace`
---
--- This is a very general purpose interface for having Lua callbacks being
--- triggered during the redraw code.
---
--- The expected usage is to set `extmarks` for the currently redrawn buffer.
--- `nvim_buf_set_extmark()` can be called to add marks on a per-window or
--- per-lines basis. Use the `ephemeral` key to only use the mark for the
--- current screen redraw (the callback will be called again for the next
--- redraw).
---
--- Note: this function should not be called often. Rather, the callbacks
--- themselves can be used to throttle unneeded callbacks. the `on_start`
--- callback can return `false` to disable the provider until the next redraw.
--- Similarly, return `false` in `on_win` will skip the `on_line` calls for
--- that window (but any extmarks set in `on_win` will still be used). A
--- plugin managing multiple sources of decoration should ideally only set one
--- provider, and merge the sources internally. You can use multiple `ns_id`
--- for the extmarks set/modified inside the callback anyway.
---
--- Note: doing anything other than setting extmarks is considered
--- experimental. Doing things like changing options are not explicitly
--- forbidden, but is likely to have unexpected consequences (such as 100% CPU
--- consumption). Doing `vim.rpcnotify` should be OK, but `vim.rpcrequest` is
--- quite dubious for the moment.
---
--- Note: It is not allowed to remove or update extmarks in `on_line`
--- callbacks.
---
--- @param ns_id integer Namespace id from `nvim_create_namespace()`
--- @param opts vim.api.keyset.set_decoration_provider Table of callbacks:
---             • on_start: called first on each screen redraw
--- ```
---                ["start", tick]
--- ```
---
---             • on_buf: called for each buffer being redrawn (before window
---               callbacks)
--- ```
---                ["buf", bufnr, tick]
--- ```
---
---             • on_win: called when starting to redraw a specific window.
--- ```
---                ["win", winid, bufnr, topline, botline]
--- ```
---
---             • on_line: called for each buffer line being redrawn. (The
---               interaction with fold lines is subject to change)
--- ```
---                ["line", winid, bufnr, row]
--- ```
---
---             • on_end: called at the end of a redraw cycle
--- ```
---                ["end", tick]
--- ```
function vim.api.nvim_set_decoration_provider(ns_id, opts) end

--- Sets a highlight group.
---
--- @param ns_id integer Namespace id for this highlight `nvim_create_namespace()`.
---              Use 0 to set a highlight group globally `:highlight`.
---              Highlights from non-global namespaces are not active by
---              default, use `nvim_set_hl_ns()` or `nvim_win_set_hl_ns()` to
---              activate them.
--- @param name string Highlight group name, e.g. "ErrorMsg"
--- @param val vim.api.keyset.highlight Highlight definition map, accepts the following keys:
---            • fg: color name or "#RRGGBB", see note.
---            • bg: color name or "#RRGGBB", see note.
---            • sp: color name or "#RRGGBB"
---            • blend: integer between 0 and 100
---            • bold: boolean
---            • standout: boolean
---            • underline: boolean
---            • undercurl: boolean
---            • underdouble: boolean
---            • underdotted: boolean
---            • underdashed: boolean
---            • strikethrough: boolean
---            • italic: boolean
---            • reverse: boolean
---            • nocombine: boolean
---            • link: name of another highlight group to link to, see
---              `:hi-link`.
---            • default: Don't override existing definition `:hi-default`
---            • ctermfg: Sets foreground of cterm color `ctermfg`
---            • ctermbg: Sets background of cterm color `ctermbg`
---            • cterm: cterm attribute map, like `highlight-args`. If not
---              set, cterm attributes will match those from the attribute map
---              documented above.
---            • force: if true force update the highlight group when it
---              exists.
function vim.api.nvim_set_hl(ns_id, name, val) end

--- Set active namespace for highlights defined with `nvim_set_hl()`. This can
--- be set for a single window, see `nvim_win_set_hl_ns()`.
---
--- @param ns_id integer the namespace to use
function vim.api.nvim_set_hl_ns(ns_id) end

--- Set active namespace for highlights defined with `nvim_set_hl()` while
--- redrawing.
---
--- This function meant to be called while redrawing, primarily from
--- `nvim_set_decoration_provider()` on_win and on_line callbacks, which are
--- allowed to change the namespace during a redraw cycle.
---
--- @param ns_id integer the namespace to activate
function vim.api.nvim_set_hl_ns_fast(ns_id) end

--- Sets a global `mapping` for the given mode.
---
--- To set a buffer-local mapping, use `nvim_buf_set_keymap()`.
---
--- Unlike `:map`, leading/trailing whitespace is accepted as part of the
--- {lhs} or {rhs}. Empty {rhs} is <Nop>. `keycodes` are replaced as usual.
---
--- Example:
---
--- ```vim
---     call nvim_set_keymap('n', ' <NL>', '', {'nowait': v:true})
--- ```
---
--- is equivalent to:
---
--- ```vim
---     nmap <nowait> <Space><NL> <Nop>
--- ```
---
---
--- @param mode string Mode short-name (map command prefix: "n", "i", "v", "x", …)
---             or "!" for `:map!`, or empty string for `:map`. "ia", "ca" or
---             "!a" for abbreviation in Insert mode, Cmdline mode, or both,
---             respectively
--- @param lhs string Left-hand-side `{lhs}` of the mapping.
--- @param rhs string Right-hand-side `{rhs}` of the mapping.
--- @param opts vim.api.keyset.keymap Optional parameters map: Accepts all `:map-arguments` as keys
---             except <buffer>, values are booleans (default false). Also:
---             • "noremap" disables `recursive_mapping`, like `:noremap`
---             • "desc" human-readable description.
---             • "callback" Lua function called in place of {rhs}.
---             • "replace_keycodes" (boolean) When "expr" is true, replace
---               keycodes in the resulting string (see
---               `nvim_replace_termcodes()`). Returning nil from the Lua
---               "callback" is equivalent to returning an empty string.
function vim.api.nvim_set_keymap(mode, lhs, rhs, opts) end

--- @deprecated
--- @param name string
--- @param value any
function vim.api.nvim_set_option(name, value) end

--- Sets the value of an option. The behavior of this function matches that of
--- `:set`: for global-local options, both the global and local value are set
--- unless otherwise specified with {scope}.
---
--- Note the options {win} and {buf} cannot be used together.
---
--- @param name string Option name
--- @param value any New option value
--- @param opts vim.api.keyset.option Optional parameters
---             • scope: One of "global" or "local". Analogous to `:setglobal`
---               and `:setlocal`, respectively.
---             • win: `window-ID`. Used for setting window local option.
---             • buf: Buffer number. Used for setting buffer local option.
function vim.api.nvim_set_option_value(name, value, opts) end

--- Sets a global (g:) variable.
---
--- @param name string Variable name
--- @param value any Variable value
function vim.api.nvim_set_var(name, value) end

--- Sets a v: variable, if it is not readonly.
---
--- @param name string Variable name
--- @param value any Variable value
function vim.api.nvim_set_vvar(name, value) end

--- Calculates the number of display cells occupied by `text`. Control
--- characters including <Tab> count as one cell.
---
--- @param text string Some text
--- @return integer
function vim.api.nvim_strwidth(text) end

--- Removes a tab-scoped (t:) variable
---
--- @param tabpage integer Tabpage handle, or 0 for current tabpage
--- @param name string Variable name
function vim.api.nvim_tabpage_del_var(tabpage, name) end

--- Gets the tabpage number
---
--- @param tabpage integer Tabpage handle, or 0 for current tabpage
--- @return integer
function vim.api.nvim_tabpage_get_number(tabpage) end

--- Gets a tab-scoped (t:) variable
---
--- @param tabpage integer Tabpage handle, or 0 for current tabpage
--- @param name string Variable name
--- @return any
function vim.api.nvim_tabpage_get_var(tabpage, name) end

--- Gets the current window in a tabpage
---
--- @param tabpage integer Tabpage handle, or 0 for current tabpage
--- @return integer
function vim.api.nvim_tabpage_get_win(tabpage) end

--- Checks if a tabpage is valid
---
--- @param tabpage integer Tabpage handle, or 0 for current tabpage
--- @return boolean
function vim.api.nvim_tabpage_is_valid(tabpage) end

--- Gets the windows in a tabpage
---
--- @param tabpage integer Tabpage handle, or 0 for current tabpage
--- @return integer[]
function vim.api.nvim_tabpage_list_wins(tabpage) end

--- Sets a tab-scoped (t:) variable
---
--- @param tabpage integer Tabpage handle, or 0 for current tabpage
--- @param name string Variable name
--- @param value any Variable value
function vim.api.nvim_tabpage_set_var(tabpage, name, value) end

--- Sets the current window in a tabpage
---
--- @param tabpage integer Tabpage handle, or 0 for current tabpage
--- @param win integer Window handle, must already belong to {tabpage}
function vim.api.nvim_tabpage_set_win(tabpage, win) end

--- Calls a function with window as temporary current window.
---
--- @param window integer Window handle, or 0 for current window
--- @param fun function Function to call inside the window (currently Lua callable
---            only)
--- @return any
function vim.api.nvim_win_call(window, fun) end

--- Closes the window (like `:close` with a `window-ID`).
---
--- @param window integer Window handle, or 0 for current window
--- @param force boolean Behave like `:close!` The last window of a buffer with
---              unwritten changes can be closed. The buffer will become
---              hidden, even if 'hidden' is not set.
function vim.api.nvim_win_close(window, force) end

--- Removes a window-scoped (w:) variable
---
--- @param window integer Window handle, or 0 for current window
--- @param name string Variable name
function vim.api.nvim_win_del_var(window, name) end

--- Gets the current buffer in a window
---
--- @param window integer Window handle, or 0 for current window
--- @return integer
function vim.api.nvim_win_get_buf(window) end

--- Gets window configuration.
---
--- The returned value may be given to `nvim_open_win()`.
---
--- `relative` is empty for normal windows.
---
--- @param window integer Window handle, or 0 for current window
--- @return vim.api.keyset.win_config
function vim.api.nvim_win_get_config(window) end

--- Gets the (1,0)-indexed, buffer-relative cursor position for a given window
--- (different windows showing the same buffer have independent cursor
--- positions). `api-indexing`
---
--- @param window integer Window handle, or 0 for current window
--- @return integer[]
function vim.api.nvim_win_get_cursor(window) end

--- Gets the window height
---
--- @param window integer Window handle, or 0 for current window
--- @return integer
function vim.api.nvim_win_get_height(window) end

--- Gets the window number
---
--- @param window integer Window handle, or 0 for current window
--- @return integer
function vim.api.nvim_win_get_number(window) end

--- @deprecated
--- @param window integer
--- @param name string
--- @return any
function vim.api.nvim_win_get_option(window, name) end

--- Gets the window position in display cells. First position is zero.
---
--- @param window integer Window handle, or 0 for current window
--- @return integer[]
function vim.api.nvim_win_get_position(window) end

--- Gets the window tabpage
---
--- @param window integer Window handle, or 0 for current window
--- @return integer
function vim.api.nvim_win_get_tabpage(window) end

--- Gets a window-scoped (w:) variable
---
--- @param window integer Window handle, or 0 for current window
--- @param name string Variable name
--- @return any
function vim.api.nvim_win_get_var(window, name) end

--- Gets the window width
---
--- @param window integer Window handle, or 0 for current window
--- @return integer
function vim.api.nvim_win_get_width(window) end

--- Closes the window and hide the buffer it contains (like `:hide` with a
--- `window-ID`).
---
--- Like `:hide` the buffer becomes hidden unless another window is editing
--- it, or 'bufhidden' is `unload`, `delete` or `wipe` as opposed to `:close`
--- or `nvim_win_close()`, which will close the buffer.
---
--- @param window integer Window handle, or 0 for current window
function vim.api.nvim_win_hide(window) end

--- Checks if a window is valid
---
--- @param window integer Window handle, or 0 for current window
--- @return boolean
function vim.api.nvim_win_is_valid(window) end

--- Sets the current buffer in a window, without side effects
---
--- @param window integer Window handle, or 0 for current window
--- @param buffer integer Buffer handle
function vim.api.nvim_win_set_buf(window, buffer) end

--- Configures window layout. Cannot be used to move the last window in a
--- tabpage to a different one.
---
--- When reconfiguring a window, absent option keys will not be changed.
--- `row`/`col` and `relative` must be reconfigured together.
---
--- @param window integer Window handle, or 0 for current window
--- @param config vim.api.keyset.win_config Map defining the window configuration, see `nvim_open_win()`
function vim.api.nvim_win_set_config(window, config) end

--- Sets the (1,0)-indexed cursor position in the window. `api-indexing` This
--- scrolls the window even if it is not the current one.
---
--- @param window integer Window handle, or 0 for current window
--- @param pos integer[] (row, col) tuple representing the new position
function vim.api.nvim_win_set_cursor(window, pos) end

--- Sets the window height.
---
--- @param window integer Window handle, or 0 for current window
--- @param height integer Height as a count of rows
function vim.api.nvim_win_set_height(window, height) end

--- Set highlight namespace for a window. This will use highlights defined
--- with `nvim_set_hl()` for this namespace, but fall back to global
--- highlights (ns=0) when missing.
---
--- This takes precedence over the 'winhighlight' option.
---
--- @param window integer
--- @param ns_id integer the namespace to use
function vim.api.nvim_win_set_hl_ns(window, ns_id) end

--- @deprecated
--- @param window integer
--- @param name string
--- @param value any
function vim.api.nvim_win_set_option(window, name, value) end

--- Sets a window-scoped (w:) variable
---
--- @param window integer Window handle, or 0 for current window
--- @param name string Variable name
--- @param value any Variable value
function vim.api.nvim_win_set_var(window, name, value) end

--- Sets the window width. This will only succeed if the screen is split
--- vertically.
---
--- @param window integer Window handle, or 0 for current window
--- @param width integer Width as a count of columns
function vim.api.nvim_win_set_width(window, width) end

--- Computes the number of screen lines occupied by a range of text in a given
--- window. Works for off-screen text and takes folds into account.
---
--- Diff filler or virtual lines above a line are counted as a part of that
--- line, unless the line is on "start_row" and "start_vcol" is specified.
---
--- Diff filler or virtual lines below the last buffer line are counted in the
--- result when "end_row" is omitted.
---
--- Line indexing is similar to `nvim_buf_get_text()`.
---
--- @param window integer Window handle, or 0 for current window.
--- @param opts vim.api.keyset.win_text_height Optional parameters:
---             • start_row: Starting line index, 0-based inclusive. When
---               omitted start at the very top.
---             • end_row: Ending line index, 0-based inclusive. When omitted
---               end at the very bottom.
---             • start_vcol: Starting virtual column index on "start_row",
---               0-based inclusive, rounded down to full screen lines. When
---               omitted include the whole line.
---             • end_vcol: Ending virtual column index on "end_row", 0-based
---               exclusive, rounded up to full screen lines. When omitted
---               include the whole line.
--- @return table<string,any>
function vim.api.nvim_win_text_height(window, opts) end
