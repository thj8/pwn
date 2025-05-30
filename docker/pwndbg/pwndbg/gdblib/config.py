"""
Dynamic configuration system for pwndbg, using GDB's built-in Parameter
mechanism.

To create a new pwndbg configuration point, call ``pwndbg.config.add_param``.

Parameters should be declared in the module in which they are primarily
used, or in this module for general-purpose parameters.

All pwndbg Parameter types are accessible via property access on this
module, for example:

    >>> pwndbg.config.add_param('example-value', 7, 'an example')
    >>> int(pwndbg.config.example_value)
    7
"""

from __future__ import annotations

from typing import Any

import gdb

import pwndbg
import pwndbg.decorators
import pwndbg.lib.config

CLASS_MAPPING = {
    pwndbg.lib.config.PARAM_BOOLEAN: gdb.PARAM_BOOLEAN,
    pwndbg.lib.config.PARAM_AUTO_BOOLEAN: gdb.PARAM_AUTO_BOOLEAN,
    pwndbg.lib.config.PARAM_ZINTEGER: gdb.PARAM_ZINTEGER,
    pwndbg.lib.config.PARAM_STRING: gdb.PARAM_STRING,
    pwndbg.lib.config.PARAM_ZUINTEGER: gdb.PARAM_ZUINTEGER,
    pwndbg.lib.config.PARAM_ENUM: gdb.PARAM_ENUM,
    pwndbg.lib.config.PARAM_OPTIONAL_FILENAME: gdb.PARAM_OPTIONAL_FILENAME,
    pwndbg.lib.config.PARAM_ZUINTEGER_UNLIMITED: gdb.PARAM_ZUINTEGER_UNLIMITED,
    pwndbg.lib.config.PARAM_INTEGER: gdb.PARAM_INTEGER,
    pwndbg.lib.config.PARAM_UINTEGER: gdb.PARAM_UINTEGER,
}


# See this for details about the API of `gdb.Parameter`:
# https://sourceware.org/gdb/onlinedocs/gdb/Parameters-In-Python.html
class Parameter(gdb.Parameter):
    def __init__(self, param: pwndbg.lib.config.Parameter) -> None:
        # `set_doc`, `show_doc`, and `__doc__` must be set before `gdb.Parameter.__init__`.
        # They will be used for `help set <param>` and `help show <param>`,
        # respectively
        self.set_doc = "Set " + param.set_show_doc + "."
        self.show_doc = "Show " + param.set_show_doc + "."
        self.__doc__ = param.help_docstring or None

        self.init_super(param)
        self.param = param
        self.value = param.value
        self.param.add_update_listener(self.on_change)

    def init_super(self, param: pwndbg.lib.config.Parameter) -> None:
        """Initializes the super class for GDB >= 9"""
        c = CLASS_MAPPING[param.param_class]
        if c == gdb.PARAM_ENUM:
            super().__init__(
                param.name,
                gdb.COMMAND_SUPPORT,
                c,
                param.enum_sequence,
            )
            return
        super().__init__(param.name, gdb.COMMAND_SUPPORT, c)

    def on_change(self, value: Any) -> None:
        """Called when the value of the pwndbg.lib.config.Parameter changes
        Transfer the value to the GDB parameter to keep them in sync.
        """
        self.value = value

    @property
    def native_value(self):
        return Parameter._value_to_gdb_native(
            self.param.value, param_class=CLASS_MAPPING[self.param.param_class]
        )

    @property
    def native_default(self):
        return Parameter._value_to_gdb_native(
            self.param.default, param_class=CLASS_MAPPING[self.param.param_class]
        )

    def get_set_string(self) -> str:
        """Handles the GDB `set <param>`"""
        # GDB will set `self.value` to the user's input
        if self.value is None and CLASS_MAPPING[self.param.param_class] in (
            gdb.PARAM_UINTEGER,
            gdb.PARAM_INTEGER,
        ):
            # Note: This is really weird, according to GDB docs, 0 should mean "unlimited" for gdb.PARAM_UINTEGER and gdb.PARAM_INTEGER, but somehow GDB sets the value to `None` actually :/
            # And hilarious thing is that GDB won't let you set the default value to `None` when you construct the `gdb.Parameter` object with `gdb.PARAM_UINTEGER` or `gdb.PARAM_INTEGER` lol
            # Maybe it's a bug of GDB?
            # Anyway, to avoid some unexpected behaviors, we'll still set `self.param.value` to 0 here.
            self.param.value = 0
        else:
            self.param.value = self.value

        for trigger in pwndbg.config.triggers[self.param.name]:
            trigger()

        # No need to print anything if this is set before we get to a prompt,
        # like if we're setting options in .gdbinit
        if not pwndbg.decorators.first_prompt:
            return ""

        return f"Set {self.param.set_show_doc} to {self.native_value!r}."

    def get_show_string(self, svalue: str) -> str:
        """Handles the GDB `show <param>`"""
        more_information_hint = f" See `help set {self.param.name}` for more information."
        return "{} is {!r}.{}".format(
            self.param.set_show_doc.capitalize(),
            svalue,
            more_information_hint if self.__doc__ else "",
        )

    @staticmethod
    def _value_to_gdb_native(value: Any, param_class: int | None = None) -> Any:
        """Translates Python value into native GDB syntax string."""
        if isinstance(value, bool):
            # Convert booleans to "on" or "off".
            return "on" if value else "off"
        elif value is None and CLASS_MAPPING[param_class] == gdb.PARAM_AUTO_BOOLEAN:
            # None for gdb.PARAM_AUTO_BOOLEAN means "auto".
            return "auto"
        elif value == 0 and CLASS_MAPPING[param_class] in (gdb.PARAM_UINTEGER, gdb.PARAM_INTEGER):
            # 0 for gdb.PARAM_UINTEGER and gdb.PARAM_INTEGER means "unlimited".
            return "unlimited"
        elif value == -1 and CLASS_MAPPING[param_class] == gdb.PARAM_ZUINTEGER_UNLIMITED:
            # -1 for gdb.PARAM_ZUINTEGER_UNLIMITED means "unlimited".
            return "unlimited"

        # Other types pass through normally
        return value


def init_params() -> None:
    # Create a gdb.Parameter for each parameter
    for p in pwndbg.config.params.values():
        # We don't need to store this anywhere, GDB will handle this
        Parameter(p)
