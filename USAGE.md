# Detailed usage guide

## Plugin UI
The plugin will prompt you for import settings/subsettings, most notably:
- `Core`
    - `Base import address`: The base to which offsets in the json form should be relative to. Auto-detected by DBImporter and should not require changing.
    - `Overwrite user-defined information`: If deselected, DBImporter will try to avoid overwriting any data you might have already added to the IDA database, but be warned! It doesn't guarantee preserving every user made change!!
- `Ghidra`
    - `Use Ghidra calling conventions`: trust calling conventions auto-dected by Ghidra.
    - `Keep N namespace levels`: Limit the namespace nesting from Ghidra. `0` for no namespaces, import everything globally, `-1` for all levels

## As a python module

The submodules let you programmatically specify import settings via \*Settings classes, you can use them like so
```python
import_settings = ida_dbimporter.ImportSettings()

import_settings.base_ea_override = 0x1337
import_settings.import_segs = False
import_settings.overwrite = False

ida_dbimporter.import_data_into_ida(data, import_settings)
```
The classes that hold this information are such:
- `ida_dbimporter`/`emuslifire.core`: `ida_dbimporter.core.ImportSettings`
- `ida_dbimporter.ghidra`: `ida_dbimporter.ghidra.GhidraXMLSettings`

## How to export data from other tools

- Ghidra: From the project view (right click binary -> Export), or from the disassembler (File -> Export *ALTERNATIVELY* use keyboard shortcuts `Alt` then `O`), export your file **in the XML format**
