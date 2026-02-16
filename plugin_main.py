import ida_idaapi
import ida_kernwin

import ida_dbimporter


class DBImporter(ida_idaapi.plugmod_t):
    def run(self, arg):
        if not form_main.Execute():
            return

        db_filepath = form_main.db_filepath.value

        i_settings = ida_dbimporter.ImportSettings()

        i_settings.base_ea_override = form_main.base_ea.value

        i_settings.import_fns = form_main.import_fns.checked
        i_settings.import_cmts = form_main.import_cmts.checked
        i_settings.import_types = form_main.import_types.checked
        i_settings.import_names = form_main.import_names.checked
        i_settings.import_marks = form_main.import_marks.checked
        i_settings.import_segs = form_main.import_segs.checked

        i_settings.overwrite = form_main.overwrite_data.checked

        db_type = db_filepath.split(".")[-1]

        dbi_data = {}

        match db_type:
            case "xml":
                if not form_ghidra.Execute():
                    return

                gxml_settings = ida_dbimporter.ghidra.GhidraXMLSettings()

                keep_namespaces = form_ghidra.keep_namespaces.value
                if keep_namespaces != -1:
                    gxml_settings.keep_namespaces = keep_namespaces

                gxml_settings.use_ghidra_callconvs = (
                    form_ghidra.use_ghidra_callconvs.checked
                )
                gxml_settings.only_user_defined_syms = (
                    form_ghidra.only_user_defined_syms.checked
                )

                dbi_data = ida_dbimporter.ghidra.parse_file(
                    db_filepath, conversion_settings=gxml_settings
                )
            case "json":
                dbi_data = ida_dbimporter.parse_file(db_filepath)
            case _:
                return

        ida_dbimporter.import_data_into_ida(dbi_data, i_settings)

        return True


class DBImporterPlug(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    comment = "Import data from all sorts of reverse engineering tools"
    wanted_name = "DBImporter"

    def init(self):
        return DBImporter()


def PLUGIN_ENTRY():
    return DBImporterPlug()


form_main = ida_kernwin.Form(
    r"""DBImporter
    <Database file: {db_filepath}>
    <Base import address: {base_ea}>

    <Import functions: {import_fns}>
    <Import comments: {import_cmts}>
    <Import types: {import_types}>
    <Import names: {import_names}>
    <Import bookmarks: {import_marks}>
    <Import segments: {import_segs}>
    <Import typed data: {import_typed_data}>

    <Overwrite user-defined information: {overwrite_data}>{toggles}>""",
    {
        "db_filepath": ida_kernwin.Form.FileInput(value="*.json;*.xml", open=True),
        "base_ea": ida_kernwin.Form.NumericInput(),
        "toggles": ida_kernwin.Form.ChkGroupControl(
            (
                "import_fns",
                "import_cmts",
                "import_types",
                "import_names",
                "import_marks",
                "import_segs",
                "import_typed_data",
                "overwrite_data",
            )
        ),
    },
)

form_ghidra = ida_kernwin.Form(
    r"""Ghidra XML import options
    <Keep N namespace levels (-1 = All): {keep_namespaces}>

    <Use Ghidra calling conventions: {use_ghidra_callconvs}>
    <Import only user-defined symbols: {only_user_defined_syms}>{toggles}>""",
    {
        "keep_namespaces": ida_kernwin.Form.NumericInput(
            tp=ida_kernwin.Form.FT_DEC, value=-1
        ),
        "toggles": ida_kernwin.Form.ChkGroupControl(
            (
                "only_user_defined_syms",
                "use_ghidra_callconvs",
            )
        ),
    },
)

form_main.Compile()

form_main.base_ea.value = ida_dbimporter.core.get_base_import_ea()

form_main.import_fns.checked = True
form_main.import_cmts.checked = True
form_main.import_types.checked = True
form_main.import_names.checked = True
form_main.import_marks.checked = True
form_main.import_segs.checked = True
form_main.import_typed_data.checked = True
form_main.overwrite_data.checked = True


form_ghidra.Compile()

form_ghidra.only_user_defined_syms.checked = True
form_ghidra.use_ghidra_callconvs.checked = False
