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
        i_settings.parser = form_main.parser[form_main.parser.value]

        i_settings.import_fns = form_main.import_fns.checked
        i_settings.import_cmts = form_main.import_cmts.checked
        i_settings.import_types = form_main.import_types.checked
        i_settings.import_names = form_main.import_names.checked
        i_settings.import_marks = form_main.import_marks.checked
        i_settings.import_segs = form_main.import_segs.checked

        i_settings.overwrite = form_main.overwrite_data.checked

        db_type = ida_dbimporter.detect_db_format(db_filepath)

        dbi_data = {}

        match db_type:
            case "ghidra_xml":
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
            case "dbi_json":
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


def export_handler(_):
    if not form_export.Execute():
        return

    e_settings = ida_dbimporter.exporter.ExportSettings()

    e_settings.export_fns = form_export.export_fns.checked
    e_settings.export_cmts = form_export.export_cmts.checked
    e_settings.export_types = form_export.export_types.checked
    e_settings.export_names = form_export.export_names.checked
    e_settings.export_marks = form_export.export_marks.checked
    e_settings.export_segs = form_export.export_segs.checked

    e_settings.no_filter_templates = form_export.no_filter_templates.checked

    ida_dbimporter.exporter.export_to_file(
        form_export.db_filepath.value, settings=e_settings
    )
    ida_kernwin.info(f"Exported info to {form_export.db_filepath.value}")


form_main = ida_kernwin.Form(
    r"""DBImporter
    <Database file: {db_filepath}>
    <Base import address: {base_ea}>
    <Type parser: {parser}>

    <Import functions: {import_fns}>
    <Import comments: {import_cmts}>
    <Import types: {import_types}>
    <Import names: {import_names}>
    <Import bookmarks: {import_marks}>
    <Import segments: {import_segs}>
    <Import typed data: {import_typed_data}>

    <Overwrite user-defined information: {overwrite_data}>{toggles}>

    <Export IDA database to DBI file: {export}>""",
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
        "export": ida_kernwin.Form.ButtonInput(export_handler),
        "parser": ida_kernwin.Form.DropdownListControl(
            items=["legacy", "clang_templates_only", "clang_always"]
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

form_ghidra.Compile()

form_ghidra.only_user_defined_syms.checked = True
form_ghidra.use_ghidra_callconvs.checked = False


form_export = ida_kernwin.Form(
    # <Base export address: {base_ea}>
    r"""DBImporter Export
    <Output file: {db_filepath}>

    <Export functions: {export_fns}>
    <Export comments: {export_cmts}>
    <Export types: {export_types}>
    <Export names: {export_names}>
    <Export bookmarks: {export_marks}>
    <Export segments: {export_segs}>
    <Export typed data: {export_typed_data}>


    <Don't filter templated typenames (requires clang parser to parse, experimental):"""
    """{no_filter_templates}>{toggles}>""",
    {
        "db_filepath": ida_kernwin.Form.FileInput(value="*.json", save=True),
        # "base_ea": ida_kernwin.Form.NumericInput(),
        "toggles": ida_kernwin.Form.ChkGroupControl(
            (
                "export_fns",
                "export_cmts",
                "export_types",
                "export_names",
                "export_marks",
                "export_segs",
                "export_typed_data",
                "no_filter_templates",
            )
        ),
    },
)

form_export.Compile()

form_export.export_fns.checked = True
form_export.export_cmts.checked = True
form_export.export_types.checked = True
form_export.export_names.checked = True
form_export.export_marks.checked = True
form_export.export_segs.checked = True
form_export.export_typed_data.checked = True

form_export.no_filter_templates.checked = False
