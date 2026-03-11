import ida_dbimporter.core
import regex
import re

from copy import deepcopy

re_templates = regex.compile("<([^<>]*(?R)?[^<>]*)*>")
re_delims = re.compile(r"[\s,*&()<>\[\]{};]")


class ExportSettings:
    export_fns = True
    export_cmts = True
    export_types = True
    export_names = True
    export_marks = True
    export_segs = True
    export_typed_data = True

    no_filter_templates = False


export_settings = ExportSettings()


def normalize_templates(typename: str) -> str:
    return re_templates.sub(lambda x: re_delims.sub("_", x.group(0)), typename)


def export_to_file(filepath: str, **kwargs) -> None:
    with open(filepath, "w") as f:
        dbi_export = export(**kwargs)
        f.write(ida_dbimporter.core.dict_to_json(dbi_export))


def export(settings=None) -> dict:
    if settings is None:
        settings = ExportSettings()

    global export_settings
    export_settings = settings
    global ida_moves, idc, ida_idaapi, ida_ida, ida_typeinf, ida_name
    global ida_lines, ida_segment, ida_bytes, ida_funcs, ida_frame, ida_nalt
    global ida_hexrays, ida_kernwin
    import ida_moves
    import idc
    import ida_idaapi
    import ida_ida
    import ida_typeinf
    import ida_name
    import ida_lines
    import ida_segment
    import ida_bytes
    import ida_funcs
    import ida_frame
    import ida_nalt
    import ida_hexrays
    import ida_kernwin
    import ida_ida

    global base_ea
    base_ea = ida_dbimporter.core.get_base_import_ea()

    result = scan_idb_props(deepcopy(ida_dbimporter.core.base_dict))

    if settings.export_marks:
        for slot in range(ida_moves.MAX_MARK_SLOT):
            ea = idc.get_bookmark(slot)
            if ea == ida_idaapi.BADADDR:
                break

            ea -= base_ea
            desc = idc.get_bookmark_desc(slot)
            result["bookmarks"][hex(ea)] = desc

    if settings.export_fns:
        for idx in range(ida_funcs.get_func_qty()):
            fn = ida_funcs.getn_func(idx)
            if fn is None:
                continue

            ea = fn.start_ea - base_ea

            fn_entry, cmts = export_function(fn)
            if len(fn_entry) >= 1:
                result["functions"][hex(ea)] = fn_entry
            
            result["comments"] += cmts

    if settings.export_segs:
        for n in range(0, ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(n)
            seg_entry = {
                "name": idc.get_segm_name(seg.start_ea),
                "start_ea": hex(seg.start_ea - base_ea),
                "end_ea": hex(seg.end_ea - base_ea),
                "perms": "",
            }

            for perm_ida, perm_dbi in [
                (ida_segment.SEGPERM_READ, "r"),
                (ida_segment.SEGPERM_WRITE, "w"),
                (ida_segment.SEGPERM_EXEC, "x"),
            ]:
                if seg.perm & perm_ida:
                    seg_entry["perms"] += perm_dbi

            result["segments"].append(seg_entry)

    if settings.export_types:
        idatil = ida_typeinf.get_idati()

        for ti in idatil.numbered_types():
            type_entry = export_type(ti)
            if type_entry is not None:
                name = ti.get_type_name()
                if not export_settings.no_filter_templates:
                    name = normalize_templates(name)

                result["datatypes"][name] = type_entry

    return result


# scans for comments, names, and data
def scan_idb_props(result: dict) -> dict:
    ea = ida_ida.inf_get_min_ea()
    max_ea = ida_ida.inf_get_max_ea()

    while ea != ida_idaapi.BADADDR:
        f = ida_bytes.get_full_flags(ea)

        if export_settings.export_cmts and (
            ida_bytes.has_cmt(f) or ida_bytes.has_extra_cmts(f)
        ):
            result["comments"] += export_cmts(ea)

        if export_settings.export_names and ida_bytes.has_user_name(f):
            name = ida_name.get_visible_name(
                ea, ida_name.GN_LOCAL | ida_name.GN_VISIBLE
            )
            if name is not None and len(name) >= 1:
                result["names"][hex(ea - base_ea)] = name

        if export_settings.export_typed_data and ida_bytes.is_struct(f):
            opndbuf = ida_nalt.opinfo_t()
            opnd = ida_bytes.get_opinfo(opndbuf, ea, 0, f)
            typename = idc.get_struc_name(opnd.tid)
            if typename is not None:
                result["typed_data"][hex(ea - base_ea)] = typename

        ea = ida_bytes.next_that(
            ea,
            max_ea,
            lambda x: (
                export_settings.export_cmts
                and (ida_bytes.has_cmt(x) or ida_bytes.has_extra_cmts(x))
            )
            or (export_settings.export_names and ida_bytes.has_user_name(x))
            or (export_settings.export_typed_data and ida_bytes.is_struct(x)),
        )
    return result


def export_cmts(ea: int) -> list[dict]:
    # function comments are extracted with the functions, see export_function
    results = []
    addr = hex(ea - base_ea)

    cmt = ida_lines.get_extra_cmt(ea, ida_lines.E_PREV)
    if cmt is not None:
        results.append({"address": addr, "contents": cmt, "type": "pre"})

    cmt = ida_lines.get_extra_cmt(ea, ida_lines.E_NEXT)
    if cmt is not None:
        results.append(
            {
                "address": addr,
                "contents": cmt,
                "type": "post",
            }
        )

    cmt = idc.get_cmt(ea, True)
    if cmt is not None:
        results.append(
            {
                "address": addr,
                "contents": cmt,
                "type": "repeatable",
            }
        )

    cmt = idc.get_cmt(ea, False)
    if cmt is not None:
        results.append({"address": addr, "contents": cmt, "type": "eol"})

    return results


def export_type(ti: "ida_typeinf.tinfo_t") -> dict:
    type_of_type = None
    if ti.is_struct() or ti.is_forward_struct():
        type_of_type = "struct"
    elif ti.is_enum():
        type_of_type = "enum"
    elif ti.is_func():
        type_of_type = "function"
    elif ti.is_union() or ti.is_forward_union():
        type_of_type = "union"
    elif ti.is_typedef():
        type_of_type = "typedef"

    if type_of_type is None:
        return None

    decl = ida_typeinf.print_tinfo(
        None,
        0,
        0,
        ida_typeinf.PRTYPE_NOREGEX
        | ida_typeinf.PRTYPE_TYPE
        | ida_typeinf.PRTYPE_DEF
        | ida_typeinf.PRTYPE_1LINE
        | ida_typeinf.PRTYPE_SEMI
        | ida_typeinf.PRTYPE_NORES,
        ti,
        "_dbimporter_dummy_name_",
        None,
    )

    if not export_settings.no_filter_templates:
        decl = normalize_templates(decl)

    return {"type": type_of_type, "decl": decl}


def export_function(fn: "ida_funcs.func_t") -> (dict, list[dict]):
    cmts = []

    cmt = ida_funcs.get_func_cmt(fn, False)
    if cmt is not None:
        cmts.append(
            {
                "address": hex(fn.start_ea - base_ea),
                "contents": cmt,
                "type": "func",
            }
        )

    cmt = ida_funcs.get_func_cmt(fn, True)
    if cmt is not None:
        cmts.append(
            {
                "address": hex(fn.start_ea - base_ea),
                "contents": cmt,
                "type": "func_repeatable",
            }
        )


    fn_entry = {"lvars": []}

    if fn.get_prototype() is not None:
        fn_entry["decl"] = str(fn.get_prototype())

    if not export_settings.no_filter_templates and "decl" in fn_entry:
        fn_entry["decl"] = normalize_templates(fn_entry["decl"])

    fo = fn.get_frame_object()
    if fo is not None:
        for m in fo.iter_struct():
            lvar = {}
            lvar["name"] = m.name
            type = ida_typeinf.print_tinfo(
                None,
                0,
                0,
                ida_typeinf.PRTYPE_NOREGEX
                | ida_typeinf.PRTYPE_1LINE
                | ida_typeinf.PRTYPE_NORES,
                m.type,
                None,
                None,
            )

            if not export_settings.no_filter_templates:
                type = normalize_templates(type)

            lvar["type"] = type
            lvar["size"] = hex(m.type.get_size())
            lvar["stack_offset"] = hex(ida_frame.soff_to_fpoff(fn, int(m.offset / 8)))

            fn_entry["lvars"].append(lvar)

    return fn_entry, cmts
