import json
import math
import re


def import_ida_mods() -> None:
    global ida_moves, ida_idc, ida_idaapi, ida_ida, ida_typeinf, ida_name
    global ida_lines, ida_segment, ida_bytes, ida_funcs, ida_frame, ida_nalt
    global ida_hexrays, ida_kernwin
    import ida_moves
    import ida_idc
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


base_dict = {
    "version": "0.1",
    "datatypes": {},
    "names": {},
    "bookmarks": {},
    "comments": {},
    "functions": {},
    "segments": [],
    "typed_data": {},
}

datatypes = {}
ida_base_ea = 0

re_fndecl = re.compile("([a-zA-Z0-9_:]+)(?:[* ]*)(?:[a-zA-Z0-9_:]+)?")
re_delims = re.compile(r"[\s,*&()<>\[\]{},]")
re_bitfield = re.compile(r"(^.*):(\d*)$")

import_stack: list[str] = []


class ImportSettings:
    base_ea_override: None | int = None

    import_fns = True
    import_cmts = True
    import_types = True
    import_names = True
    import_marks = True
    import_segs = True
    import_typed_data = True

    overwrite = True


def dict_to_json(data: dict) -> str:
    return json.dumps(data, indent=4)


def parse_file(filepath: str):
    with open(filepath, "r") as f:
        return json.load(f)


def import_file_into_ida(filepath: str, **kwargs):
    dbi_data = parse_file(filepath)
    import_data_into_ida(dbi_data, **kwargs)


def import_data_into_ida(data: dict, import_settings=ImportSettings()):
    import_ida_mods()

    global ida_base_ea
    ida_base_ea = (
        get_base_import_ea()
        if import_settings.base_ea_override is None
        else import_settings.base_ea_override
    )

    if import_settings.import_types:
        global datatypes
        datatypes = data["datatypes"]
        for name, info in datatypes.items():
            try:
                global import_stack
                import_stack = []
                import_datatype(name)
            except Exception as e:
                wlog(f"Failed to import type {name}: {e}")
                continue

    if import_settings.import_names:
        for addr, name in data["names"].items():
            try:
                ea = int(addr, 0x10) + ida_base_ea

                if ea_has_user_name(ea) and not import_settings.overwrite:
                    continue

                ida_name.set_name(ea, name, ida_name.SN_FORCE)
            except Exception as e:
                wlog("Failed to import name %s@%s: %s" % (name, addr, e))
                continue

    if import_settings.import_marks:
        for address, description in data["bookmarks"].items():
            try:
                address = int(address, 0x10) + ida_base_ea
                import_bookmark(address, description)
            except Exception as e:
                wlog("Failed to import bookmark @%X: %s" % (address, e))
                continue

    if import_settings.import_cmts:
        for address, comment in data["comments"].items():
            try:
                address = int(address, 0x10) + ida_base_ea

                if (
                    ida_bytes.get_cmt(address, False) is not None
                    and not import_settings.overwrite
                ):
                    continue

                import_comment(address, comment)
            except Exception as e:
                wlog("Failed to import comment @%X: %s" % (address, e))
                continue

    if import_settings.import_fns:
        for fn_ea, fn_info in data["functions"].items():
            try:
                fn_ea_int = int(fn_ea, 0x10) + ida_base_ea
                import_function(fn_ea_int, fn_info)
            except Exception as e:
                wlog(f"Failed to import function '{fn_ea}': {e}")
                continue

    if import_settings.import_segs:
        for segment in data["segments"]:
            try:
                import_segment(segment)
            except Exception as e:
                wlog("Failed to import segment %s: %s" % (segment["name"], e))
                continue

    if import_settings.import_typed_data:
        for ea, type in data["typed_data"].items():
            try:
                ea_int = int(ea, 0x10) + ida_base_ea
                ea_ti = ida_typeinf.tinfo_t()
                if ea_ti.parse(type, pt_flags=ida_typeinf.PT_SIL) is True:
                    ida_typeinf.apply_tinfo(
                        ea_int,
                        ea_ti,
                        ida_typeinf.TINFO_DEFINITE | ida_typeinf.TINFO_DELAYFUNC,
                    )
            except Exception as e:
                wlog("Failed to set datatype %s@%s: %s" % (type, ea, e))
            continue


def wlog(msg: str) -> None:
    print(f"WARNING: {msg}")


def get_arbitrary_size_type(size: int) -> str:
    size_type_map = {1: "_BYTE", 2: "_WORD", 4: "_DWORD", 8: "_QWORD"}

    if size not in size_type_map:
        return f"_BYTE[{size}]"

    return size_type_map[size]


def import_function(fn_ea: int, info: dict) -> None:
    fn_ti = ida_typeinf.tinfo_t()

    if "decl" in info:
        if fn_ti.parse(info["decl"], pt_flags=ida_typeinf.PT_SIL) is True:
            ida_typeinf.apply_tinfo(
                fn_ea,
                fn_ti,
                ida_typeinf.TINFO_DEFINITE | ida_typeinf.TINFO_DELAYFUNC,
            )

    for lvar in info["lvars"]:
        if "stack_offset" in lvar:
            stkvar_ti = ida_typeinf.tinfo_t()

            if stkvar_ti.parse(lvar["type"], pt_flags=ida_typeinf.PT_SIL) is False:
                wlog("Failed to parse stkvar %s" % lvar["type"])
                continue

            ida_frame.define_stkvar(
                ida_funcs.get_func(fn_ea),
                lvar["name"],
                int(lvar["stack_offset"], 0x10),
                stkvar_ti,
            )

        elif "reg" in lvar:
            ida_frame.add_regvar(
                ida_funcs.get_func(fn_ea),
                int(lvar["start_ea"], 0x10) + ida_base_ea,
                int(lvar["end_ea"], 0x10) + ida_base_ea,
                lvar["reg"],
                lvar["name"],
                lvar["cmt"],
            )


def import_comment(address: int, comment: dict) -> None:
    match comment["type"]:
        case "pre":
            ida_lines.add_extra_cmt(address, True, comment["contents"])
        case "post":
            ida_lines.add_extra_cmt(address, False, comment["contents"])
        case "repeatable":
            ida_bytes.set_cmt(address, comment["contents"], True)
        case "eol":
            ida_bytes.set_cmt(address, comment["contents"], False)


def import_segment(segment: dict) -> None:
    if ida_segment.get_segm_by_name(segment["name"]) is not None:
        return

    idaseg = ida_segment.segment_t()

    idaseg.sel = ida_segment.allocate_selector(0)
    idaseg.start_ea = int(segment["start_ea"], 0x10) + ida_base_ea
    idaseg.end_ea = int(segment["end_ea"], 0x10) + ida_base_ea

    ida_bitness2seg_bitness_map = {16: 0, 32: 1, 64: 2}

    idaseg.bitness = ida_bitness2seg_bitness_map[ida_ida.inf_get_app_bitness()]

    idaseg_class = None

    if "r" in segment["perms"]:
        idaseg.perm |= ida_segment.SEGPERM_READ
    if "w" in segment["perms"]:
        idaseg.perm |= ida_segment.SEGPERM_WRITE
    if "x" in segment["perms"]:
        idaseg.perm |= ida_segment.SEGPERM_EXEC
        idaseg_class = "CODE"

    ida_segment.add_segm_ex(idaseg, segment["name"], idaseg_class, 0)


def import_bookmark(address: int, description: str) -> bool:
    for slot in range(ida_moves.MAX_MARK_SLOT):
        pos = ida_idc.get_marked_pos(slot)
        if pos == ida_idaapi.BADADDR or pos == address:
            ida_idc.mark_position(address, 0, 0, 0, slot, description)
            return True
    return False


def import_datatype(name: str) -> bool:
    if name in import_stack:
        ti = ida_typeinf.tinfo_t()
        ti.create_forward_decl(None, ida_typeinf.BTF_STRUCT, name)

        return True

    import_stack.append(name)
    ti = ida_typeinf.tinfo_t()

    info = datatypes[name]

    match info["type"]:
        case "struct":
            ti = get_struct_or_union_ti(info)

            if ti is None:
                wlog(f"Failed to create struct {name}")
                return False

            return check_terr(
                ti.set_named_type(None, name, ida_typeinf.NTF_REPLACE),
                f"Adding struct '{name}'",
            )

        case "union":
            ti = get_struct_or_union_ti(info, True)

            if ti is None:
                wlog(f"Failed to create union {name}")
                return False

            return check_terr(
                ti.set_named_type(None, name, ida_typeinf.NTF_REPLACE),
                f"Adding union '{name}'",
            )

        case "typedef":
            datatype_def = info["decl"]
            ti = datatype_to_tinfo(datatype_def)

            if ti is None:
                wlog(f"Failed to parse typedef {name}: {datatype_def}")
                return False

            return check_terr(
                ti.set_named_type(None, name, ida_typeinf.NTF_REPLACE),
                f"Adding typedef '{name}'",
            )

        case "enum":
            enum_ti = ida_typeinf.get_named_type(None, name, ida_typeinf.NTF_TYPE)
            if enum_ti is not None:
                return True

            # IDA enum size = 1 << (n - 1)
            enum_size = int(info["size"], 0x10)
            enum_size_exp = int(math.log2(enum_size)) + 1
            if ti.create_enum(enum_size_exp | ida_typeinf.BTE_HEX) is not True:
                ida_kernwin.warning(f"Bad enum size: {name}, {enum_size}")
                return False

            for entry_name, entry_value in info["entries"].items():
                e_val_int = int(entry_value, 0x10)
                check_terr(
                    ti.add_edm(entry_name, e_val_int, -1, ida_typeinf.ETF_FORCENAME),
                    f"Adding enum value {entry_name}",
                )

            return check_terr(
                ti.set_named_type(None, name, ida_typeinf.NTF_REPLACE),
                f"Adding enum '{name}'",
            )

        case "function":
            if "decl" in info:
                ti = get_fn_tinfo_parse(info["decl"])
            else:
                ti = get_fn_tinfo_programmatic(info)

            return check_terr(
                ti.set_named_type(None, name, ida_typeinf.NTF_REPLACE),
                f"Adding function '{name}'",
            )

    return False


def check_terr(code: int, action: str) -> bool:
    if code != ida_typeinf.TERR_OK:
        wlog(f"{action} failed: {ida_typeinf.tinfo_errstr(code)}")

    return code == ida_typeinf.TERR_OK


def datatype_to_tinfo(datatype: str, size: int | None = None):
    ti = ida_typeinf.tinfo_t()

    if datatype == "void":
        ti.create_simple_type(ida_typeinf.BT_VOID)
        return ti

    # if it's an indigenous type, try to import/get
    if datatype in datatypes:
        if ti.get_named_type(datatype):
            return ti
        else:
            import_datatype(datatype)

    # can we parse correctly?
    if ti.parse(datatype, pt_flags=ida_typeinf.PT_SIL):
        return ti

    # import whatever we can find in the decl string
    for word in re_delims.split(datatype):
        if word in datatypes:
            import_datatype(word)

    # can we now?
    if ti.parse(datatype, pt_flags=ida_typeinf.PT_SIL):
        return ti

    # fall back to an unspecific type
    if size is not None:
        ti.parse(get_arbitrary_size_type(size))
        return ti
    else:
        return None


def add_member(parent_td: "ida_typeinf.udt_type_data_t", member: dict) -> bool:
    member_name = member["name"]
    member_type = member["type"]
    member_size = int(member["size"], 0x10)

    member_ti = ida_typeinf.tinfo_t()

    m = re_bitfield.match(member_type)
    if m is None:
        member_ti = datatype_to_tinfo(member_type, member_size)
    else:
        bf_type = m.group(1)
        bf_underlying_ti = datatype_to_tinfo(bf_type)
        bf_underlying_size = bf_underlying_ti.get_size()
        bf_width = int(m.group(2))
        member_ti.create_bitfield(bf_underlying_size, bf_width)

    if member_ti is None:
        wlog("Failed to parse member type %s" % member["type"])
        return False

    offset = 0
    if not parent_td.is_union:
        offset = int(member["offset"], 0x10) * 8

    parent_td.add_member(member_name, member_ti, offset)
    return True


def get_struct_or_union_ti(info: dict, union=False) -> "ida_typeinf.tinfo_t":
    ti = ida_typeinf.tinfo_t()

    if "decl" in info:
        if not ti.parse(info["decl"], pt_flags=ida_typeinf.PT_SIL):
            return None

        return ti

    udt_td = ida_typeinf.udt_type_data_t()
    udt_td.is_union = union

    for member in info["members"]:
        add_member(udt_td, member)

    if not ti.create_udt(udt_td, ida_typeinf.BTF_UNION):
        wlog(f"Failed to create udt: {name}")
        return None

    return ti


def get_fn_tinfo_parse(fn_decl: str) -> "ida_typeinf.tinfo_t":
    fn_ti = ida_typeinf.tinfo_t()
    # purpose: extract all types from a function declaration
    # so we can recursively import them all from the string
    fn_types = re_fndecl.findall(fn_decl)

    for ftype in fn_types:
        if fn_ti.parse(ftype, pt_flags=ida_typeinf.PT_SIL) is False:
            if ftype in datatypes:
                import_datatype(ftype)

    if fn_ti.parse(fn_decl, pt_flags=ida_typeinf.PT_SIL) is False:
        raise Exception(f"Failed to parse function '{fn_decl}'")

    return fn_ti


def get_fn_tinfo_programmatic(fn_data: dict) -> "ida_typeinf.tinfo_t":
    fn_ti = ida_typeinf.tinfo_t()

    ftd = ida_typeinf.func_type_data_t()

    for arg in fn_data["args"]:
        arg_name = arg["name"]
        arg_type = arg["type"]

        arg_ti = datatype_to_tinfo(arg_type)
        if arg_ti is None:
            raise Exception("Failed to get argument type %s" % arg_type)

        farg = ida_typeinf.funcarg_t(arg_name, arg_ti)
        ftd.append(farg)

    rettype_ti = datatype_to_tinfo(fn_data["rettype"])
    if rettype_ti is None:
        raise Exception("Failed to get return type %s " % fn_data["rettype"])

    ftd.rettype = rettype_ti

    fn_ti.create_func(ftd)

    return fn_ti


def get_base_import_ea() -> int:
    import_ida_mods()

    return (
        ida_nalt.get_imagebase()
        if ida_nalt.get_imagebase() != 0
        else ida_ida.inf_get_min_ea()
    )


def ea_has_user_name(ea: int):
    return ida_bytes.has_user_name(ida_bytes.get_flags(ea))
