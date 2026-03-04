import xml.dom.minidom
import re

import ida_dbimporter

image_base = 0


class GhidraXMLSettings:
    keep_namespaces: None | int = None
    use_ghidra_callconvs = False
    only_user_defined_syms = True


conv_settings = GhidraXMLSettings()

forbidden_words = [
    # generic attributes
    "__bin",
    "__oct",
    "__hex",
    "__dec",
    "__float",
    "__char",
    "__segm",
    "__enum",
    "__off",
    "__offset",
    "__unused",
    "__strlit",
    "__stroff",
    "__custom",
    "__invsign",
    "__invbits",
    "__lzero",
    "__sbin",
    "__soct",
    "__shex",
    "__udec",
    "__tabform",
    "__signed",
    "__hidden",
    "__return_ptr",
    "__struct_ptr",
    "__array_ptr",
    # C code parser
    "default",
]

forbidden_chars = ["[", "]", ".", "/", "(", ")", "!"]

ghidra_builtin_types = {
    "undefined": {"type": "typedef", "decl": "unsigned char"},
    "byte": {"type": "typedef", "decl": "unsigned char"},
    "dword": {"type": "typedef", "decl": "unsigned int"},
    "pointer32": {"type": "typedef", "decl": "unsigned int"},
    "ImageBaseOffset32": {"type": "typedef", "decl": "pointer32"},
    "uint": {"type": "typedef", "decl": "unsigned int"},
    "undefined1": {"type": "typedef", "decl": "unsigned char"},
    "undefined2": {"type": "typedef", "decl": "unsigned short"},
    "undefined4": {"type": "typedef", "decl": "unsigned int"},
    "word": {"type": "typedef", "decl": "unsigned short"},
    "complex16": {"type": "typedef", "decl": "unsigned long long"},
    "complex32": {"type": "typedef", "decl": "unsigned long long"},
    "complex8": {"type": "typedef", "decl": "unsigned long long"},
    "doublecomplex": {"type": "typedef", "decl": "unsigned long long"},
    "dwfenc": {"type": "typedef", "decl": "unsigned char"},
    "FileTime": {"type": "typedef", "decl": "unsigned long long"},
    "floatcomplex": {"type": "typedef", "decl": "unsigned long long"},
    "GUID": {"type": "typedef", "decl": "unsigned long long"},
    "pointer64": {"type": "typedef", "decl": "unsigned long long"},
    "ImageBaseOffset64": {"type": "typedef", "decl": "pointer64"},
    "int16": {"type": "typedef", "decl": "long long"},
    "int3": {"type": "typedef", "decl": "int"},
    "int5": {"type": "typedef", "decl": "long long"},
    "int6": {"type": "typedef", "decl": "long long"},
    "int7": {"type": "typedef", "decl": "long long"},
    "longdouble": {"type": "typedef", "decl": "long double"},
    "longdoublecomplex": {"type": "typedef", "decl": "unsigned long long"},
    "longlong": {"type": "typedef", "decl": "long long"},
    "MacTime": {"type": "typedef", "decl": "unsigned int"},
    "prel31": {"type": "typedef", "decl": "unsigned int"},
    "qword": {"type": "typedef", "decl": "unsigned long long"},
    "sbyte": {"type": "typedef", "decl": "char"},
    "schar": {"type": "typedef", "decl": "signed char"},
    "sdword": {"type": "typedef", "decl": "int"},
    "SegmentedCodeAddress": {"type": "typedef", "decl": "unsigned int"},
    "ShiftedAddress": {"type": "typedef", "decl": "unsigned int"},
    "sqword": {"type": "typedef", "decl": "long long"},
    "sword": {"type": "typedef", "decl": "short"},
    "wchar16": {"type": "typedef", "decl": "unsigned short"},
    "wchar32": {"type": "typedef", "decl": "unsigned int"},
    "uchar": {"type": "typedef", "decl": "unsigned char"},
    "uint16": {"type": "typedef", "decl": "unsigned long long"},
    "uint3": {"type": "typedef", "decl": "unsigned int"},
    "uint5": {"type": "typedef", "decl": "unsigned long long"},
    "uint6": {"type": "typedef", "decl": "unsigned long long"},
    "uint7": {"type": "typedef", "decl": "unsigned long long"},
    "ulong": {"type": "typedef", "decl": "unsigned long"},
    "ulonglong": {"type": "typedef", "decl": "unsigned long long"},
    "undefined3": {"type": "typedef", "decl": "unsigned int"},
    "undefined5": {"type": "typedef", "decl": "unsigned long long"},
    "undefined6": {"type": "typedef", "decl": "unsigned long long"},
    "undefined7": {"type": "typedef", "decl": "unsigned long long"},
    "undefined8": {"type": "typedef", "decl": "unsigned long long"},
    "ushort": {"type": "typedef", "decl": "unsigned short"},
    "wchar_t": {"type": "typedef", "decl": "short"},
}


def parse_file(filepath: str, **kwargs) -> dict:
    with open(filepath, "r") as f:
        return parse_xml(xml.dom.minidom.parse(f), **kwargs)


def parse_xml(
    xmlobj: xml.dom.minidom.Document, conversion_settings=GhidraXMLSettings()
) -> dict:
    global conv_settings
    conv_settings = conversion_settings

    result = ida_dbimporter.core.base_dict

    program = xmlobj.getElementsByTagName("PROGRAM")[0]

    global image_base
    image_base = int(program.getAttribute("IMAGE_BASE"), 0x10)

    # initialize the "typelib" with ghidra's builtins
    # their typelib uses them a lot
    result["datatypes"] = ghidra_builtin_types

    datatypes = program.getElementsByTagName("DATATYPES")[0].childNodes
    for datatype in datatypes:
        if datatype.nodeType != xml.dom.minidom.Node.ELEMENT_NODE:
            continue
        type_of_datatype = datatype.nodeName
        datatype_name = get_typename_of_obj(datatype)
        # it's a lost cause
        if " " in datatype_name:
            continue

        match type_of_datatype:
            case "STRUCTURE":
                if datatype_name == "(anonymous_namespace)":
                    datatype_name = "anon_ns"

                members = import_members(datatype)

                result["datatypes"][datatype_name] = {
                    "type": "struct",
                    "members": members,
                }
            case "UNION":
                members = import_members(datatype)

                result["datatypes"][datatype_name] = {
                    "type": "union",
                    "members": members,
                }
            case "TYPE_DEF":
                datatype_def = get_datatype_of_obj(datatype)

                result["datatypes"][datatype_name] = {
                    "type": "typedef",
                    "decl": datatype_def,
                }
            case "ENUM":
                enum_size = datatype.getAttribute("SIZE")
                entries = {}
                for entry in datatype.getElementsByTagName("ENUM_ENTRY"):
                    entry_name = entry.getAttribute("NAME")
                    entry_value = entry.getAttribute("VALUE")
                    entries[entry_name] = entry_value

                result["datatypes"][datatype_name] = {
                    "type": "enum",
                    "size": enum_size,
                    "entries": entries,
                }

            case "FUNCTION_DEF":
                result["datatypes"][datatype_name] = {
                    "type": "function",
                    "rettype": get_datatype_of_obj(
                        datatype.getElementsByTagName("RETURN_TYPE")[0]
                    ),
                    "args": [],
                }

                for param in datatype.getElementsByTagName("PARAMETER"):
                    arg_name = param.getAttribute("NAME")
                    arg_type = get_datatype_of_obj(param)
                    result["datatypes"][datatype_name]["args"].append(
                        {"name": arg_name, "type": arg_type}
                    )

    for sym in program.getElementsByTagName("SYMBOL"):
        sym_name = sym.getAttribute("NAME")
        sym_namespace = sym.getAttribute("NAMESPACE")
        sym_namespace_prefix = get_namespace_prefix(sym_namespace, "::")

        source = sym.getAttribute("SOURCE_TYPE")

        if conv_settings.only_user_defined_syms:
            if source != "USER_DEFINED":
                continue

        sym_address = ghidra_addr_to_ea(sym.getAttribute("ADDRESS"))
        result["names"][hex(sym_address)] = sym_namespace_prefix + sym_name

    for fn in program.getElementsByTagName("FUNCTION"):
        fn_ea = ghidra_addr_to_ea(fn.getAttribute("ENTRY_POINT"))
        result["functions"][hex(fn_ea)] = import_function(fn)

    for bookmark in program.getElementsByTagName("BOOKMARK"):
        bookmark_addr = ghidra_addr_to_ea(bookmark.getAttribute("ADDRESS"))
        bookmark_type = bookmark.getAttribute("TYPE")
        bookmark_description = bookmark.getAttribute("DESCRIPTION")

        result["bookmarks"][
            hex(bookmark_addr)
        ] = f"({bookmark_type}) {bookmark_description}"

    for cmt in program.getElementsByTagName("COMMENT"):
        addr = ghidra_addr_to_ea(cmt.getAttribute("ADDRESS"))
        contents = get_xml_entity_text(cmt)
        type = cmt.getAttribute("TYPE")

        match type:
            case "plate":
                type = "pre"
            case "end-of-line":
                type = "eol"

        result["comments"][hex(addr)] = {"contents": contents, "type": type}

    memmap = program.getElementsByTagName("MEMORY_MAP")[0]
    for msection in memmap.getElementsByTagName("MEMORY_SECTION"):
        seg_name = msection.getAttribute("NAME")
        seg_size = int(msection.getAttribute("LENGTH"), 0x10)
        seg_addr = ghidra_addr_to_ea(msection.getAttribute("START_ADDR"))
        if seg_addr == -1:
            continue
        perms = msection.getAttribute("PERMISSIONS")

        seg_start_ea = seg_addr
        seg_end_ea = seg_addr + seg_size
        seg = {
            "name": seg_name,
            "start_ea": hex(seg_start_ea),
            "end_ea": hex(seg_end_ea),
            "perms": perms,
        }
        result["segments"].append(seg)

    for dd in program.getElementsByTagName("DEFINED_DATA"):
        dd_ea = ghidra_addr_to_ea(dd.getAttribute("ADDRESS"))
        dd_type = get_datatype_of_obj(dd)

        result["typed_data"][hex(dd_ea)] = dd_type

    return result


def get_xml_entity_text(ent: xml.dom.minidom.Element) -> str:
    text = ""
    for cn in ent.childNodes:
        if cn.nodeType == xml.dom.minidom.Node.TEXT_NODE:
            text += cn.data
    return text


def get_namespace_prefix(ns: str, delim: str, newdelim: str | None = None) -> str:
    if conv_settings.keep_namespaces == 0 or ns == delim:
        return ""

    if ns.startswith(delim):
        ns = ns.removeprefix(delim)

    if newdelim is None:
        newdelim = delim

    namespace_prefix = newdelim.join(ns.split(delim)[conv_settings.keep_namespaces :])

    if len(namespace_prefix) > 0 and not namespace_prefix.endswith(newdelim):
        namespace_prefix += newdelim

    return namespace_prefix


# purpose: get the name of a type declaration object
# i.e. typedef int MyInt; -> MyInt
def get_typename_of_obj(obj: xml.dom.minidom.Element) -> str:
    typename = obj.getAttribute("NAME")

    namespace = get_namespace_prefix(obj.getAttribute("NAMESPACE"), "/", "::")

    return filter_chars(namespace + typename)


# purpose: get the type of the subject of a type declaration
# i.e. typedef int MyInt; -> int
# or float fp_var; -> float
def get_datatype_of_obj(obj: xml.dom.minidom.Element) -> str:
    datatype = obj.getAttribute("DATATYPE")

    namespace = get_namespace_prefix(obj.getAttribute("DATATYPE_NAMESPACE"), "/", "::")

    return filter_chars(namespace + datatype, ["."])


def import_members(datatype: xml.dom.minidom.Element) -> list:
    datatype_size = int(datatype.getAttribute("SIZE"), 0x10)

    member_offset_int = 0
    member_size_int = 0
    members = []
    for mem in datatype.getElementsByTagName("MEMBER"):
        member_name = mem.getAttribute("NAME")
        member_name = filter_names(member_name)
        member_name = filter_chars(member_name)
        member_type = get_datatype_of_obj(mem)

        member_offset = mem.getAttribute("OFFSET")
        member_size = mem.getAttribute("SIZE")
        member_offset_int = int(member_offset, 0x10)
        member_size_int = int(member_size, 0x10)

        if member_size_int == 0:
            continue

        if member_type == "string *":
            member_type = "char*"

        if member_type == "string":
            member_type = f"_BYTE[{member_size}]"

        if len(member_name) == 0:
            member_name = f"member_{member_offset}"

        member = {"name": member_name, "type": member_type, "size": member_size}

        if datatype.tagName == "STRUCTURE":
            member["offset"] = member_offset

        members.append(member)

    size_delta = 0
    # last member of the struct is used
    total_size = member_offset_int + member_size_int

    if datatype.tagName == "STRUCTURE":
        size_delta = datatype_size - total_size

    if size_delta > 0:
        members.append(
            {
                "name": f"pad{size_delta}",
                "type": f"_BYTE[{size_delta}]",
                "size": hex(size_delta),
                "offset": hex(total_size),
            }
        )

    return members


def import_function(fn: xml.dom.minidom.Element) -> dict:
    fn_dict_entry = {
        # optional
        # "decl": "",
        "lvars": [],
    }

    fn_typeinfo_cmt = fn.getElementsByTagName("TYPEINFO_CMT")

    if fn_typeinfo_cmt != []:
        fn_typeinfo_cmt = get_xml_entity_text(fn_typeinfo_cmt[0])
        fn_typeinfo_cmt = filter_names(fn_typeinfo_cmt)

        calling_convetions = [
            "__stdcall",
            "MSABI",
            "__thiscall",
            "processEntry",
            "syscall",
        ]

        if not conv_settings.use_ghidra_callconvs:
            for cc in calling_convetions:
                fn_typeinfo_cmt = fn_typeinfo_cmt.replace(cc, "")

        fn_dict_entry["decl"] = fn_typeinfo_cmt

    stkframe = fn.getElementsByTagName("STACK_FRAME")[0]
    for stkvar in stkframe.getElementsByTagName("STACK_VAR"):
        stkvar_name = stkvar.getAttribute("NAME")

        stkvar_type = get_datatype_of_obj(stkvar)
        stkvar_size = stkvar.getAttribute("SIZE")
        stkvar_offset = stkvar.getAttribute("STACK_PTR_OFFSET")

        fn_dict_entry["lvars"].append(
            {
                "name": stkvar_name,
                "stack_offset": stkvar_offset,
                "size": stkvar_size,
                "type": stkvar_type,
            }
        )
    return fn_dict_entry


def filter_chars(word: str, chars=forbidden_chars) -> str:
    for c in chars:
        word = word.replace(c, "_")
    return word


re_badwords = re.compile(
    #  separators  word  separators
    r"(?:[, ();]|^)(%s)(?:[, ();]|$)"
    % "|".join(forbidden_words)
)
# we only capture the 'word' group
# we create a regex with all the bad words in the group joined by OR operators


def filter_names(name: str) -> str:
    # __off_t __off -> __off_t __off_
    def replace_names(m: re.Match):
        return m[0].replace(m[1], m[1] + "_")

    return re_badwords.sub(replace_names, name)


def ghidra_addr_to_ea(ghidra_addr: str) -> int:
    if "::" in ghidra_addr:
        ida_dbimporter.core.wlog(f"Could not convert address {ghidra_addr}")
        return -1
    elif ":" in ghidra_addr:
        [segment, offset] = ghidra_addr.split(":")
        try:
            segment_i = int(segment, 0x10)
            offset_i = int(offset, 0x10)
        except ValueError:
            ida_dbimporter.core.wlog(f"Could not convert address {ghidra_addr}")
            return -1
        return segment_i * 16 + offset_i - image_base
    else:
        return int(ghidra_addr, 0x10) - image_base
