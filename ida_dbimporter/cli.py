def deep_merge(d1, d2):
    for k, v in d2.items():
        if isinstance(v, dict) and k in d1 and isinstance(d1[k], dict):
            deep_merge(d1[k], v)
        else:
            if isinstance(v, list) and k in d1:
                d1[k] += v
            else:
                d1[k] = v
    return d1


def main():
    import argparse
    import sys

    import ida_dbimporter

    parser = argparse.ArgumentParser(
        prog="dbimporter",
        description="A tool to import data from "
        "all sorts of reverse engineering tools into IDA",
    )
    parser.add_argument(
        "-p",
        "--parser",
        default="legacy",
        choices=["legacy", "clang_templates_only", "clang_always"],
        help="Set the type parser (default: %(default)s)"
        "Legacy: default, fast. "
        "Clang (templates only): use clang to parse templated types only. "
        "Clang (always): Always use clang for type parsing (may fix some issues, slow)",
    )
    parser.add_argument(
        "-i", "--input", nargs="*", help="Input file path, can be multiple files"
    )
    parser.add_argument(
        "-c",
        "--combine",
        action="store_true",
        help="Combine input files",
    )
    parser.add_argument(
        "-mkidb",
        "--make-idb",
        action="store_true",
        help="Create an IDA database with the imported data (idb-base)",
    )
    parser.add_argument(
        "-idbb",
        "--idb-base",
        help="File that the IDA database should be based on. "
        "Can be an existing IDA database or a new binary (export, make-idb)",
    )
    parser.add_argument(
        "-e",
        "--export",
        help="Export IDB/binary to DBI JSON format database (idb-base, make-idb)",
    )
    parser.add_argument(
        "-t",
        "--translate",
        action="store_true",
        help="Translate input files into DBI json. Files will be saved either to "
        "{input_filepath}.json, or {first_input_filepath}.combined.json, when combined",
    )

    args = parser.parse_args(sys.argv[1:])

    dbi_data = {}

    if args.combine or args.translate:
        for i in args.input:
            if args.combine:
                dbi_data = deep_merge(dbi_data, ida_dbimporter.parse_file_auto(i))
            elif args.translate:
                if ida_dbimporter.detect_db_format(i) == "dbi_json":
                    continue

                dbi_data = ida_dbimporter.parse_file_auto(i)
                with open(f"{i}.json", "w") as f:
                    f.write(ida_dbimporter.dict_to_json(dbi_data))
    else:
        if args.input is not None:
            i = args.input[len(args.input) - 1]
            dbi_data = ida_dbimporter.parse_file_auto(i)

    if args.make_idb or args.export is not None:
        import ida_domain

        db = ida_domain.Database()

        if db.open(args.idb_base, save_on_close=args.make_idb) is None:
            sys.exit(2)

        if len(dbi_data) > 0:
            i_settings = ida_dbimporter.ImportSettings()
            i_settings.parser = args.parser

            ida_dbimporter.import_data_into_ida(dbi_data, i_settings)

        if args.export is not None:
            ida_dbimporter.exporter.export_to_file(args.export)

        db.close()

    if not args.combine:
        return

    json_str = ida_dbimporter.dict_to_json(dbi_data)

    with open(args.input[0] + ".combined.json", "w") as f:
        f.write(json_str)

    return


if __name__ == "__main__":
    main()
