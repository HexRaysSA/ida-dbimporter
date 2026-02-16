import argparse
import sys

import ida_dbimporter

parser = argparse.ArgumentParser(
    prog="dbimporter",
    description="A tool to import data from all sorts of reverse engineering tools into IDA",
)

parser.add_argument("input_file")
parser.add_argument("-o", "--output", help="Output file path")
parser.add_argument(
    "-mkidb",
    "--make-idb",
    action="store_true",
    help="Create an IDA database with the imported data",
)
parser.add_argument(
    "-idbb",
    "--idb-base",
    help="File that the IDA database should be based on. Can be an existing IDA database or a new binary",
)

args = parser.parse_args(sys.argv[1:])

if args.make_idb:
    import ida_domain

    with ida_domain.Database() as db:
        if db.open(args.idb_base, save_on_close=True):
            dbi_data = {}

            if args.input_file.endswith(".xml"):
                dbi_data = ida_dbimporter.ghidra.parse_file(args.input_file)
            elif args.input_file.endswith(".json"):
                dbi_data = ida_dbimporter.parse_file(args.input_file)

            ida_dbimporter.import_data_into_ida(dbi_data)
        else:
            print(f"IDA couldn't open file {args.idb_base}")
            sys.exit(1)

    sys.exit(0)

if args.output is None:
    args.output = args.input_file + ".json"

dbi_data = ida_dbimporter.ghidra.parse_file(args.input_file)
json_str = ida_dbimporter.dict_to_json(dbi_data)

with open(args.output, "w") as f:
    f.write(json_str)
