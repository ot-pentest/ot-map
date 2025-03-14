# [key for key, value in my_dict.items() if value.get('age') == target_age]

# Internal Imports
import config
from functions import arguments, export_to_csv, export_to_json, header, logging, run_module, write_to_file

#  args = arguments.init_arguments()

# Storage used while program is running
hosts = {}

def main():
  header.generate_and_print_header()
  args = arguments.init_arguments() # moved down
  module_names = []

  for mode in args.mode: 
    for module in config.modes.get(mode):
      if module not in module_names: module_names.append(module)

  hosts = (run_module.run_modules(module_names=module_names, args=args, hosts={}))
  if args.output_file != None:
    match args.output_file[0].lower():
      case "json": write_to_file.write_to_file(export_to_json.export_to_json(hosts), args.output_file[1])
      case "csv": export_to_csv.export_and_write_to_csv(hosts, args.output_file[1])
      case _: logging.log("Wrong export format", module="Exporter", category=2)
  logging.log(hosts, module="core", category=3, options={"debug": args.debug})

if __name__ == "__main__":
  main()