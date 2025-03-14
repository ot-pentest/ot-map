import argparse
import appinfo
import config

def define_program() -> object:
  return argparse.ArgumentParser(
    description=appinfo.program_description,
    prog=appinfo.program_name,
    epilog=f"Version: {appinfo.program_version}\nDeveloped by: {'; '.join(appinfo.program_authors)}"
  )

def define_arguments(parser: object) -> object:
  parser.add_argument(
    "--add",
    "-a",
    help="Adds custom Arguments to commands",
    nargs=2 
  )

  parser.add_argument(
    "--duration",
    "-d",
    default=config.default_duration,
    help="Runtime Duration of LLDP Sniffer",
    type=int
  )

  parser.add_argument(
    "--debug",
    help="Shows debug and diagnostic Informations",
    action="store_true"
  )

  parser.add_argument(
    "--interface", 
    "-i",
    default=config.default_interface,
    metavar=("interface"),
    help="Specify the interface you want to scan on"
  )

  # parser.add_argument(
  #   "--lldp",
  #   action="store_true",
  #   help="toggle lldp sniff"
  # )

  parser.add_argument(
    "--mode",
    "-m",
    action='append',
    choices=list(config.modes.keys()),
    help=f"choose the mode to run like: {', '.join(list(config.modes.keys()))}",
    default=config.default_modes
  )

  # parser.add_argument(
  #   "--nmap-agresive",
  #   "-x",
  #   action="store_true",
  #   help="Toggle agresive NMAP scan"
  # )

  parser.add_argument(
    "--output-file",
    "-o",
    metavar=("filetype", "filepath"),
    help="Outputs results to a file, output json or csv ",
    nargs=2
  )

  parser.add_argument(
    "--siemens-advisories",
    "-sa",
    help="Specify a Siemens Advisories Atom file to check for vulnerabilities",
    type=str,
    nargs=2,
    metavar=("atomfile", "namingtable"),
    default=config.default_siemens_advisories
  )

  parser.add_argument(
    "--siemens-advisories-local",
    "-sal",
    help="Specify a local Siemens Advisories Atom file that will be used to check for vulnerabilities if no internet connection is available",
    type=str,
    metavar=("local atomfile"),
    default=config.default_siemens_advisories_local
  )

  parser.add_argument(
    "target_ip", 
    help="Specify the IP / IP Range"
  )

  return parser

def get_args(parser: object) -> object: return parser.parse_args()

def init_arguments(): return get_args(define_arguments(define_program()))