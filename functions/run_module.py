import importlib
import appinfo
from functions import logging

class Runtime_config:
  def __init__(self, debug: bool, target_ip: str, interface: str, duration: int, siemens_advisories: str, siemens_advisories_local: str) -> object:
      self.debug = debug
      self.target_ip = target_ip
      self.interface = interface
      self.duration = duration
      self.siemens_advisories = siemens_advisories
      self.siemens_advisories_local = siemens_advisories_local

class Module_import:
  def __init__(self, debug: bool, target_ip: str, interface: str, duration: int, siemens_advisories, siemens_advisories_local, hosts: dict) -> object:
    self.runtime_config = Runtime_config(debug, target_ip, interface, duration, siemens_advisories, siemens_advisories_local=siemens_advisories_local)
    self.hosts = hosts

def run_module(module_name: str, appconfig, debug: bool, target_ip: str, interface: str, duration: int, siemens_advisories: str, siemens_advisories_local, hosts: dict) -> dict:
  module_import = Module_import(
    debug=debug,
    target_ip=target_ip,
    interface=interface,
    duration=duration,
    siemens_advisories=siemens_advisories,
    siemens_advisories_local=siemens_advisories_local,
    hosts=hosts
  )

  try:
    module = importlib.import_module(f'{appconfig.modulefolder}.{module_name}')
    logging.log("Starting...", module=module.module_info["name"])
    hosts = module.run(module_import)
  except Exception as e:
    logging.log({type(e).__name__}, module=module_name, category=2)
    logging.log(e, module=module_name, category=3, options={"debug": module_import.runtime_config.debug})
    return
  else:
    logging.log('Finished Successfuly', module=module.module_info["name"])
    return hosts

def run_modules(module_names: list, args: object, hosts: dict) -> dict: 
  for module_name in module_names:
    hosts = run_module(module_name=module_name, appconfig=appinfo, debug=args.debug, target_ip=args.target_ip, interface=args.interface, duration=args.duration, siemens_advisories=args.siemens_advisories, siemens_advisories_local=args.siemens_advisories, hosts=hosts)
  return hosts