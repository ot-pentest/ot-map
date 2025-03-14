module_info = {
  "name": "AB Info",
  "version": 0.1,
  "output": "hosts",
  "otscanner": {
    "version": 0.1
  }
}

from functions import logging

def run(module_import: object) -> dict:
  # Run once per Host
  for host_id in module_import.hosts:
    if {'Port': 44818, 'Protocol': 'TCP', 'State': 'open'} not in module_import.hosts[host_id]["ports"] and {'Port': 44818, 'Protocol': 'UDP', 'State': 'open|filtered'} not in  module_import.hosts[host_id]["ports"] and {'Port': 44818, 'Protocol': 'UDP', 'State': 'open|filtered'} not in module_import.hosts[host_id]["ports"]: continue
    main(module_import.hosts[host_id], module_import)
  return module_import.hosts

def main(host: dict, module_import: object) -> dict:
  result = get_plc_info(host['ip'], module_import)
  if result == None: 
    return
  host["device_info"] = {} if not "device_info" in host else host["device_info"]
  host["device_info"] = result
  return

from pycomm3 import LogixDriver

def get_plc_info(ip_address, module_import):
    try:
        with LogixDriver(ip_address) as plc:
            info = {
                'System Name': plc.info['name'],
                'Vendor': plc.info['vendor'],
                'Product Number': plc.info['product_code'],
                'Firmware Version': plc.info['revision'],
                'Serial Number': plc.info['serial'],
                'Device Version': plc.info['product_name']
            }
            logging.log(f"RAW Device information: IP: ${ip_address} {plc.info}", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
            return info
    except Exception as e:
        logging.log(e, module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
        return None