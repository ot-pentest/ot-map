module_info = {
  "name": "NMAP",
  "version": 0.1,
  "output": "hosts",
  "otscanner": {
    "version": 0.1
  }
}

import nmap
from functions import logging

def run(module_import: object) -> dict:
  for host_id in module_import.hosts:
    main(module_import.hosts[host_id], module_import)
  return module_import.hosts

def main(host: dict, module_import: object) -> dict:
  # Create Nmap PortScanner object
  nm = nmap.PortScanner()

  # Perform TCP scan
  nm.scan(hosts=host["ip"], arguments='-sT -p 102,80,443,502,1089-1091,4000,4840,20000,34962-34964,44818')

  # Print out the scan results
  host["ports"] = []

  for port in nm[host["ip"]]["tcp"].keys():
    if nm[host["ip"]]["tcp"][port]['state'] != "closed":
      logging.log(f'IP: {host["ip"]} \t Port: {port} \t Protcol: TCP \t State: {nm[host["ip"]]["tcp"][port]["state"]}', module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
      host["ports"].append({
        "Port": port, 
        "Protocol": "TCP", 
        "State": nm[host["ip"]]["tcp"][port]['state']
      })

  # Perform UDP scan
  nm.scan(hosts=host["ip"], arguments='-sU -p 161,1089-1091,2222,4000,20000,34962,34963,34964,34980,44818,47808,55000-55003')

  for port in nm[host["ip"]]["udp"].keys():
    if nm[host["ip"]]["udp"][port]['state'] != "closed":
      logging.log(f'IP: {host["ip"]} \t Port: {port} \t Protcol: UDP \t State: {nm[host["ip"]]["udp"][port]["state"]}', module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
      host["ports"].append({
        "Port": port, 
        "Protocol": "UDP", 
        "State": nm[host["ip"]]["udp"][port]['state']
      })
  
  return host