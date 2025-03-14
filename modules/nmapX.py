module_info = {
  "name": "NMAP Extreme",
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

  # Perform TCP scan with -sC and -sV options
  nm.scan(hosts=host["ip"], arguments='-sC -sV -sS -p-')

  # Initialize ports list in the host dictionary
  host["ports"] = []

  # Process TCP scan results
  for port in nm[host["ip"]]["tcp"].keys():
      if nm[host["ip"]]["tcp"][port]['state'] == "closed": break
      logging.log(f'IP: {host["ip"]} \t Port: {port} \t Protcol: TCP \t State: {nm[host["ip"]]["tcp"][port]["state"]} \t Service: {nm[host["ip"]]["tcp"][port].get("product", "")} \t Version: {nm[host["ip"]]["tcp"][port].get("version", "")} Scripts: {nm[host["ip"]]["tcp"][port].get("script", {})}', module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
      host["ports"].append({
          "Port": port, 
          "Protocol": "TCP", 
          "State": nm[host["ip"]]["tcp"][port]['state'], 
          "Service": nm[host["ip"]]["tcp"][port].get("product", ""),
          "Version": nm[host["ip"]]["tcp"][port].get("version", ""), 
          "Scripts": nm[host["ip"]]["tcp"][port].get("script", {})
      })

  # Perform UDP scan
  nm.scan(hosts=host["ip"], arguments='-sUV -p 161,1089-1091,2222,4000,20000,34962,34963,34964,34980,44818,47808,55000-55003')

  # Process UDP scan results
  for port in nm[host["ip"]]["udp"].keys():
      if nm[host["ip"]]["udp"][port]['state'] == "closed": break
      logging.log(f'IP: {host["ip"]} \t Port: {port} \t Protcol: UDP \t State: {nm[host["ip"]]["udp"][port]["state"]} \t Service: {nm[host["ip"]]["udp"][port].get("product", "")} \t Version: {nm[host["ip"]]["udp"][port].get("version", "")} Scripts: {nm[host["ip"]]["udp"][port].get("script", {})}', module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
      host["ports"].append({
          "Port": port,
          "Protocol": "UDP",
          "State": nm[host["ip"]]["udp"][port]['state'],
          "Service": nm[host["ip"]]["udp"][port].get("product", ""),
          "Version": nm[host["ip"]]["udp"][port].get("version", ""),
          "Scripts": nm[host["ip"]]["udp"][port].get("script", {})
      })

  return host