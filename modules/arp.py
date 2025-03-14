module_info = {
  "name": "ARP",
  "version": 0.2,
  "output": "hosts",
  "otscanner": {
    "version": 0.1
  }
}

import nmap
from functions import logging
import xml.etree.ElementTree as ET

def parse_vendor_xml(xml_path: str) -> dict:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    namespace = {'ns': 'http://www.cisco.com/server/spt'}
    vendor_mapping = {}
    for vendor in root.findall('ns:VendorMapping', namespace):
        mac_prefix = vendor.get('mac_prefix')
        vendor_name = vendor.get('vendor_name')
        vendor_mapping[mac_prefix] = vendor_name
    return vendor_mapping

def get_vendor_name(mac: str, vendor_mapping: dict) -> str:
    mac_prefix = mac[:8].upper()  # Get the first 8 characters of the MAC address
    return vendor_mapping.get(mac_prefix, 'Unknown Vendor')

def run(module_import: object) -> object:
    return main(module_import)

def main(module_import: object) -> object:
    # Create an instance of the PortScanner class
    nm = nmap.PortScanner()

    # Perform the ARP scan
    nm.scan(hosts=module_import.runtime_config.target_ip, arguments='-sn -PR')

    # Parse the vendor XML file
    vendor_mapping = parse_vendor_xml('assets/vendorMacs.xml')

    # Parse the result
    for host in nm.all_hosts():
        if 'mac' not in nm[host]['addresses']:
            continue
        module_import.hosts[len(module_import.hosts)] = {"ip": nm[host]['addresses']['ipv4'], "mac": nm[host]['addresses']['mac'], "device_info": {"Vendor": get_vendor_name(nm[host]['addresses']['mac'], vendor_mapping)}}
        logging.log(f"IP: {nm[host]['addresses']['ipv4']} \t MAC: {nm[host]['addresses']['mac']} \t Vendor: {get_vendor_name(nm[host]['addresses']['mac'], vendor_mapping)}", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
    return module_import.hosts