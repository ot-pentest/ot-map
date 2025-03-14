module_info = {
  "name": "Check siemens Advisories",
  "version": 0.1,
  "output": "hosts",
  "otscanner": {
    "version": 0.1
  }
}

import re
import requests
import xml.etree.ElementTree as ET
from functions import logging, import_from_json

def run(module_import: object) -> dict:
  if len(module_import.runtime_config.siemens_advisories) != 2:
    logging.log("Not enough arguments - module skipped", module_info["name"], 2)
    return module_import.hosts

  if re.match(r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#\?&//=]*)", module_import.runtime_config.siemens_advisories[0]):
    try:
      response = requests.get(module_import.runtime_config.siemens_advisories[0])
      logging.log("Downloading Atom file", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
      if response.status_code == 200:
        logging.log("Downloaded Atom file", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
        atomFile_content = response.content
      else:
        logging.log(f"Failed to download the file. - Using local file - Status code: {response.status_code}", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
        atomFile = open(module_import.runtime_config.siemens_advisories_local, "r")
        atomFile_content = atomFile.read()
    except Exception as e:
      logging.log(f"Failed to download the file. - Using local file: {e}", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
      atomFile = open(module_import.runtime_config.siemens_advisories_local, "r")
      atomFile_content = atomFile.read()
  else:
    logging.log("Using specific local file", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
    atomFile = open(module_import.runtime_config.siemens_advisories[0], "r")
    atomFile_content = atomFile.read()
  siemensAdvisoriesList = ImportsiemensAdvisoriesAtomFile(atomFile_content)
  lookuptable = import_from_json.import_from_json(module_import.runtime_config.siemens_advisories[1])
  for host_id in module_import.hosts:
    main(module_import.hosts[host_id], siemensAdvisoriesList, lookuptable, module_import)
  return module_import.hosts

def main(host: object, siemensAdvisoriesList: list, lookuptable: dict, module_import: object) -> dict:
  search_for_vulnerabilities_in_device_info(host, siemensAdvisoriesList, lookuptable, module_import)
  search_for_vulnerabilities_in_network_info(host, siemensAdvisoriesList, lookuptable, module_import)
  return

def search_for_vulnerabilities_in_device_info(host: object, siemensAdvisoriesList: list, lookuptable: dict, module_import: object) -> dict:
  if not host.get("device_info"):
    logging.log(f"No devices info: {host['ip']}", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
    return
  if not host["device_info"].get("device version") in lookuptable:
    logging.log(f"No devices version: {host['ip']}", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
    return
  for entry in siemensAdvisoriesList:
    for lookupEntry in lookuptable[host["device_info"]["device version"]]:
      if lookupEntry not in entry["Title"] or lookupEntry not in entry["Summary"]: continue
      host["vulnerabilities"] = [] if not "vulnerabilities" in host else host["vulnerabilities"]
      host["vulnerabilities"].append(entry)

def search_for_vulnerabilities_in_network_info(host: object, siemensAdvisoriesList: list, lookuptable: dict, module_import: object) -> dict:
  if not host.get("network_info"):
    logging.log(f"No network info: {host['ip']}", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
    return
  if not host["network_info"].get("network version") in lookuptable:
    logging.log(f"No network version: {host['ip']}", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
    return
  for entry in siemensAdvisoriesList:
    for lookupEntry in lookuptable[host["device_info"]["device version"]]:
      if lookupEntry not in entry["Title"] or lookupEntry not in entry["Summary"]: continue
      host["vulnerabilities"] = [] if not "vulnerabilities" in host else host["vulnerabilities"]
      host["vulnerabilities"].append(entry)

def ImportsiemensAdvisoriesAtomFile(atom_data: str) -> list:
  root = ET.fromstring(atom_data)
  siemensAdvisoriesList = []
  for entry in root.findall(".//{http://www.w3.org/2005/Atom}entry"):
    siemensAdvisoriesList.append({'Title': entry.find("{http://www.w3.org/2005/Atom}title").text, 'Summary': entry.find("{http://www.w3.org/2005/Atom}summary").text, 'Link': entry.find("{http://www.w3.org/2005/Atom}link").attrib.get("href")})
  return siemensAdvisoriesList