module_info = {
    "name": "S7-scanner",
    "version": 0.1,
    "otscanner": {
        "version": 0.1
    }
}

from functions import logging

import socket
import struct
import snap7
import os
import sys

def run(module_import: object) -> dict:
  for host_id in module_import.hosts:
    if {'Port': 102, 'Protocol': 'TCP', 'State': 'open'} not in module_import.hosts[host_id]["ports"]: continue
    main(module_import.hosts[host_id], module_import)
  return module_import.hosts

def main(host: dict, module_import: object) -> dict:
  host["device_info"] = {} if not "device_info" in host else host["device_info"]
  target = host["ip"]
  port = 102
  result = action(target, port)
  plc = snap7.client.Client()
  try:
    for slot in range(7):
      sys.stderr = open(os.devnull, 'w')
      try:
        plc.connect(target, 0, slot)
        if b"CPU" in plc.get_cpu_info().ModuleTypeName: break
        else: plc.disconnect()
      except Exception as e:
         logging.log(f"Error connecting to slot {slot} on {target}: {e}", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
         continue
      finally:
         sys.stderr = sys.__stderr__
      logging.log(f"Connecting to: \t IP: {host['ip']} \t Slot: {slot}", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
    # Read basic device information
    try:
      info = plc.get_cpu_info()
      host["device_info"]["cpu state"] = "Run" if plc.get_cpu_state() == "S7CpuStatusRun" else "Stop"
      host["device_info"]["device version"] = info.ModuleTypeName.decode()
      host["device_info"]["Serial Number"] = info.SerialNumber.decode()
      logging.log(f"device info: \t {host['device_info']}", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
    except Exception as e:
      logging.log(f"Error reading device information: {e}", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
  except Exception as e:
      logging.log(f"General error in PLC connection process: {e}", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
  finally:
      # Close the connection
    try:
      plc.disconnect()
    except Exception as e:
      logging.log(f"Error disconnecting from PLC: {e}", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
    if isinstance(result, dict):
      for key, value in result.items():
        host["device_info"][key] = value
  return host

def send_receive(sock, query, bytes_expected):
  try:
    sock.sendall(query)
    response = sock.recv(bytes_expected)
    return response
  except socket.error as e:
    return "Error: " + str(e)

def parse_response(response, output):
  if len(response) < 31:
    return None

  value = response[7]
  szl_id = response[30]

  if value == 0x32 and len(response) >= 125:
    output["Basic Hardware"] = response[71:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    char1, char2, char3 = struct.unpack("BBB", response[122:125])
    output["Firmware Version"] = f"{char1 or 0}.{char2}.{char3}"
    return output
  else:
    return None

def second_parse_response(response, output):
  offset = 0
  if len(response) < 31:
    return None

  value = response[7]
  szl_id = response[30]

  if value == 0x32:
    if szl_id != 0x1c:
      offset = 4
    if len(response) > 40 + offset:
      output["System Name"] = response[39 + offset:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    if len(response) > 74 + offset:
      output["Module Type"] = response[73 + offset:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    if len(response) > 176 + offset:
      output["Serial Number"] = response[175 + offset:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    if len(response) > 108 + offset:
      output["Plant Identification"] = response[107 + offset:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    if len(response) > 142 + offset:
      output["Vendor"] = response[141 + offset:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    for key, value in list(output.items()):
      if len(output[key]) == 0:
         del output[key]
      return output
  else:
    return None

def action(host, port):
  COTP = bytes.fromhex("0300001611e00000001400c1020100c202010200c0010a")
  alt_COTP = bytes.fromhex("0300001611e00000000500c1020100c2020200c0010a")
  ROSCTR_Setup = bytes.fromhex("0300001902f08032010000000000080000f0000001000101e0")
  Read_SZL = bytes.fromhex("0300002102f080320700000000000800080001120411440100ff09000400110001")
  first_SZL_Request = bytes.fromhex("0300002102f080320700000000000800080001120411440100ff09000400110001")
  second_SZL_Request = bytes.fromhex("0300002102f080320700000000000800080001120411440100ff090004001c0001")
  output = {}

  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    try:
      sock.connect((host, port))
      response = send_receive(sock, COTP, 256)
      CC_connect_confirm = response[5]
      if CC_connect_confirm != 0xd0:
        sock.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        response = send_receive(sock, alt_COTP, 256)
        CC_connect_confirm = response[5]
        if CC_connect_confirm != 0xd0:
          return None
        response = send_receive(sock, ROSCTR_Setup, 256)
        protocol_id = response[7]
        if protocol_id != 0x32:
          return None
        response = send_receive(sock, Read_SZL, 256)
        protocol_id = response[7]
        if protocol_id != 0x32:
          return None
        response = send_receive(sock, first_SZL_Request, 256)
        output = parse_response(response, output)
        response = send_receive(sock, second_SZL_Request, 256)
        output = second_parse_response(response, output)

    except Exception as e:
      return "Error: " + str(e)

    return output