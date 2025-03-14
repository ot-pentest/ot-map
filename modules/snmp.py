import asyncio
from pysnmp.hlapi.v1arch.asyncio import *
from functions import logging

module_info = {
    "name": "SNMP",
    "version": 0.1,
    "output": "hosts",
    "otscanner": {
        "version": 0.1
    }
}

# Create a global SnmpDispatcher instance to reuse
SNMP_DISPATCHER = SnmpDispatcher()
SNMP_TIMEOUT = 5  # Set timeout in seconds to prevent indefinite hanging

def run(module_import: object) -> dict:
    return asyncio.run(async_run(module_import))

async def async_run(module_import: object) -> dict:
    tasks = []
    for host_id in module_import.hosts:
        if {'Port': 161, 'Protocol': 'UDP', 'State': 'open'} not in module_import.hosts[host_id]["ports"]:
            continue
        tasks.append(main(module_import.hosts[host_id], module_import))
    
    results = await asyncio.gather(*[asyncio.wait_for(task, timeout=SNMP_TIMEOUT) for task in tasks], return_exceptions=True)
    
    for host, result in zip(module_import.hosts.values(), results):
        if isinstance(result, Exception):
            logging.log(f"SNMP request failed: {result}", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
        else:
            host.update(result)
    
    return module_import.hosts

async def main(host: dict, module_import: object) -> dict:
    try:
        snmp_data = await asyncio.wait_for(get_snmp_data(host, module_import), timeout=SNMP_TIMEOUT)
    except asyncio.TimeoutError:
        logging.log(f"SNMP request timed out for {host['ip']}", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
        return host
    return format_snmp_data(host, module_import, snmp_data)

async def get_snmp_data(host: dict, module_import: object) -> dict:
    community = 'public'  # Replace with actual SNMP community string
    oid = '1.3.6.1.2.1.1.1.0'

    try:
        transport_target = await asyncio.wait_for(UdpTransportTarget.create((host["ip"], 161)), timeout=SNMP_TIMEOUT)
        errorIndication, errorStatus, errorIndex, varBinds = await asyncio.wait_for(
            get_cmd(
                SNMP_DISPATCHER,
                CommunityData(community),
                transport_target,
                ObjectType(ObjectIdentity(oid))
            ), timeout=SNMP_TIMEOUT)

        if errorIndication:
            logging.log(f'{errorIndication}', module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
            return None
        elif errorStatus:
            logging.log('%s at %s' % (errorStatus, errorIndex and varBinds[int(errorIndex) - 1][0] or '?'), module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
            return None
        else:
            for varBind in varBinds:
                return varBind.prettyPrint().split('=')[1].strip()
    except asyncio.TimeoutError:
        logging.log(f"Timeout while querying SNMP for {host['ip']}", module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
        return None
    except Exception as e:
        logging.log(f'Error: {str(e)}', module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
        return None

def format_snmp_data(host: str, module_import: object, snmp_data: str) -> dict:
    logging.log(f'IP: {host["ip"]}\t{snmp_data}', module=module_info["name"], category=3, options={"debug": module_import.runtime_config.debug})
    
    if snmp_data is None:
        return host
    
    if "Siemens" in snmp_data:
        snmp_data_splited = snmp_data.split(",")
        host["device_info"] = host.get("device_info", {})
        host["device_info"].update({
            "Vendor": snmp_data_splited[0].strip(),
            "System Name": snmp_data_splited[1].strip(),
            "device version": snmp_data_splited[2].strip(),
            "Basic Hardware": snmp_data_splited[3].strip(),
            "Hardware version": snmp_data_splited[4].strip(),
            "Firmware Version": snmp_data_splited[5].strip(),
        })
        if len(snmp_data_splited) >= 7:
            host["device_info"]["serial number"] = snmp_data_splited[6].strip()
    elif "Rockwell" in snmp_data:
        host["network_info"] = host.get("network_info", {})
        host["network_info"]["network version"] = snmp_data
    
    return host
