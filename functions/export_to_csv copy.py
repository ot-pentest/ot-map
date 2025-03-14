import csv

def export_and_write_to_csv(data: dict, file: dict):
  with open(file, 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=["ID", "IP", "MAC", "Ports", "cpu state", "device version", "serial number", "Basic Hardware", "Firmware Version", "System Name", "Vendor", "Vulnerabilities"])
    writer.writeheader()
    for index, data_item in data.items():
      if "device_info" in data_item: 
        writer.writerow({
          'ID': index,
          'IP': data_item['ip'],
          'MAC': data_item['mac'],
          'Ports': '\n'.join(f"{port['Port']} ({port['Protocol']}, {port['State']})" for port in data_item['ports']),
          "cpu state": data_item['device_info'].get('cpu state', ''),
          "device version": data_item['device_info'].get('device version', ''),
          "serial number": data_item['device_info'].get('serial number', ''),
          "Basic Hardware": data_item['device_info'].get('Basic Hardware', ''),
          "Firmware Version": data_item['device_info'].get('Firmware Version', ''),
          "System Name": data_item['device_info'].get('System Name', ''),
          "Vendor": data_item['device_info'].get('Vendor', ''),
          "Vulnerabilities": '\n\n'.join(f"{vulnerability['Title']}: {vulnerability['Link']}" for vulnerability in data_item['vulnerabilities'])
        })
      else:
        writer.writerow({
          'ID': index,
          'IP': data_item['ip'],
          'MAC': data_item['mac'],
          'Ports': '\n'.join(f"{port['Port']} ({port['Protocol']}, {port['State']})" for port in data_item['ports']),
      })