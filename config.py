default_interface = 'eth0'
default_duration = 60
default_siemens_advisories = ["assets/advisories.atom", "assets/siemens_advisories_lookup_table.json"]
default_siemens_advisories_local = ""
default_modes = ["normal"]

modes = {
  "normal": ["arp", "nmap", "snmp", "ab_info", "sSeven"], # arp, nmap, snmp, ab info, s7
  "nmapx": ["arp", "nmapX", "snmp", "ab_info", "sSeven"],
  "vulnlookup": ["arp", "nmap", "snmp", "ab_info", "sSeven", "checkSiemensAdvisories"],
}
