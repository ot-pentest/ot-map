# OT-Map Scanner

OT-Map is a minimally invasive network scanner designed for operational technology (OT) environments. It detects Siemens and Allen-Bradley devices within your network and provides detailed information about each discovered device.

Additionally, OT-Map includes an integrated vulnerability scanning feature, currently supporting Siemens devices.

⚠️ Use with caution in production environments.

---

## Installation
Download the project

```bash
git clone https://github.com/ot-pentest/ot-map.git
```

Install dependencies from `requirements.txt`:

```bash
pip3 install -r requirements.txt
```

---

## Usage

Run OT-Map from the command line:

```bash
python main.py 192.168.0.0/24 --output json results.json [options]
```

### Options:

- **`--interface`**: Specify the network interface (e.g., eth0).
  ```bash
  python main.py 192.168.0.0/24 --interface eth0 --output json results.json
  ```

- **`--mode`**: Select the scanning mode:
  - **normal** *(default)*: Least invasive. Performs ARP scan to find IP addresses, then scans OT-specific ports.
  - **nmapx**: Comprehensive scan using Nmap scripts on all ports.
  - **vulnlookup**: Performs normal scan and additionally checks for known vulnerabilities (currently Siemens only).
  
  Example:
  ```bash
  python main.py 192.168.0.0/24 --mode vulnlookup --output json results.json
  ```

- **`--output`**: Save results to a file. Specify file type (`json` or `csv`) and file path. 
  ```bash
  python main.py 192.168.0.0/24 --output csv results.csv
  ```

- **`--debug`**: Enables verbose output for troubleshooting.

---

## Adding Devices for Vulnerability Scanning

To include new Siemens devices in vulnerability scans, update:

`assets/siemens_advisories_lookup_table.json`

Each entry has the following structure:

```json
"SCALANCE W786-1 RJ45": ["W700", "W-700"],
```

- **First value**: Device version displayed by the scanner.
- **Second and third values**: Keywords used to search in `assets/siemens_advisories.atom`.

### Example:

To test keywords for vulnerability scanning, use the `grep` command:

```bash
grep W786 assets/siemens_advisories.atom
```

If no results are returned, broaden your search:

```bash
grep W700 assets/siemens_advisories.atom
```

Then add a corresponding entry to the JSON file as shown above.

---

## Supported Devices
- Siemens
- Allen-Bradley
- Other devices for now only ip's and ports open

(Vulnerability scanning currently supports Siemens only.)

---

## TODO:
Automatic download of advisories.atom
See all cards in the rack and get info
Get more devices info from Beckhoff, Schneider and more

---

## Files used for this project 
vendorMac.xml from https://maclookup.app/downloads/cisco-vendor-macs-xml-database 
advisories.atom from https://cert-portal.siemens.com/productcert/rss/advisories.atom

---

## Contributing
Feel free to submit pull requests or open issues to improve OT-Map Scanner.

---

## License
GNU General Public License v3.0
