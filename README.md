<img src="https://raw.githubusercontent.com/l4rm4nd/PyADRecon-ADWS/refs/heads/main/.github/pyadrecon.png" alt="pyadrecon" width="300"/>

A Python3 implementation of [PyADRecon](https://github.com/l4rm4nd/PyADRecon) using ADWS instead of LDAP for Pentesters, Red and Blue Teams

> PyADRecon is a tool which gathers information about MS Active Directory and generates an XSLX report to provide a holistic picture of the current state of the target AD environment.

>[!TIP]
>Queries Active Directory Web Services (ADWS) over TCP/9389 instead of LDAP to fly under the EDR radar.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Docker](#docker)
- [Collection Modules](#collection-modules)
- [HTML Dashboard](#html-dashboard)
- [Known Limitations](#known-limitations)
- [Acknowledgements](#acknowledgements)
- [License](#license)

## Installation

````bash
# stable release from pypi
pipx install pyadrecon-adws

# latest commit from github
pipx install git+https://github.com/l4rm4nd/PyADRecon-ADWS
````

Then verify installation:

````bash
pyadrecon_adws --version
````

> [!TIP]
> For Windows, may read [this](https://github.com/l4rm4nd/PyADRecon/tree/main/windows). Only NTLM authentication works on Windows atm.

## Usage

````py
usage: pyadrecon_adws.py [-h] [--version] [--generate-excel-from CSV_DIR] [-d DOMAIN] [-u USERNAME] [-p PASSWORD]
                         [-dc DOMAIN_CONTROLLER] [--port PORT] [--auth {ntlm,kerberos}] [--spn SPN]
                         [--workstation WORKSTATION] [-c COLLECT] [--only-enabled] [--page-size PAGE_SIZE]
                         [--dormant-days DORMANT_DAYS] [--password-age PASSWORD_AGE] [-o OUTPUT] [--no-excel]
                         [-v]

PyADRecon-ADWS # Active Directory Reconnaissance using ADWS

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --generate-excel-from CSV_DIR
                        Generate Excel report from existing CSV files (standalone mode)
  -d, --domain DOMAIN   Domain name (e.g., example.com)
  -u, --username USERNAME
                        Username (DOMAIN\user or user@domain.com)
  -p, --password PASSWORD
                        Password or LM:NTLM hash (will prompt if not provided)
  -dc, --domain-controller DOMAIN_CONTROLLER
                        Domain controller hostname or IP
  --port PORT           ADWS port (default: 9389)
  --auth {ntlm,kerberos}
                        Authentication method: ntlm or kerberos (default: ntlm)
  --spn SPN             Service Principal Name override (default: HTTP/dc.fqdn)
  --workstation WORKSTATION
                        NTLM authentication workstation name (default: random)
  -c, --collect COLLECT
                        Comma-separated modules to collect (default: all)
  --only-enabled        Only collect enabled users/computers
  --page-size PAGE_SIZE
                        ADWS query page size (default: 256)
  --dormant-days DORMANT_DAYS
                        Users/Computers with lastLogon older than X days are dormant (default: 90)
  --password-age PASSWORD_AGE
                        Users with pwdLastSet older than X days have old passwords (default: 180)
  -o, --output OUTPUT   Output directory (default: PyADRecon-Report-<timestamp>)
  --no-excel            Skip Excel export
  --no-dashboard        Skip interactive HTML dashboard generation  
  -v, --verbose         Enable verbose output

Examples:
  # Basic usage with NTLM authentication
  pyadrecon_adws.py -dc 192.168.1.1 -u admin -p password123 -d DOMAIN.LOCAL

  # With Kerberos authentication (only works on Linux with gssapi atm)
  pyadrecon.py -dc dc01.domain.local -u admin -p password123 -d DOMAIN.LOCAL --auth kerberos

  # Only collect specific modules
  pyadrecon_adws.py -dc 192.168.1.1 -u admin -p pass -d DOMAIN.LOCAL --collect users,groups,computers

  # Output to specific directory
  pyadrecon_adws.py -dc 192.168.1.1 -u admin -p pass -d DOMAIN.LOCAL -o /tmp/adrecon_output

  # Generate Excel report from existing CSV files (standalone mode)
  pyadrecon_adws.py --generate-excel-from /path/to/CSV-Files -o report.xlsx
````

## Docker

There is also a Docker image available on GHCR.IO.

````
docker run --rm -v /etc/krb5.conf:/etc/krb5.conf:ro -v /etc/hosts:/etc/hosts:ro -v ./:/tmp/pyadrecon_output ghcr.io/l4rm4nd/pyadrecon-adws:latest -dc dc01.domain.local -u admin -p password123 -d DOMAIN.LOCAL -o /tmp/pyadrecon_output
````

## Collection Modules

As default, PyADRecon-ADWS runs all collection modules. They are referenced to as `default` or `all`.

Though, you can freely select your own collection of modules to run:

| Icon | Meaning |
|------|---------|
| 🛑 | Requires administrative domain privileges (e.g. Domain Admins) |
| ✅ | Requires regular domain privileges (e.g. Authenticated Users) |
| 💥 | New collection modul in beta state. Results may be incorrect. |

**Forest & Domain**
- `forest` ✅
- `domain` ✅
- `trusts` ✅
- `sites` ✅
- `subnets` ✅
- `schema` or `schemahistory` ✅

**Domain Controllers**
- `dcs` or `domaincontrollers` ✅

**Users & Groups**
- `users` ✅
- `userspns` ✅
- `groups` ✅
- `groupmembers` ✅
- `protectedgroups` ✅💥
- `krbtgt` ✅
- `asreproastable` ✅
- `kerberoastable` ✅

**Computers & Printers**
- `computers` ✅
- `computerspns` ✅
- `printers` ✅

**OUs & Group Policy**
- `ous` ✅
- `gpos` ✅
- `gplinks` ✅

**Passwords & Credentials**
- `passwordpolicy` ✅
- `fgpp` or `finegrainedpasswordpolicy` 🛑
- `laps` 🛑
- `bitlocker` 🛑💥

**Managed Service Accounts**
- `gmsa` or `groupmanagedserviceaccounts` ✅💥
- `dmsa` or `delegatedmanagedserviceaccounts` ✅💥
  - Only works for Windows Server 2025+ AD schema

**Certificates**
- `adcs` or `certificates` ✅💥
  - Detects ESC1, ESC2, ESC3, ESC4 and ESC9

**DNS**
- `dnszones` ✅
- `dnsrecords` ✅

## HTML Dashboard

PyADRecon-ADWS will automatically create an HTML dashboard with important stats and security findings.

You may disable HTML dashboard generation via `--no-dashboard`.

>[!CAUTION]
> This is a beta feature. Displayed data may be falsely parsed or reported as issue. Take it with a grain of salt!

<img width="1209" height="500" alt="image" src="https://github.com/user-attachments/assets/e9500806-374d-4c69-a9a8-7f1540779266" />

<details>
<img width="1318" height="927" alt="image" src="https://github.com/user-attachments/assets/0760056c-963d-48fb-a252-fd082862bb01" />

<img width="1283" height="817" alt="image" src="https://github.com/user-attachments/assets/325197eb-8bd7-4aca-ac4e-c34b85057df1" />

<img width="1253" height="569" alt="image" src="https://github.com/user-attachments/assets/b6c4f94b-9da3-4a55-808d-23036181d02b" />
</details>

## Known Limitations

### Multi-Domain Forests – Security Descriptors
<details>
<summary><strong>Show details</strong></summary>

<br>

When querying **child domains** in a multi-domain forest, ADWS returns **incomplete security descriptors** for forest-wide objects like certificate templates.

**Issue:**
- Certificate template ACLs (enrollment rights, write permissions) may not show principals from the **child domain itself**
- Only parent domain principals will appear in enrollment rights
- This is an ADWS protocol limitation, not a PyADRecon-ADWS bug

**Example:**
- Querying from child domain (`child.domain.local`): Shows parent domain principals only  
- Querying from parent domain (`domain.local`): Shows all principals including child domain

**Solution:**
- For **complete certificate template ACL data**, connect to the **forest root domain controller** instead of a child DC

</details>

### Multi-Domain Forests – LDAP Referrals

<details>
<summary><strong>Show details</strong></summary>

<br>

When querying a **child domain** in a multi-domain forest, LDAP may return **referrals** for objects that reside in a different naming context (for example, the forest root domain).

**Issue:**
- Queries for forest-root objects (e.g., *Enterprise Admins*, *Schema Admins*, or root-domain users/groups) may return LDAP referrals
- PyADRecon does **not** chase LDAP referrals
- Referred objects are therefore **not collected automatically**

**Solution:**
- To ensure complete forest-wide enumeration, run PyADRecon separately against:
  - The **child domain**
  - The **forest root domain**
- Combine results manually if full forest visibility is required

</details>

## Acknowledgements

Many thanks to the following folks:
- [S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t) for a first Claude draft of PyADRecon using LDAP 
- [Sense-of-Security](https://github.com/sense-of-security) for the original ADRecon script in PowerShell
- [dirkjanm](https://github.com/dirkjanm) for the original ldapdomaindump script
- [mverschu](https://github.com/mverschu) for his port of ldapdomaindump using ADWS (adwsdomaindump). PyADRecon-ADWS heavily makes use of the ldap-to-adws wrapper.
- [Forta](https://github.com/fortra) for the awesome impacket suite
- [Anthropic](https://github.com/anthropics) for Claude LLMs

## License

**PyADRecon-ADWS** is released under the **MIT License**.

The following third-party libraries are used:

| Library     | License        |
|-------------|----------------|
| openpyxl    | MIT            |
| impacket    | Apache 2.0     |
| adwsdomaindump ADWS Wrapper | MIT         |

Please refer to the respective licenses of these libraries when using or redistributing this software.
