# PyADRecon-ADWS on Windows

A guide for running **PyADRecon-ADWS** on Windows systems using either the pre-built executable or Python.

---

## Table of Contents

- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Installation Methods](#installation-methods)
  - [Using Pre-built Executable](#using-pre-built-executable)
  - [Running with Python](#running-with-python)
  - [Building Your Own Executable](#building-your-own-executable)
- [Output](#output)
- [Troubleshooting](#troubleshooting)
- [Help](#help)

---

## Requirements

### System Requirements
- Windows 10/11 or Windows Server
- Python 3.11 (x64) - only if running from source

### Network Requirements

The following ports must be accessible on the Domain Controller:

| Service | Port | Protocol | Required For |
|---------|------|----------|--------------|
| ADWS | 9389 | TCP | Unencrypted LDAP (as fall-back) |
| DNS | 53 | TCP/UDP | Name resolution / Kerberos SPNs |

### Additional Requirements
- Working DNS resolution for DC hostname/FQDN
- Time synchronization between client and DC (within a few minutes for Kerberos)

---

## Quick Start

### Using the pre-built executable

```powershell
.\pyadrecon_adws.exe -dc 10.10.10.10 -d vulnad.local -u john -p "P@ssw0rd"
```

> [!NOTE]
> NTLM authentication works with DC IP addresses or hostnames.

---

## Installation Methods

### Using Pre-built Executable

No installation required. Simply download and run `pyadrecon_adws.exe`.

See [Quick Start](#quick-start) for usage examples.

---

### Running with Python

For development, testing, or custom builds.

#### Step 1: Install Python

```powershell
winget install -e --id Python.Python.3.11
```

Verify installation:
```powershell
py -V
py -V:3.11 -c "import sys; print(sys.version)"
```

#### Step 2: Clone the repository

```powershell
cd C:\Temp
git clone https://github.com/l4rm4nd/PyADRecon-ADWS.git
cd PyADRecon-ADWS
```

#### Step 3: Create virtual environment

```powershell
py -V:3.11 -m venv .venv
.\.venv\Scripts\activate
python -m pip install -U pip setuptools wheel
```

#### Step 4: Install dependencies

Using `requirements.txt`:
```powershell
python -m pip install -r .\requirements.txt
```

Or from `pyproject.toml`:
```powershell
python -m pip install .
```

#### Step 5: Run PyADRecon-ADWS

**NTLM:**
```powershell
python .\pyadrecon_adws.py -dc 10.10.10.10 -d vulnad.local -u john -p "P@ssw0rd"
```

---

### Building Your Own Executable

Use PyInstaller to create a standalone executable.

#### Step 1: Install PyInstaller

```powershell
.\.venv\Scripts\activate
python -m pip install -U pyinstaller
```

#### Step 2: Build the executable

```powershell
pyinstaller --onefile --name pyadrecon_adws --clean pyadrecon_adws.py
```

#### Step 3: Test the executable

Output location: `dist\pyadrecon_adws.exe`

```powershell
.\dist\pyadrecon_adws.exe --help
```

---

## Output

PyADRecon generates a timestamped output directory:

```
PyADRecon-ADWS-Report-YYYYMMDDHHMMSS\
```

Contents:
- CSV files for each module
- Excel report (unless `--no-excel` is specified)

---

## Troubleshooting

### DNS resolution fails

**Problem:** The DC hostname does not resolve.

**Solutions:**

1. Configure your DNS to use the AD DNS server/DC
2. Add a hosts file entry:

Edit `C:\Windows\System32\drivers\etc\hosts`:
```text
10.10.10.10 dc1.vulnad.local dc1
```

---

## Help

Display all available options:

```powershell
.\pyadrecon_adws.exe --help
```

Or with Python:
```powershell
python .\pyadrecon_adws.py --help
```
