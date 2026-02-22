#!/usr/bin/env python3
"""Generate large test CSV files for dashboard performance testing"""

import csv
import random
from datetime import datetime, timedelta
import os

# Configuration
NUM_USERS = 10000
NUM_CERT_TEMPLATES = 10000
NUM_COMPUTERS = 10000
OUTPUT_DIR = "PyADRecon-ADWS-Report-20260222042207/CSV-Files"

# Sample data for realistic generation
FIRST_NAMES = ["John", "Jane", "Michael", "Sarah", "David", "Emily", "James", "Lisa", "Robert", "Jennifer", 
               "William", "Linda", "Richard", "Patricia", "Joseph", "Elizabeth", "Thomas", "Barbara", "Charles", "Susan",
               "Daniel", "Jessica", "Matthew", "Nancy", "Anthony", "Karen", "Mark", "Betty", "Donald", "Helen"]

LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
              "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
              "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson"]

DEPARTMENTS = ["IT", "HR", "Finance", "Sales", "Marketing", "Engineering", "Operations", "Legal", "Support", "Research"]
TITLES = ["Manager", "Director", "Analyst", "Engineer", "Administrator", "Specialist", "Coordinator", "Consultant", "Developer", "Technician"]
COMPANIES = ["Vulnad Corp", "TechCorp", "DataSystems", "SecureNet"]

CERT_TEMPLATE_TYPES = ["User", "Computer", "WebServer", "CodeSigning", "DomainController", "MachineEnrollment", 
                       "SubCA", "Administrator", "SmartcardUser", "IPSecIntermediateOffline", "DirectoryEmailReplication"]

EKU_OPTIONS = ["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.4", "1.3.6.1.4.1.311.10.3.4", "1.3.6.1.4.1.311.20.2.2",
               "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.3"]

ESC_VULNS = ["None", "ESC1", "ESC2", "ESC3", "ESC4", "ESC1, ESC3", "ESC2, ESC4"]
RISK_LEVELS = ["None", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

OS_VERSIONS = [
    "Windows Server 2019 Standard  10.0 (17763)",
    "Windows Server 2016 Standard  10.0 (14393)",
    "Windows Server 2022 Standard  10.0 (20348)",
    "Windows 11 Pro  10.0 (22631)",
    "Windows 10 Pro  10.0 (19045)",
    "Windows 10 Enterprise  10.0 (19044)",
    "Windows Server 2012 R2 Standard  6.3 (9600)",
]

COMPUTER_PREFIXES = ["WS", "DC", "SRV", "LAPTOP", "DESKTOP", "PC", "DEV", "TEST", "PROD", "APP"]


def random_date(start_year=2023, end_year=2026):
    """Generate random datetime"""
    start = datetime(start_year, 1, 1)
    end = datetime(end_year, 2, 22)
    delta = end - start
    random_days = random.randint(0, delta.days)
    return (start + timedelta(days=random_days)).strftime("%m/%d/%Y %I:%M:%S %p")

def generate_users_csv():
    """Generate Users.csv with 10k records"""
    print(f"Generating {NUM_USERS} user records...")
    
    users_file = os.path.join(OUTPUT_DIR, "Users.csv")
    
    # Read existing header
    with open(users_file, 'r') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        existing_users = list(reader)[:10]  # Keep first 10 real users
    
    with open(users_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        # Write existing users first
        for user in existing_users:
            writer.writerow(user)
        
        # Generate new users
        for i in range(NUM_USERS - len(existing_users)):
            first_name = random.choice(FIRST_NAMES)
            last_name = random.choice(LAST_NAMES)
            username = f"{first_name.lower()}.{last_name.lower()}{random.randint(1, 999)}"
            name = f"{first_name} {last_name}"
            
            enabled = random.choice(["True", "False"])
            never_logged = random.choice(["True", "False"])
            logon_age = "" if never_logged == "True" else str(random.randint(0, 365))
            password_age = str(random.randint(0, 900))
            dormant = "True" if (logon_age and int(logon_age) > 90) else "False"
            password_old = "True" if int(password_age) > 180 else "False"
            admin_count = random.choice(["", "1"]) if random.random() < 0.05 else ""
            
            has_spn = "True" if random.random() < 0.1 else "False"
            
            sid_base = random.randint(1200, 99999)
            
            row = {
                "UserName": username,
                "Name": name,
                "Enabled": enabled,
                "Must Change Password at Logon": random.choice(["True", "False"]),
                "Cannot Change Password": "False",
                "Password Never Expires": random.choice(["True", "False"]),
                "Reversible Password Encryption": "False",
                "Smartcard Logon Required": "False",
                "Delegation Permitted": "True",
                "Kerberos DES Only": "False",
                "Kerberos RC4": "Default",
                "Kerberos AES-128bit": "Default",
                "Kerberos AES-256bit": "Default",
                "Does Not Require Pre Auth": "False",
                "Never Logged in": never_logged,
                "Logon Age (days)": logon_age,
                "Password Age (days)": password_age,
                "Dormant (> 90 days)": dormant,
                "Password Age (> 180 days)": password_old,
                "Account Locked Out": "False",
                "Password Expired": "False",
                "Password Not Required": "False",
                "Delegation Type": "",
                "Delegation Protocol": "",
                "Delegation Services": "",
                "Logon Workstations": "",
                "AdminCount": admin_count,
                "Primary GroupID": "513",
                "SID": f"S-1-5-21-4178490863-1286169181-2994033663-{sid_base}",
                "SIDHistory": "",
                "HasSPN": has_spn,
                "Description": "",
                "Title": random.choice(TITLES) if random.random() < 0.7 else "",
                "Department": random.choice(DEPARTMENTS) if random.random() < 0.7 else "",
                "Company": random.choice(COMPANIES) if random.random() < 0.5 else "",
                "Manager": "",
                "Info": "Password123!" if random.random() < 0.01 else "",  # 1% have cleartext password
                "Last Logon Date": "" if never_logged == "True" else random_date(),
                "Password LastSet": random_date(),
                "Account Expiration Date": "",
                "Account Expiration (days)": "",
                "Mobile": "",
                "Email": f"{username}@vulnad.local" if random.random() < 0.8 else "",
                "HomeDirectory": "",
                "ProfilePath": "",
                "ScriptPath": "",
                "UserAccountControl": str(random.choice([512, 514, 66048, 66050])),
                "First Name": first_name,
                "Middle Name": "",
                "Last Name": last_name,
                "Country": "",
                "whenCreated": random_date(2024, 2026),
                "whenChanged": random_date(2024, 2026),
                "DistinguishedName": f"CN={name},CN=Users,DC=vulnad,DC=local",
                "CanonicalName": f"vulnad.local/Users/{name}"
            }
            
            writer.writerow(row)
    
    print(f"✓ Generated {users_file}")

def generate_cert_templates_csv():
    """Generate CertificateTemplates.csv with 10k records"""
    print(f"Generating {NUM_CERT_TEMPLATES} certificate template records...")
    
    cert_file = os.path.join(OUTPUT_DIR, "CertificateTemplates.csv")
    
    # Read existing header
    with open(cert_file, 'r') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        existing_certs = list(reader)[:5]  # Keep first 5 real templates
    
    with open(cert_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        # Write existing templates first
        for cert in existing_certs:
            writer.writerow(cert)
        
        # Generate new templates
        for i in range(NUM_CERT_TEMPLATES - len(existing_certs)):
            template_base = random.choice(CERT_TEMPLATE_TYPES)
            template_name = f"{template_base}Template{random.randint(1000, 99999)}"
            display_name = f"{template_base} Template {i+1}"
            
            enrollee_supplies = random.choice(["True", "False"])
            allows_san = random.choice(["True", "False"])
            exportable = random.choice(["True", "False"])
            requires_approval = random.choice(["True", "False"])
            
            # Determine ESC vulnerability based on risk factors
            esc_vuln = "None"
            risk_level = "None"
            risk_factors = "None"
            
            if random.random() < 0.15:  # 15% vulnerable
                esc_vuln = random.choice(["ESC1", "ESC2", "ESC3", "ESC4", "ESC1, ESC3"])
                risk_level = random.choice(["HIGH", "CRITICAL", "MEDIUM"])
                
                factors = []
                if enrollee_supplies == "True":
                    factors.append("Enrollee Supplies Subject")
                if allows_san == "True":
                    factors.append("SAN Allowed")
                if exportable == "True":
                    factors.append("Exportable Key")
                if not requires_approval or requires_approval == "False":
                    factors.append("No Manager Approval")
                    
                risk_factors = "; ".join(factors) if factors else "Configuration Risk"
            elif random.random() < 0.3:  # 30% low/medium risk
                risk_level = random.choice(["LOW", "MEDIUM"])
                risk_factors = random.choice(["Exportable Key", "SAN Allowed", "Auto-Enrollment Enabled"])
            
            row = {
                "Template Name": template_name,
                "Display Name": display_name,
                "Distinguished Name": f"CN={template_name},CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=vulnad,DC=local",
                "Owner": "Enterprise Admins",
                "Schema Version": str(random.choice([1, 2, 3, 4])),
                "Created": random_date(2023, 2024),
                "Modified": random_date(2024, 2026),
                "Extended Key Usage": ", ".join(random.sample(EKU_OPTIONS, random.randint(1, 3))),
                "Enrollee Supplies Subject": enrollee_supplies,
                "Allows SAN": allows_san,
                "Client Authentication": random.choice(["True", "False"]),
                "Any Purpose EKU": "False",
                "Enrollment Agent": "False",
                "Exportable Key": exportable,
                "Auto-Enrollment": random.choice(["True", "False"]),
                "Requires Manager Approval": requires_approval,
                "Authorized Signatures Required": "0",
                "Enrollment Flag": hex(random.choice([0x20, 0x29, 0x9])),
                "Certificate Name Flag": hex(random.choice([-0x5a000000, -0x7e000000])),
                "Private Key Flag": hex(random.choice([0x0, 0x10])),
                "Enrollment Rights": "Domain Admins; Domain Users; Enterprise Admins" if random.random() < 0.7 else "Domain Admins; Enterprise Admins",
                "Auto-Enrollment Rights": "None",
                "Write Permissions": "Domain Admins; Enterprise Admins",
                "ESC Vulnerabilities": esc_vuln,
                "Risk Level": risk_level,
                "Risk Factors": risk_factors
            }
            
            writer.writerow(row)
    
    print(f"✓ Generated {cert_file}")

def generate_computers_csv():
    """Generate Computers.csv with 10k records"""
    print(f"Generating {NUM_COMPUTERS} computer records...")
    
    comp_file = os.path.join(OUTPUT_DIR, "Computers.csv")
    
    # Read existing header
    with open(comp_file, 'r') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        existing_computers = list(reader)[:5]  # Keep first 5 real computers
    
    with open(comp_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        # Write existing computers first
        for comp in existing_computers:
            writer.writerow(comp)
        
        # Generate new computers
        for i in range(NUM_COMPUTERS - len(existing_computers)):
            prefix = random.choice(COMPUTER_PREFIXES)
            comp_name = f"{prefix}{random.randint(1000, 99999)}"
            username = f"{comp_name}$"
            dns_hostname = f"{comp_name.lower()}.vulnad.local"
            
            enabled = random.choice(["True", "False"])
            has_ip = random.random() < 0.8
            ipv4 = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}" if has_ip else ""
            
            logon_age = str(random.randint(0, 365))
            password_age = str(random.randint(0, 365))
            dormant = "True" if int(logon_age) > 90 else "False"
            password_old = "True" if int(password_age) > 180 else "False"
            
            os_version = random.choice(OS_VERSIONS)
            
            # Unconstrained delegation (risky)
            delegation_type = ""
            delegation_protocol = ""
            delegation_services = ""
            if random.random() < 0.05:  # 5% unconstrained
                delegation_type = "Unconstrained"
                delegation_protocol = "Kerberos"
                delegation_services = "Any"
            elif random.random() < 0.1:  # 10% constrained
                delegation_type = "Constrained"
                delegation_protocol = "Kerberos"
                delegation_services = "http/someserver"
            
            sid_base = random.randint(1200, 99999)
            primary_group = "516" if "DC" in comp_name or "SERVER" in comp_name.upper() else "515"
            uac = "532480" if delegation_type == "Unconstrained" else "4096"
            
            row = {
                "UserName": username,
                "Name": comp_name,
                "DNSHostName": dns_hostname,
                "Enabled": enabled,
                "IPv4Address": ipv4,
                "IPv6Address": "",
                "Operating System": os_version,
                "Logon Age (days)": logon_age,
                "Password Age (days)": password_age,
                "Dormant (> 90 days)": dormant,
                "Password Age (> 180 days)": password_old,
                "Delegation Type": delegation_type,
                "Delegation Protocol": delegation_protocol,
                "Delegation Services": delegation_services,
                "Primary Group ID": primary_group,
                "SID": f"S-1-5-21-4178490863-1286169181-2994033663-{sid_base}",
                "SIDHistory": "",
                "Description": "",
                "ms-ds-CreatorSid": "",
                "Last Logon Date": random_date(),
                "Password LastSet": random_date(),
                "UserAccountControl": uac,
                "whenCreated": random_date(2024, 2026),
                "whenChanged": random_date(2024, 2026),
                "Distinguished Name": f"CN={comp_name},CN=Computers,DC=vulnad,DC=local"
            }
            
            writer.writerow(row)
    
    print(f"✓ Generated {comp_file}")


if __name__ == "__main__":
    print("=" * 60)
    print("Generating large test datasets for dashboard testing")
    print("=" * 60)
    
    generate_users_csv()
    generate_cert_templates_csv()
    generate_computers_csv()
    
    print("\n✓ All test data generated successfully!")
    print(f"\nFiles created in: {OUTPUT_DIR}")
    print(f"  - Users.csv: {NUM_USERS} records")
    print(f"  - CertificateTemplates.csv: {NUM_CERT_TEMPLATES} records")
    print(f"  - Computers.csv: {NUM_COMPUTERS} records")
