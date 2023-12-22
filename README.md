# Project Assessment
ScanSTIG
## About
ScanSTIG is a wrapper command line tool based on Python3 for the already existing **oscap** program [1].

This tool runs scans with STIG and other profiles defined in the "scap-security-guide" [2] package for Oracle Linux 8 system and saves critical data of the scan in JSON-formatted under the user's home directory ~/.scan_stig.

[1][https://docs.oracle.com/en/operating-systems/oracle-linux/8/oscap/oscap_information_and_reference.html#topic_wwd_2qf_m5b](https://docs.oracle.com/en/operating-systems/oracle-linux/8/oscap/oscap_information_and_reference.html#topic_wwd_2qf_m5b)
[2][https://docs.oracle.com/en/operating-systems/oracle-linux/8/oscap/oscap-CheckingComplianceWithOSCAP.html#sect-scan](https://docs.oracle.com/en/operating-systems/oracle-linux/8/oscap/oscap-CheckingComplianceWithOSCAP.html#sect-scan)

## Getting started
Before using the tool, it is required to download the git project and move to the project source directory where the Python tool (scan_stig.py) is located:

> git clone https://github.com/EduVaca/Project_Assessment.git
> cd Project_Assessment/src

The tool is made based on two Python3 scripts: scan_stig.py, which is the main program (described in more detail below), and the Report class (src/oscap/scan/report.py), which is a representation of the obtained scan reports performed by oscap.

## Uses cases
### Default Scanning
Running a scan command without any parameters, the tool will perform a default scanning over the running system with the STIG profile from the "scap-security-guide."

> python3 scan_stig.py scan

If the scan runs without any issues, it will generate and print a Scan ID (18-digit string) to the standard output, which can be used to print the scan summary or compare it with previous scans.

### Scan with a different profile
You can scan the system with all the different profiles defined in "scap-security-guide." If a different profile not defined in the "scap-security-guide" is passed as an argument, then the tool will show up a message error, and the scan won't be performed.

Security profiles can be passed either in short or long names.

Example to run a scan with the profile "Standard System Security Profile for Oracle Linux 8"

> python3 scan_stig.py scan -p xccdf_org.ssgproject.content_profile_standard

or

> python3 scan_stig.py scan -p standard

### List scans
To get a list of previous scans stored in the current system, run the following:

> python3 scan_stig.py list

This command will print in the standard output a list of previous scan IDs, which can be used to print summary statistics or compare them against each other.

### Print summary statistics
To print summary statistics of a previous scan ID, run the following command:

> python3 scan_stig.py print [ID]

Where ID (with brackets) is a previous scan ID obtained from a scan or list command.
Additionally, you can list all rules defined in the scan profile (-a, -all) or failed rules (-f, --failed).

For more information, print the help:

> python3 scan_stig.py --help

### Compare two scan IDs
You can compare two scan previous scan IDs to get summary statistics regarding both scans and get a comparison between rules passed or failed in one scan and another. Also, to see rules defined only in one of the profiles:

> python3 scan_stig.py compare [ID1] [ID2]

### Get extra help
You can get more help on the tool usage by printing it with the command

> python3 scan_stig.py --help

This will show you all the available commands and subcommands the tool supports.