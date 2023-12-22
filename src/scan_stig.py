#!/bin/env python3

""" Command line tool for regular "openscap" scans

Command line tool for regular "openscap" [1] scans of the Oracle Linux 8
system using available "stig" profile from the "scap-security-guide" package [2].

Command line tool provides following features:

    * Execute scan and print scan ID report in the standar output
    * List history of executed scans
    * Print scan report by scan id available from the history
    * Compare two scan reports available from the history by scan ids:
        Print following:
            Summary statistics for scan1 (id/total/passed/failed)
            Summary statistics for scan2 (id/total/passed/failed)
            Summary statistics for fixed/introduced results diff between scan1 and scan2

Usage:

    * Scan
        python3 scan_stig.py scan
    * list
        python3 scan_stig.py list
    * print
        python3 scan_stig.py print ID
    * compare
        python3 scan_stig.py compare ID1 ID2

Resources:

[1]https://docs.oracle.com/en/operating-systems/oracle-linux/8/oscap/\
oscap_information_and_reference.html#topic_wwd_2qf_m5b
[2]https://docs.oracle.com/en/operating-systems/oracle-linux/8/oscap/\
oscap-CheckingComplianceWithOSCAP.html#sect-scan

"""

###############################################################################################

import os
import re
import sys
import glob
import logging
import argparse
import subprocess

from datetime import datetime
from oscap.scan.report import Report

###############################################################################################
VERBOSE = False

SCAP_SEC_TOOL = "scap-security-guide"
STIG_PROFILE = "xccdf_org.ssgproject.content_profile_stig"
DATA_STREAM_LOC = "/usr/share/xml/scap/ssg/content/ssg-ol8-ds.xml"
SCAN_STIG_HOME_DIR = os.path.expanduser("~/.scan_stig")

# Set logger
logging.basicConfig(
    stream=sys.stdout,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

# Give it the program name
logger = logging.getLogger("scan_stig")
#logger.setLevel(logging.DEBUG)

###############################################################################################

def validate_id(scan_id):
    """ Helper function to validate a given scan ID meets the build syntaxis

    The syntaxis for a valid scan ID is as follows:

        Date : %d%m%Y - 8 digits
            %d - Day of the month as a zero-padded decimal number.
            %m - Month as a zero-padded decimal number.
            %Y - Year with century as a decimal number.

        Time : %H%M%S - 6 digits
            %H - Hour (24-hour clock) as a zero-padded decimal number.
            %M - Minute as a zero-padded decimal number.
            %S - Second as a zero-padded decimal number.

        Consecutive number : #### - 4 digits
            Number from 0000 to 9999 taken.

    Parameters
    ----------
    scan_id : str
        Scan ID string made of date, time, and a consecutive number.

    Returns
    -------
    scan_id : str
        A valid scan ID
    """

    date_time = "%d%m%Y%H%M%S"

    msg = """
    Scan ID must be in the format ddmmYYHHMMSS###

    The syntaxis for a valid scan ID is as follows:

    Date : %d%m%Y - 8 digits
        %d - Day of the month as a zero-padded decimal number.
        %m - Month as a zero-padded decimal number.
        %Y - Year with century as a decimal number.

    Time : %H%M%S - 6 digits
        %H - Hour (24-hour clock) as a zero-padded decimal number.
        %M - Minute as a zero-padded decimal number.
        %S - Second as a zero-padded decimal number.

    Consecutive number : #### - 4 digits
        Number from 0000 to 9999 taken.
    """

    # Check only for numbers and lenght
    if not scan_id.isnumeric() or len(scan_id) != 18:
        raise argparse.ArgumentTypeError(msg)

    # Check for a valid date
    try:
        # strptime does not check for zero-padded on month and day so double check it.
        if scan_id[:14] != datetime.strptime(scan_id[:14], date_time).strftime(date_time):
            raise argparse.ArgumentTypeError(msg)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(msg) from exc

    return scan_id

###############################################################################################

def get_results(lam=None, func=filter):
    """ Helper function to get a list of available reults

    First, it looks for valid file names with an 18 digit xml ending pattern.
    Lastly, it applies the passed lambda function to return only the interested values
    so that the caller gets a list that it can  work with it without exceptions
    on the formatting.

    Parameters
    ----------
    lam : lambda
        A lambda function to apply to the obtained list

    func : function
        A function to filter/map the obtained list

    Returns
    -------
    list : list
        List of found result IDs
    """

    # Do a quick filter for filenames with an 18 digit xml ending pattern
    regx = re.compile(r"_[0-9]{18}\.xml")
    results = list(filter(regx.search, glob.glob(f"{SCAN_STIG_HOME_DIR}/result_*.xml")))

    logger.debug("Filtered results: %s", results)

    # If nothing to do, then return the list as it is
    if lam is None:
        return results

    # Return the list with the appropiate filter/map
    return list(func(lam, results))


###############################################################################################

def print_scan_compare_summary(report1, report2):
    """ Print a compare summary of two existing oscap report

    Parameters
    ----------
    report1 : Report
        Report object to compare
    report2 : Report
        Report object to compare

    Returns
    -------
    None
    """

    if VERBOSE:
        print("print_scan_compare_summary")
    logger.info("print_scan_compare_summary")

    rules1 = report1.get_raw_rules()
    rules2 = report2.get_raw_rules()

    print("\nDiff summary statistics")
    # Get rules that only lives in the first report
    print(f"\n\tExtra rules ID({report1})")
    check = 1
    for rule in rules1:
        if not rule in rules2:
            print(f"\t\tRule\t: {rule}")
            check = 0
    if check:
        print("\t\tNone")

    # Get rules that only lives in the second report
    print(f"\n\tExtra rules ID({report2})")
    check = 1
    for rule in rules2:
        if not rule in rules1:
            print(f"\t\tRule\t: {rule}")
            check = 0
    if check:
        print("\t\tNone")
        check = 1

    # Get rules that lives in both reports with different results
    print("\n\tUnmatching results for the same rule")
    check = 1
    for rule in rules1:
        if rule in rules2 and rules1[rule] != rules2[rule]:
            print(f"\t\tRule\t: {rule}")
            print(f"\t\tID({report1})\t: {rules1[rule]}")
            print(f"\t\tID({report2})\t: {rules2[rule]}")
            print()
            check = 0
    if check:
        print("\t\tNone")
        check = 1

###############################################################################################

def get_new_scan_id(now):
    """ Get from configuration directory the latest scan ID

    Get the latest scan ID of the current date plus one and return it,
    if none scan ID in the current date is found, then start from 0000

    Parameters
    ----------
    now : str
        String with the current date

    Returns
    -------
    id : str
        A 4 digit consecutive number based on the last scan ID
    """

    if VERBOSE:
        print("get_new_scan_id")
    logger.info("get_new_scan_id")

    results = get_results(lambda x: int(x[-8:-4]) if now in x else 0, map)

    logger.debug(results)

    if results:
        # Sort reverse the list and get the first element, then sum one and fill it with
        # zeros so it can be taken as the full ID
        results.sort(reverse=True)
        last_id = results[0] + 1
        return str(last_id).zfill(4)

    return "0000"

###############################################################################################

def validate_system():
    """ Checks if all needed packages to run this tool are available

    Parameters
    ----------
    None

    Returns
    -------
    exit_code : int
        0 : The tool can run on this system
        1 : The tool cannot run on this system
    """

    if VERBOSE:
        print("validate_system")
    logger.info("validate_system")

    # Check for scap-security-guide suit which depens on oscap
    exit_code = subprocess.call(
        ["rpm", "-q", SCAP_SEC_TOOL],
        stdout = (
            subprocess.DEVNULL if logger.level >= logging.INFO or not VERBOSE else None
            ),
        stderr = (
            subprocess.DEVNULL if logger.level >= logging.INFO or not VERBOSE else None
            )
    )

    if exit_code != 0:
        print(f"Package {SCAP_SEC_TOOL} is not installed")
        return 1

    # Check for Oracle Linux Server 8
    is_ol8 = False
    logger.debug("Inspecting OS")
    with open("/etc/os-release", "r", encoding="UTF-8") as file:
        is_ol8 = False
        for line in file:
            line = line.replace("\n", "")
            logger.debug(line)
            if "platform:el8" in line:
                if VERBOSE:
                    print(f"validate_system : {line}")
                logger.info("validate_system : %s", line)
                is_ol8 = True
                break

    if is_ol8 is False:
        print("This tool is designed for Oracle Linux Server 8")
        return 1

    return exit_code

###############################################################################################

def set_environment():
    """ Prepare the system for execution

    Parameters
    ----------
    None

    Returns
    -------
    None
    """

    if VERBOSE:
        print("set_environment")
    logger.info("set_environment")

    os.makedirs(SCAN_STIG_HOME_DIR, exist_ok=True)

###############################################################################################

def run_scan():
    """ Execute scan and print scan report in the output

    Executes a scan using the STIG profile and save the report and results
    for further analysis.

    Parameters
    ----------
    args : list
        List of passed arguments to the tool

    Returns
    -------
    exit_code : int
        0 : All rules passed
        1 : Something went wrong during evaluation
        2 : Rules failed or unknown results
    """
    if VERBOSE:
        print("run_scan")
    logger.info("run_scan")

    # Get the starting date
    now = datetime.now().strftime("%d%m%Y%H%M%S")

    if VERBOSE:
        print(f"Current date is : {now}")
    logger.debug("Current date is : %s", now)

    scan_id = get_new_scan_id(now[:8])

    # Let oscap remove the files if they already exists
    tmp_result = f"/tmp/result_{now}{scan_id}.xml"
    tmp_report = f"/tmp/report_{now}{scan_id}.html"

    print(f"Scan ID : {now}{scan_id}")
    # Form the command to scan the system using the STIG profile
    cmd = [
        "oscap", "xccdf", "eval", "--profile", STIG_PROFILE,
        "--results", tmp_result, "--report", tmp_report, DATA_STREAM_LOC
    ]

    logger.debug("cmd : %s", cmd)

    # We don't care about STDOUT/
    exit_code = subprocess.call(cmd,
        stdout = (
            subprocess.DEVNULL if logger.level >= logging.INFO or not VERBOSE else None
            ),
        stderr = (
            subprocess.DEVNULL if logger.level >= logging.INFO or not VERBOSE else None
            )
    )

    logger.debug("exit_code : %d", exit_code)

    # All rules passed
    if exit_code == 0:
        print(f"All rules defined for {STIG_PROFILE} were passed")
    # Something went wrong during evaluation
    elif exit_code == 1:
        print("oscap evaluation went wrong")
    # Rules failed or unknown results
    else:
        print(f"Some rules defined for {STIG_PROFILE} were not passed")

    # Save scan
    if exit_code != 1:
        os.rename(tmp_result, tmp_result.replace("/tmp", SCAN_STIG_HOME_DIR))
        os.rename(tmp_report, tmp_report.replace("/tmp", SCAN_STIG_HOME_DIR))

    return exit_code

###############################################################################################

def list_scans(args):
    """ List history of executed scans printing scan ids

    Parameters
    ----------
    args : list
        List of passed arguments to the tool

        args.all    : Print all rules and results for each report
        args.failed : Print all failed rules for each report

    Returns
    -------
    int : int
        0 : One or more scan IDs were found
        1 : None scan IDs were found
    """
    if VERBOSE:
        print("list_scans")
    logger.info("list_scans")

    if args.all or args.failed:
        results = get_results()
    else:
        results = get_results(lambda x: x[-22:-4], map)


    logger.debug(results)

    if results:
        print(f"{len(results)} scan IDs were found:")
        results.sort()
        for result in results:
            if args.all:
                report = Report(result)
                print(f"\nRerpot ID : {report}")
                report.print_all_rules()
            elif args.failed:
                report = Report(result)
                print(f"\nRerpot ID : {report}")
                report.print_failed_rules()
            else:
                print(f"\t{result}")
        return 0

    print("Scan IDs not found")
    return 1

###############################################################################################

def print_scan(args):
    """ Print scan report by scan id available from the history

    Parameters
    ----------
    args : list
        List of passed arguments to the tool

        args.id[0]  : Scan ID to print
        args.all    : Print all rules and results
        args.failed : Print all failed rules

    Returns
    -------
    int : int
        0 : Scan ID was found and printed
        1 : Scan ID was not found
    """

    scan_id = args.id[0]

    if VERBOSE:
        print(f"print_scan : {scan_id}")
    logger.info("print_scan : %s", scan_id)

    result = get_results(lambda x: scan_id in x)

    if VERBOSE:
        print(f"Scan IDs found : {len(result)}")
    logger.debug("Scan IDs found : %d", len(result))
    logger.debug(result)

    if len(result) == 1:
        report = Report(result[0])
        report.print_summary()
        if args.all:
            report.print_all_rules()
        if args.failed:
            report.print_failed_rules()
        return 0

    print(f"Scan id {scan_id} was not found")
    return 1

###############################################################################################

def compare_scans(args):
    """ Compare two scan reports available from the history by scan ids.

    Print following:
        Summary statistics for scan 1 (id/total/passed/failed)
        Summary statistics for scan 2 (id/total/passed/failed)
        Summary statistics for fixed/introduced results diff between scan 1 and scan 2

    Parameters
    ----------
    args : list
        List of passed arguments to the tool

        args.id1[0] : Scan ID to compare
        args.id2[0] : Scan ID to compare

    Returns
    -------
    int : int
        0 : Scan IDs were found and printed
        1 : One or more scan IDs were not found
    """

    scan_id1 = args.id1[0]
    scan_id2 = args.id2[0]

    if VERBOSE:
        print(f"compare_scans : {scan_id1} {scan_id2}")
    logger.info("compare_scans : %s %s", scan_id1, scan_id2)

    result1 = ""
    result2 = ""

    for result in get_results(lambda x: scan_id1 in x or scan_id2 in x):
        if scan_id1 in result:
            result1 = result
        if scan_id2 in result:
            result2 = result

    if not result1:
        print(f"Scan id {scan_id1} was not found")
        return 1
    if not result2:
        print(f"Scan id {scan_id2} was not found")
        return 1

    report1 = Report(result1)
    report2 = Report(result2)

    report1.print_summary()
    report2.print_summary()

    # Make the magic here for both reports
    print_scan_compare_summary(report1, report2)
    return 0

###############################################################################################

def create_parser():
    """ Create an argument parser for the program

    Parameters
    ----------
    None

    Returns
    -------
    parser : ArgumentParser
        Program argument parser
    """

    description = """
Command line tool for regular "openscap" scans of the Oracle Linux 8 system using
available "stig" profile from the "scap-security-guide" package.
"""

    epilog = """
The following commands are supported:

    scan
       Scan the current system agaist the STIG profile.

       If the scan is performed correctly, an 18 digits scan ID is printed in
       the standard output for future references.

    list
       List history of executed scan IDs.

       -f, --failed  Print all failed rules in all the reports available
       -a, --all     Print all rules in all the reports available

    print [id]
       Print a given scan ID report.

       -f, --failed  Print failed rules
       -a, --all     Print all rules

    compare [id1, id2]
       Compare two given scan ID reports.
       

"""

    argparser = argparse.ArgumentParser(description = description[1:],
                                     epilog = epilog[1:],
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     add_help = False)

    argparser.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS,
                        help="Show this help message and exit")

    argparser.add_argument("-v", "--verbose", default=False, action='store_true',
                        help="Verbose (print extra useful information)")

    subparser = argparser.add_subparsers(help="Commands\n")

    # Scan system against STIG profile
    parser_scan = subparser.add_parser("scan", help="Scan the current system agaist the \
        STIG profile")
    parser_scan.set_defaults(action="scan", func=run_scan)

    # List a previous scan IDs in the system
    parser_list = subparser.add_parser("list", help="List previous scans in the system")
    parser_list.add_argument(
        "-f", "--failed", default=False, action='store_true', help="Print all \
        failed rules in all the reports available"
        )
    parser_list.add_argument(
        "-a", "--all", default=False, action='store_true', help="Print all rules \
        in all the reports available"
        )
    parser_list.set_defaults(action="list", func=list_scans)

    # Print a given scan ID
    parser_print = subparser.add_parser("print", help="Print the given scan ID")
    parser_print.add_argument("id", nargs=1, type=validate_id, help="Scan ID to print")
    parser_print.add_argument(
        "-f", "--failed", default=False, action='store_true', help="Print failed rules"
        )
    parser_print.add_argument(
        "-a", "--all", default=False, action='store_true', help="Print all rules"
        )
    parser_print.set_defaults(action="print", func=print_scan)

    # Print two given scan IDs
    parser_compare = subparser.add_parser("compare", help="Compare and print two given \
        scan IDs")
    parser_compare.add_argument("id1", nargs=1, type=validate_id, help="Scan ID to \
        compare")
    parser_compare.add_argument("id2", nargs=1, type=validate_id, help="Scan ID to \
        compare")
    parser_compare.set_defaults(action="compare", func=compare_scans)

    return argparser

###############################################################################################

if __name__ == '__main__':
    # Main program

    # Create the program arguments parser
    parser = create_parser()

    if not sys.argv[1:]:
        parser.print_usage()
        print("\nUse the -h or --help flag for more detailed information")
        sys.exit(1)

    settings = parser.parse_args(args=sys.argv[1:])

    if settings.verbose:
        VERBOSE = settings.verbose

    # Check for dependencies
    if validate_system() != 0:
        sys.exit(2)

    # Prepare the environment
    set_environment()

    if settings.action == "scan":
        EXIT_CODE = settings.func()
    elif settings.action == "list":
        EXIT_CODE = settings.func(settings)
    elif settings.action == "print":
        EXIT_CODE = settings.func(settings)
    elif settings.action == "compare":
        EXIT_CODE = settings.func(settings)
    else:
        EXIT_CODE = 3

    sys.exit(EXIT_CODE)

###############################################################################################
