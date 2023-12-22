""" Report class that represents an XCCDF result.xml

This class respresent the content of an XCCDF result.xml for ease usage of
the scan_stig tool.

Typical usage example:

  report = Report()
  report.print_summary()
"""

import xml.etree.ElementTree as ET
from datetime import datetime

NAMESPACE = "http://checklists.nist.gov/xccdf/1.2"

class Report():
    """ This class represents the result of a profile evaluation performed OpenSCAP

    Attributes
    ----------
    scan_id : str
        first name of the person
    date : str
        family name of the person
    score : str
        age of the person
    rules : dict

    Methods
    -------
    get_scan_date() :
        Returns the date of the report
    get_score() :
        Returns the score of the report
    get_raw_rules() :
        Returns the rules evaluated in the report
    print_all_rules():
        Print all rules in the report with its result
    get_passed_rules() :
        Returns the passed rules in the report
    get_failed_rules() :
        Returns the failed rules in the report
    print_failed_rules():
        Print all failed rules in the report
    print_summary() :
        Print a summary of the report results
    """

    def __init__(self, file):
        """ Constructs all the necessary attributes for the report object.

        Parameters
        ----------
            file : str
                XML file with XCCDF results of a previous scan
        """

        # Fill data from the file name
        self.scan_id = file[-22:-4]
        self.date = datetime.strptime(file[-22:-8], "%d%m%Y%H%M%S")

        # Parse the result XML file
        self._root = ET.parse(file).getroot()
        # Get references to the test results section since this is the only information
        # we care about
        self._test_results = self._root.findall(f"{{{NAMESPACE}}}TestResult")[0]
        self._defined_rules = self._test_results.findall(f"{{{NAMESPACE}}}rule-result")
        self.score = self._test_results.find(f"{{{NAMESPACE}}}score").text

        self.rules = {}
        # Create a dictionary of all defined rules for later usage
        for rule in self._defined_rules:
            rule_name = rule.attrib["idref"]
            result = rule.find(f"{{{NAMESPACE}}}result").text
            if not "notselected" in result:
                self.rules[rule_name] = result

    def __str__(self):
        """ Built-in method to print the object as a string

        Parameters
        ----------
        None

        Returns
        -------
        scan_id : str
            Scan ID
        """
        return self.scan_id

    def get_scan_date(self):
        """ Returns the date of the report

        Parameters
        ----------
        None

        Returns
        -------
        date : str
            Date of the report
        """
        return self.date

    def get_score(self):
        """ Returns the score of the report

        Parameters
        ----------
        None

        Returns
        -------
        score : score
            The score of the report
        """
        return self.score

    def get_raw_rules(self):
        """ Returns the rules evaluated in the report

        Parameters
        ----------
        None

        Returns
        -------
        rules : dic
            A dictionary with all the rules defined for a profile except notselected
        """
        return self.rules

    def print_all_rules(self):
        """ Print all rules in the report with its result

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        print(f"\nAll rules results ({len(self.rules)})\n")
        for rule, result in self.rules.items():
            print(f"\tRule\t: {rule}")
            print(f"\tResult\t: {result}")

    def get_passed_rules(self):
        """ Returns the passed rules in the report

        Parameters
        ----------
        None

        Returns
        -------
        list : list
            A list of all passed rules
        """
        return [ key for key, value in self.rules.items() if value == "pass" ]

    def get_failed_rules(self):
        """ Returns the failed rules in the report

        Parameters
        ----------
        None

        Returns
        -------
        list : list
            A list of all failed rules
        """
        return [ key for key, value in self.rules.items() if value == "fail" ]

    def print_failed_rules(self):
        """ Print all failed rules in the report

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        print(f"\nSummary of failed rules ({len(self.get_failed_rules())})\n")
        for rule in self.get_failed_rules():
            print(f"\tRule\t: {rule}")

    def print_summary(self):
        """ Print a summary of the report results

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        print("\nSummary statistics\n")
        print(f"\tID\t\t: {self.scan_id}")
        print(f"\tDate\t\t: {self.get_scan_date()}")
        print(f"\tSystem Score\t: {self.get_score()}")
        print(f"\tTotal Rules\t: {len(self.get_raw_rules())}")
        print(f"\t\tPassed\t: {len(self.get_passed_rules())}")
        print(f"\t\tFailed\t: {len(self.get_failed_rules())}")
