import xml.etree.ElementTree as ET
from datetime import datetime

NAMESPACE = "http://checklists.nist.gov/xccdf/1.2"

class Report(object):
    """docstring for Report"""

    def __init__(self, file):
        super(Report, self).__init__()

        # Fill data from the file name
        self.scan_id = file[-22:-4]
        self.date = datetime.strptime(file[-22:-8], "%d%m%Y%H%M%S")
        self.file = file

        # Parse the result XML file
        self.root = ET.parse(file).getroot()
        # Get references to the test results section since this is the only information
        # we care about
        self.test_results = self.root.findall(f"{{{NAMESPACE}}}TestResult")[0]
        self.defined_rules = self.test_results.findall(f"{{{NAMESPACE}}}rule-result")
        self.score = self.test_results.find(f"{{{NAMESPACE}}}score").text

        self.parse_rules = {}
        # Create a dictionary of all defined rules for later usage
        for rule in self.defined_rules:
            rule_name = rule.attrib["idref"]
            result = rule.find(f"{{{NAMESPACE}}}result").text
            self.parse_rules[rule_name] = result

        # Now get the pass/fail rules
        self.executed_rules = {}
        for rule in self.parse_rules:
            if self.parse_rules[rule] in ["pass", "fail"]:
                self.executed_rules[rule] = self.parse_rules[rule]

        # Get fail/pass rules
        self.passed_rules = len(
            [ r for r in self.executed_rules if "pass" in self.executed_rules[r]]
        )
        self.failed_rules = len(self.executed_rules) - self.passed_rules

    def __str__(self):
        return self.scan_id

    def get_scan_date(self):
        """
        Return the date of the scan result
        """
        return self.date

    def get_score(self):
        """
        Get the final score from the parsed XML
        """
        return self.score

    def get_executed_rules(self):
        """
        Get the filter number of rules pass/fail
        """
        return len(self.executed_rules)

    def get_passed_rules(self):
        """
        Get only pass number of rules
        """
        return self.passed_rules

    def get_failed_rules(self):
        """
        Get only fail number of rules
        """
        return self.failed_rules

    def get_raw_executed_rules(self):
        """
        Get a copy of the already parse rules dictionary
        """
        return self.executed_rules

    def print_summary(self):
        """ Print a summary of the report

        Parameters
        ----------
        self : Report
            Instance of this class
        """

        print(f"\nSummary statistics\n")
        print(f"\tID\t\t: {self.scan_id}")
        print(f"\tDate\t\t: {self.get_scan_date()}")
        print(f"\tSystem Score\t: {self.get_score()}")
        print(f"\tTotal Rules\t: {self.get_executed_rules()}")
        print(f"\t\tPassed\t: {self.get_passed_rules()}")
        print(f"\t\tFailed\t: {self.get_failed_rules()}")
