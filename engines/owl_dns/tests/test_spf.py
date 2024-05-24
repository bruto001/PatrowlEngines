import unittest
from unittest import mock

from engines.owl_dns.engine_owl_dns import (
    _dns_resolve_asset,
    _parse_spf_record,
)
from engines.owl_dns.etc.issues import spf_issues


class TestSPF(unittest.TestCase):
    maxDiff = None

    @mock.patch("dns.resolver.Resolver.resolve")
    def test_dns_resolve_asset(self, mock_resolve):
        # Arrange: set up the mock with a random SPF record
        mock_resolve.return_value = ['"v=spf1 include:spf.protection.outlook.com -all"']

        # Act
        dns_records = _dns_resolve_asset("patrowl.io", "TXT")

        # Assert
        mock_resolve.assert_called_with("patrowl.io", "TXT")
        self.assertCountEqual(
            dns_records,
            [
                {
                    "record_type": "TXT",
                    "values": ["v=spf1 include:spf.protection.outlook.com -all"],
                    "answers": ['"v=spf1 include:spf.protection.outlook.com -all"'],
                },
            ],
        )

    def test_parse_spf_record_with_no_dns_record(self):
        # Arrange
        dns_records = []

        # Act and Assert
        result, issues = _parse_spf_record(dns_records=dns_records)

        self.assertCountEqual(
            issues,
            [spf_issues.NO_SPF_RECORD],
        )

    def test_parse_spf_record_with_no_spf_record(self):
        # Arrange
        dns_records = ['"BLA-BLA-BLA"', '"BLA-BLA-BLA-2"']

        # Act and Assert
        result, issues = _parse_spf_record(dns_records=dns_records)

        self.assertCountEqual(
            issues,
            [spf_issues.NO_SPF_RECORD],
        )

    def test_parse_spf_record_with_multiple_spf_records(self):
        # Arrange
        dns_records = [
            '"v=spf1 include:spf.protection.outlook -all"',
            '"v=spf1 include:_spf.google.com ~all"',
            '"v=spf1 redirect=_spf.facebook.com"',
        ]

        # Act and Assert
        result, issues = _parse_spf_record(dns_records=dns_records)

        self.assertCountEqual(
            issues,
            [spf_issues.MULTIPLE_SPF_RECORDS],
        )

    def test_parse_spf_record_with_directive_after_all(self):
        # Arrange
        dns_records = [
            '"v=spf1 +all include:spf.protection.outlook"',
        ]

        # Act and Assert
        result, issues = _parse_spf_record(dns_records=dns_records)

        self.assertCountEqual(
            issues,
            [
                dict(
                    spf_issues.DIRECTIVES_AFTER_ALL,
                    value="v=spf1 +all include:spf.protection.outlook",
                    extra_info='These directives after "all" are ignored: include:spf.protection.outlook',
                )
            ],
        )

    def test_parse_spf_record_with_string_too_long(self):
        # Arrange
        dns_records = [
            '"v=spf1 include:spf.protection.outlook veryloooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo'
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            'oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog -all"',
        ]

        # Act and Assert
        result, issues = _parse_spf_record(dns_records=dns_records)

        self.assertCountEqual(
            issues,
            [
                dict(
                    spf_issues.STRING_TOO_LONG,
                    value="v=spf1 include:spf.protection.outlook verylooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooog -all",
                    extra_info="This part is 510 characters long, and therefore too long: v=spf1 include:spf.protection"
                    ".outlook veryloooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog -all",
                )
            ],
        )

    def test_parse_spf_record_with_multiple_strings_too_long(self):
        # Arrange
        dns_records = [
            '"v=spf1 include:spf.protection.outlook veryloooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo'
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            'oooooooooooooooooooooooooooooooooooooooooooo" "ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo'
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            'ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog -all"',
        ]

        # Act and Assert
        result, issues = _parse_spf_record(dns_records=dns_records)

        self.assertCountEqual(
            issues,
            [
                dict(
                    spf_issues.STRING_TOO_LONG,
                    value="v=spf1 include:spf.protection.outlook verylooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "ooooooooooooooooooooog -all",
                    extra_info="This part is 256 characters long, and therefore too long: ooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "ooooooooooooooooooooooooog -all",
                )
            ],
        )

    def test_parse_spf_record_with_multiple_correct_strings_length(self):
        # Arrange
        dns_records = [
            '"v=spf1 include:spf.protection.outlook veryloooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo'
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            'oooooooooooooooooooooooooooooooooooooooooooo" "ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo'
            "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
            'oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog -all"',
        ]

        # Act and Assert
        result, issues = _parse_spf_record(dns_records=dns_records)

        self.assertCountEqual(
            issues,
            [],
        )

    def test_parse_spf_record_with_ptr_mechanism(self):
        # Arrange
        dns_records = ['"v=spf1 include:spf.protection.outlook ptr -all"']

        # Act and Assert
        result, issues = _parse_spf_record(dns_records=dns_records)

        self.assertCountEqual(
            issues,
            [
                dict(
                    spf_issues.PRESENCE_OF_PTR,
                    value="v=spf1 include:spf.protection.outlook ptr -all",
                )
            ],
        )

    def test_parse_spf_record_with_simple_spf_record(self):
        # Arrange: set up the mock with a random string as a DNS record
        dns_record = "v=spf1 include:spf.protection.outlook.com -all"

        # Act and Assert
        result, issues = _parse_spf_record(dns_records=[dns_record])

        self.assertDictEqual(
            result, {"include": ["spf.protection.outlook.com"], "all": []}
        )


if __name__ == "__main__":
    unittest.main()
