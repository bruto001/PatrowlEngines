import unittest
from unittest import mock

from engines.owl_dns.engine_owl_dns import (
    _dns_resolve_asset,
    _parse_spf_record,
    get_lookup_count_and_spf_records,
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
            [dict(spf_issues.NO_SPF_RECORD, extra_info="There is no DNS TXT record.")],
        )

    def test_parse_spf_record_with_no_spf_record(self):
        # Arrange
        dns_records = ['"BLA-BLA-BLA"', '"BLA-BLA-BLA-2"']

        # Act and Assert
        result, issues = _parse_spf_record(dns_records=dns_records)

        self.assertCountEqual(
            issues,
            [
                dict(
                    spf_issues.NO_SPF_RECORD,
                    extra_info=f"Other DNS TXT records are: {', '.join(dns_records)}.",
                )
            ],
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
            [
                dict(
                    spf_issues.MULTIPLE_SPF_RECORDS,
                    extra_info=f"Other DNS TXT records are: {', '.join(dns_records)}.",
                )
            ],
        )

    def test_parse_spf_record_with_directive_after_all(self):
        # Arrange
        dns_records = [
            '"v=spf1 ~all include:spf.protection.outlook -all"',
        ]

        # Act and Assert
        result, issues = _parse_spf_record(dns_records=dns_records)

        self.assertCountEqual(
            issues,
            [
                dict(
                    spf_issues.DIRECTIVES_AFTER_ALL,
                    value="v=spf1 ~all include:spf.protection.outlook -all",
                    extra_info='These directives after "all" are ignored: include:spf.protection.outlook -all.',
                )
            ],
        )

    def test_parse_spf_record_with_string_too_long(self):
        # Arrange
        dns_records = [
            '"v=spf1 include:spf.protection.outlook include:veryloooooooooooooooooooooooooooooooooooooooooooooooooooooo'
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
                    value="v=spf1 include:spf.protection.outlook include:verylooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooog -all",
                    extra_info="This part is 510 characters long, and therefore too long: v=spf1 include:spf.protection"
                    ".outlook include:veryloooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog -all.",
                )
            ],
        )

    def test_parse_spf_record_with_multiple_strings_too_long(self):
        # Arrange
        dns_records = [
            '"v=spf1 include:spf.protection.outlook include:veryloooooooooooooooooooooooooooooooooooooooooooooooooooooo'
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
                    value="v=spf1 include:spf.protection.outlook include:verylooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "ooooooooooooooooooooog -all",
                    extra_info="This part is 256 characters long, and therefore too long: ooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
                    "ooooooooooooooooooooooooog -all.",
                )
            ],
        )

    def test_parse_spf_record_with_multiple_correct_strings_length(self):
        # Arrange
        dns_records = [
            '"v=spf1 include:spf.protection.outlook include:veryloooooooooooooooooooooooooooooooooooooooooooooooooooooo'
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

    @mock.patch("dns.resolver.Resolver.resolve")
    def test_check_dns_lookup_limit_less_than_10(self, mock_resolve):
        # Arrange
        mock_resolve.side_effect = [
            [
                '"v=spf1 include:spf.protection.outlook.com include:servers.mcsv.net include:7593890.spf10.hubspotemail.net -all"'
            ],
            [
                '"v=spf1 ip4:40.92.0.0/15 ip4:40.107.0.0/16 ip4:52.100.0.0/14 ip4:104.47.0.0/17 ip6:2a01:111:f400::/48 ip6:2a01:111:f403::/49 ip6:2a01:111:f403:8000::/51 ip6:2a01:111:f403:c000::/51 ip6:2a01:111:f403:f000::/52 -all"'
            ],
            [
                '"v=spf1 ip4:205.201.128.0/20 ip4:198.2.128.0/18 ip4:148.105.8.0/21 -all"'
            ],
            [
                '"v=spf1 ip4:3.93.157.0/24 ip4:3.210.190.0/24 ip4:18.208.124.128/25 ip4:54.174.52.0/24 ip4:54.174.57.0/24 ip4:54.174.59.0/24 ip4:54.174.60.0/23 ip4:54.174.63.0/24 ip4:108.179.144.0/20 ip4:139.180.17.0/24 ip4:141.193.184.32/27 ip4:141.193.184.64/26 ip4:141.193.184.128/25 ip4:141.193.185.32/27 ip4:141.193.185.64/26 ip4:141.193.185.128/25 ip4:143.244.80.0/20 ip4:158.247.16.0/20 -all "'
            ],
        ]

        # Act
        dns_lookup_count, spf_lookup_records = get_lookup_count_and_spf_records(
            domain="patrowl.io"
        )

        # Assert
        self.assertEqual(dns_lookup_count, 3)

    @mock.patch("dns.resolver.Resolver.resolve")
    def test_check_dns_lookup_limit_recursion_error(self, mock_resolve):
        # Arrange (5000 DNS lookup)
        mock_resolve.side_effect = [
            ['"v=spf1 include:spf.protection.outlook.com -all"'] for _ in range(5000)
        ]
        # Assert
        self.assertRaises(
            RecursionError,
            lambda: get_lookup_count_and_spf_records(domain="patrowl.io"),
        )

    def test_parse_spf_record_with_extra_spaces_before_the_start_of_the_string(self):
        # Arrange
        dns_records = ['" v=spf1 include:spf.protection.outlook -all"']

        # Act and Assert
        result, issues = _parse_spf_record(dns_records=dns_records)

        self.assertCountEqual(
            issues,
            [
                dict(
                    spf_issues.MALFORMED_SPF_RECORD,
                    value=" v=spf1 include:spf.protection.outlook -all",
                    extra_info="There is an extra space before the start of the string.",
                )
            ],
        )

    def test_parse_spf_record_with_extra_spaces_after_the_end_of_the_string(self):
        # Arrange
        dns_records = ['"v=spf1 include:spf.protection.outlook -all "']

        # Act and Assert
        result, issues = _parse_spf_record(dns_records=dns_records)

        self.assertCountEqual(
            issues,
            [
                dict(
                    spf_issues.MALFORMED_SPF_RECORD,
                    value="v=spf1 include:spf.protection.outlook -all ",
                    extra_info="There is an extra space after the end of the string.",
                )
            ],
        )

    def test_parse_spf_record_surrounded_by_quotation_marks(self):
        # Arrange
        dns_records = ['""v=spf1 include:spf.protection.outlook -all""']

        # Act and Assert
        result, issues = _parse_spf_record(dns_records=dns_records)

        self.assertCountEqual(
            issues,
            [
                dict(
                    spf_issues.MALFORMED_SPF_RECORD,
                    value='"v=spf1 include:spf.protection.outlook -all"',
                    extra_info="The SPF record is surrounded quotation marks.",
                )
            ],
        )

    def test_parse_spf_record_with_illegal_term(self):
        # Arrange
        dns_records_1 = [
            '"v=spf1 include:spf.protection.outlook includes:spf.protection.outlook -all"'
        ]

        # Act
        result_1, issues_1 = _parse_spf_record(dns_records=dns_records_1)

        # Assert
        self.assertCountEqual(
            issues_1,
            [
                dict(
                    spf_issues.MALFORMED_SPF_RECORD,
                    value="v=spf1 include:spf.protection.outlook includes:spf.protection.outlook -all",
                    extra_info="'includes' is an illegal term.",
                )
            ],
        )

        # Arrange
        dns_records_2 = ['"v=spf1 include:spf.protection.outlook -alll"']

        # Act
        result_2, issues_2 = _parse_spf_record(dns_records=dns_records_2)

        # Assert
        self.assertCountEqual(
            issues_2,
            [
                dict(
                    spf_issues.MALFORMED_SPF_RECORD,
                    value="v=spf1 include:spf.protection.outlook -alll",
                    extra_info="'alll' is an illegal term.",
                )
            ],
        )

    def test_parse_spf_record_with_uppercase(self):
        # Arrange
        dns_records = ['"V=SPF1 InClUdE:spf.protection.outlook -All"']

        # Act
        result, issues = _parse_spf_record(dns_records=dns_records)

        # Assert
        self.assertCountEqual(
            issues,
            [],
        )

    def test_parse_spf_record_with_permissive_all(self):
        # Arrange
        dns_records_1 = ['"v=spf1 include:spf.protection.outlook all"']

        # Act
        result_1, issues_1 = _parse_spf_record(dns_records=dns_records_1)

        # Assert
        self.assertCountEqual(
            issues_1,
            [
                dict(
                    spf_issues.PERMISSIVE_SPF_RECORD,
                    value="v=spf1 include:spf.protection.outlook all",
                )
            ],
        )

        # Arrange
        dns_records_2 = ['"v=spf1 include:spf.protection.outlook +all"']

        # Act
        result_2, issues_2 = _parse_spf_record(dns_records=dns_records_2)

        # Assert
        self.assertCountEqual(
            issues_2,
            [
                dict(
                    spf_issues.PERMISSIVE_SPF_RECORD,
                    value="v=spf1 include:spf.protection.outlook +all",
                )
            ],
        )

        # Arrange
        dns_records_3 = ['"v=spf1 include:spf.protection.outlook ?all"']

        # Act
        result_3, issues_3 = _parse_spf_record(dns_records=dns_records_3)

        # Assert
        self.assertCountEqual(
            issues_3,
            [
                dict(
                    spf_issues.PERMISSIVE_SPF_RECORD,
                    value="v=spf1 include:spf.protection.outlook ?all",
                )
            ],
        )

    def test_parse_spf_record_without_spf_record_termination(self):
        # Arrange
        dns_records = ['"v=spf1 include:spf.protection.outlook"']

        # Act
        result, issues = _parse_spf_record(dns_records=dns_records)

        # Assert
        self.assertCountEqual(
            issues,
            [
                dict(
                    spf_issues.MISS_SPF_RECORD_TERMINATION,
                    value="v=spf1 include:spf.protection.outlook",
                )
            ],
        )

    def test_parse_spf_record_with_all_spf_record_termination(self):
        # Arrange
        dns_records = ['"v=spf1 include:spf.protection.outlook -all"']

        # Act
        result, issues = _parse_spf_record(dns_records=dns_records)

        # Assert
        self.assertCountEqual(
            issues,
            [],
        )

    def test_parse_spf_record_with_redirect_spf_record_termination(self):
        # Arrange
        dns_records = ['"v=spf1 redirect=_spf.facebook.com"']

        # Act
        result, issues = _parse_spf_record(dns_records=dns_records)

        # Assert
        self.assertCountEqual(
            issues,
            [],
        )


if __name__ == "__main__":
    unittest.main()
