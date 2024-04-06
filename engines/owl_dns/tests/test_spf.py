import unittest
import unittest.mock as mock

from engines.owl_dns.engine_owl_dns import (
    _dns_resolve_asset,
    _parse_spf_record,
)


class TestSPF(unittest.TestCase):
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
                },
            ],
        )

    def test_parse_spf_record_with_no_spf_record(self):
        # Arrange
        dns_record = "BLA-BLA-BLA"

        # Act and Assert
        with self.assertRaises(ValueError) as cm:
            _parse_spf_record(dns_record=dns_record)

        self.assertEqual(str(cm.exception), "Do not contains SPF records")

    def test_parse_spf_record_with_directive_after_all(self):
        # Arrange
        dns_records = [
            "v=spf1 +all include:spf.protection.outlook",
            "v=spf1 ~all include:spf.protection.outlook",
            "v=spf1 -all include:spf.protection.outlook",
        ]

        # Act and Assert
        for dns_record in dns_records:
            result, issues = _parse_spf_record(dns_record=dns_record)

            self.assertCountEqual(
                issues,
                [
                    {
                        "title": 'Directives after "all" are not allowed',
                        "description": '"all" directive is used as the rightmost directive in a record to provide an '
                        'explicit default.Directives after "all" are ignored and will never be tested.',
                    }
                ],
            )

    def test_parse_spf_record_with_simple_spf_record(self):
        # Arrange: set up the mock with a random string as a DNS record
        dns_record = "v=spf1 include:spf.protection.outlook.com -all"

        # Act and Assert
        result = _parse_spf_record(dns_record=dns_record)

        self.assertDictEqual(
            result, {"include": ["spf.protection.outlook.com"], "all": []}
        )


if __name__ == "__main__":
    unittest.main()
