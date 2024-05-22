spf_issues = {
    "deprecated_spf_record": {"title": "Deprecated SPF record"},
    "invalid_spf_record": {"title": "Invalid SPF record"},
    "over_lookup": {},
}

# Require the SPF record in the DNS so that it can validate it.
# SPF records must be published as a DNS TXT (type 16) Resource Record (RR) [RFC1035]. See RFC7208 for further detail.
NO_SPF_RECORD = {
    "severity": "low",
    "confidence": "certain",
    "title": "No SPF record",
    "description": "",
    "solution": "",
}

# Check for multiple SPF records. It is not permitted to publish multiple SPF records.
# RFC 7208, Section 3.3:
MULTIPLE_SPF_RECORDS = {
    "severity": "low",
    "confidence": "certain",
    "title": "Multiple SPF records",
    "description": "A domain name must not have multiple records that would cause an authorization check to select "
    "more than one record.",
    "solution": "",
}

# Check the SPF string length. It has a 255-character string limit.
STRING_TOO_LONG = {
    "severity": "low",
    "confidence": "certain",
    "title": "Character-string too long",
    "description": "",
    "solution": "",
}

#  	Number of void lookups is OK.
# The void lookup limit was introduced in RFC 7208 and refers to DNS lookups which either return an empty response (NOERROR with no answers) or an NXDOMAIN response. This is a separate count from the 10 DNS lookup overall count.
#
# As described at the end of Section 11.1, there may be cases where it is useful to limit the number of "terms" for which DNS queries return either a positive answer (RCODE 0) with an answer count of 0, or a "Name Error" (RCODE 3) answer. These are sometimes collectively referred to as "void lookups". SPF implementations SHOULD limit "void lookups" to two. An implementation MAY choose to make such a limit configurable. In this case, a default of two is RECOMMENDED. Exceeding the limit produces a "permerror" result.
#
# This is meant to help prevent erroneous or malicious SPF records from contributing to a DNS-based denial of service attack.
#  	Number of lookups is OK. (10)
# When using SPF, it's only possible to perform 10 (nested) DNS lookups.


# 	Too Many MX Resource Records

# Check whether the PTR mechanism is used. It's not advised to use PTR as this is a deprecated one, and several senders may ignore the SPF record when this method is used.
# RFC 7208, Section 5.5: PTR mechanism SHOULD NOT be published. This mechanism is slow, it is not as reliable as other
#    mechanisms in cases of DNS errors, and it places a large burden on
#    the .arpa name servers.  If used, proper PTR records have to be in
#    place for the domain's hosts and the "ptr" mechanism SHOULD be one of
#    the last mechanisms checked.  After many years of SPF deployment
#    experience, it has been concluded that it is unnecessary and more
#    reliable alternatives should be used instead.  It is, however, still
#    in use as part of the SPF protocol, so compliant check_host()
#    implementations MUST support it.
# Your domain's SPF record includes a sender mechanism type of PTR. The use of this mechanism is heavily discouraged per RFC4408 as it is slow and unreliable. Per email delivery best practices, it is advisable to avoid including PTR type mechanisms in your SPF record.
#
# RFC 4408 states:
# "Use of this mechanism is discouraged because it is slow, it is not as reliable as other mechanisms in cases of DNS errors, and it places a large burden on the arpa name servers. If used, proper PTR records must be in place for the domain's hosts and the "ptr" mechanism should be one of the last mechanisms checked."
PRESENCE_OF_PTR = {
    "severity": "low",
    "confidence": "certain",
    "title": 'Mechanism "ptr" not recommended',
    "description": "",
    "solution": "",
}

# The record is valid.
# No deprecated records found.
# The domain has published the SPF record in a DNS type "SPF".
#  The use of alternative DNS RR types that was formerly supported during the experimental phase of SPF was discontinued in 2014. SPF records must now only be published as a DNS TXT (type 16) Resource Record (RR) [RFC1035]. See RFC 7208 for further detail on this change.
DEPRECATED_SPF_RECORD = {
    "severity": "low",
    "confidence": "certain",
    "title": "Deprecated SPF record",
    "description": "",
    "solution": "",
}


# Check for the "+all" mechanism. That means that anyone can send an email on your behalf. This setup is discouraged.

# No items after the 'all' mechanism.
# RFC 7208, Section 5.1: Mechanisms after "all" will never be tested. Mechanisms listed after "all" MUST be ignored.
#  This alert means that you have a delivery problem due to a misconfigured SPF record. Tthere are one (1) or more tags after the "all" indicator in your SPF record. All of those tags that fall after the "all" tag are currently being ignored by mail servers. For example, if you have a record such as:
#
# v=spf1 ip4:1.2.3.4 ip4: 1.2.3.7 include:spf.example.com ~ all include:spf2.microsoft.com
#
# The include: spf2.microsoft.com will be IGNORED because it falls after the "all" tag. Therefore, per RFC 7208 Section 5.1, be sure to insert all desired tags before the ~all stipulation or the ensuing text will be disregarded.
DIRECTIVES_AFTER_ALL = {
    "severity": "low",
    "confidence": "certain",
    "title": 'Directives after "all" not allowed',
    "description": '"all" directive is used as the rightmost directive in a record to provide an explicit default. '
    'Directives after "all" are ignored and will never be tested.',
    "solution": "",
}
