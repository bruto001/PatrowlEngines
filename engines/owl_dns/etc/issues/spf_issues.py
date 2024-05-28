# fmt: off
NO_SPF_RECORD = {
    "severity": "low",
    "confidence": "certain",
    "title": "No SPF record",
    "description": "An SPF (Sender Policy Framework) record defines the mail servers and domains that are allowed to "
                   "send email on behalf of your domain. It also tells receiving servers what to do with messages "
                   "after they're checked.",
    "solution": "List which servers are allowed to send email on behalf of your domain, and add an SPF record on that "
                "domain. If your domain doesn't send mail, this SPF record must be added: v=spf1 -all, or at least "
                "v=spf1 ~all",
}

# RFC 7208, Section 3.2
MULTIPLE_SPF_RECORDS = {
    "severity": "low",
    "confidence": "certain",
    "title": "Multiple SPF records",
    "description": "A domain name must not have multiple records that would cause an authorization check to select "
                   "more than one record (see RFC 7208, Section 3.2).",
    "solution": "Keep only one SPF record and delete the others: you should always update your SPF record, rather than "
                "creating a new record in addition to the existing one.",
}

# RFC 7208, Section 3.3
STRING_TOO_LONG = {
    "severity": "low",
    "confidence": "certain",
    "title": "String longer than 255 characters",
    "description": "A TXT record string cannot be longer than 255 characters (see RFC 7208, Section 3.3).",
    "solution": "A single TXT record can be composed of more than one string, which are useful in constructing "
                "records that would exceed the 255-octet maximum length of a character-string within a single TXT "
                "record.",
}

# RFC 7208, Section 4.6.4
DNS_LOOKUP_LIMIT = {
    "severity": "low",
    "confidence": "certain",
    "title": "High number of DNS lookup",
    "description": "The following terms cause DNS queries: the INCLUDE, A, MX, PTR, and EXISTS mechanisms, "
                   "and the REDIRECTS modifier. SPF implementations limits the total number of those terms to 10 "
                   "during SPF evaluation, to avoid unreasonable load on the DNS.",
    "solution": "Review and adjust if necessary."
}

# TODO: RFC 7208, Section 4.6.4
# ARS-437
#  In addition for MX mechanism, the evaluation of each "MX" record MUST NOT result in querying more than 10 address
#  records -- either "A" or "AAAA" resource records.

# TODO: RFC 7208, Section 4.6.4
# ARS-437
#  In addition for PTR mechanism, the evaluation of each "PTR" record MUST NOT result in querying more than 10 address
#  records -- either "A" or "AAAA" resource records.

# TODO: RFC 7208, Section 4.6.4
# ARS-437
#  SPF implementations SHOULD limit "void lookups" to two (DNS queries return either a positive answer (RCODE 0) with an
#  answer count of 0, or a "Name Error" (RCODE) answer.

# RFC 7208, Section 5.1
DIRECTIVES_AFTER_ALL = {
    "severity": "low",
    "confidence": "certain",
    "title": "Directives after ALL not allowed",
    "description": "Mechanisms after ALL will never be tested and are ignored by mail servers (see RFC 7208, "
                   "Section 5.1).",
    "solution": "Be sure to insert all desired tags before the ~all stipulation or the ensuing text will be "
                "disregarded.",
}

# RFC 7208, Section 5.5
PRESENCE_OF_PTR = {
    "severity": "low",
    "confidence": "certain",
    "title": "Mechanism PTR not recommended",
    "description": "Use of PTR is discourage, because it is slow and not as reliable as other mechanisms in cases "
                   "of DNS errors, and it places a large burden on the .arpa name servers (see RFC 7208, "
                   "Section 5.5). Besides, several senders may ignore the SPF record when this mechanism is used.",
    "solution": "Alternatives mechanisms should be used instead. If used, proper PTR records have to be in place for "
                "the domain's hosts and the PTR mechanism should be one of the last mechanisms checked.",
}

# RFC 7208, Section 14.1
DEPRECATED_SPF_RECORD = {
    "severity": "low",
    "confidence": "certain",
    "title": "Deprecated SPF record",
    "description": "SPF (Sender Policy Framework) records must now only be published as a TXT resource record type, "
                   "with code 16, and not with formerly supported SPF resource record type, with code 99 (see RFC "
                   "7208, Section 14.1).",
    "solution": "Change SPF resource record type (code 99) to TXT resource record (code 16).",
}

# Custom issues / Best practices

# Malformed SPF record
# - extra space before the start of the string
# - extra space after the end of the string
# - surrounded by quotation marks
# - illegal mechanisms
MALFORMED_SPF_RECORD = {
    "severity": "low",
    "confidence": "certain",
    "title": "Malformed SPF record"
}

# Permissive SPF record
# - +all or just all
# - ?all
PERMISSIVE_SPF_RECORD = {
    "severity": "low",
    "confidence": "certain",
    "title": "Permissive SPF record",
    "description": "An SPF record is interpreted from left to right, the all mechanism will match all senders that "
                   "did not match the preceding mechanisms. Therefore, you should place the all mechanism at the end "
                   "of the SPF record, and use it with the ~ (softfail) or - (fail) prefix. Do note that if no prefix "
                   "is set, the + (pass) is used by default. This setup is  discouraged.",
    "solution": "Use more strict mechanism like '-all', or '~all' if you do not feel ready yet."
}

# Missing end of record, with ALL mechanism or REDIRECT modifier
MISS_SPF_RECORD_TERMINATION = {
    "severity": "low",
    "confidence": "certain",
    "title": "Miss SPF record termination",
    "description": "An SPF record should conclude with either an 'all' mechanism or a 'redirect' modifier."
}

# fmt: on
