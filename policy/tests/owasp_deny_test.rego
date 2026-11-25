package owasp.deny_test

import rego.v1

import data.owasp.deny

finding := {"owasp": "A06", "package": "libfoo", "severity": "HIGH"}

test_prod_blocks_unexempted_a06 if {
  count(deny.deny) == 1 with input as {"environment": "prod", "findings": [finding]}
    with data.exceptions.exceptions as []
}

test_dev_allows_a06 if {
  count(deny.deny) == 0 with input as {"environment": "dev", "findings": [finding]}
    with data.exceptions.exceptions as []
}

test_active_exception_suppresses_a06 if {
  count(deny.deny) == 0 with input as {"environment": "prod", "findings": [finding]}
    with data.exceptions.exceptions as [{"owasp": "A06", "expires": "2999-01-01"}]
}

test_expired_exception_does_not_suppress if {
  count(deny.deny) == 1 with input as {"environment": "prod", "findings": [finding]}
    with data.exceptions.exceptions as [{"owasp": "A06", "expires": "2020-01-01"}]
}

test_malformed_expiry_fails_closed if {
  count(deny.deny) == 1 with input as {"environment": "prod", "findings": [finding]}
    with data.exceptions.exceptions as [{"owasp": "A06", "expires": "2999/01/01"}]
}
