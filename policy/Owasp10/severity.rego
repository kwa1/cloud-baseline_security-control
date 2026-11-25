package owasp.severity

import rego.v1

default blocked_categories := []

blocked_categories := ["A03", "A05", "A06"] if {
  input.environment == "prod"
}

blocked_categories := ["A03", "A05"] if {
  input.environment == "staging"
}

blocked_categories := [] if {
  input.environment == "dev"
}
