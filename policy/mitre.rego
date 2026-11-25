package security.mitre

import rego.v1

import data.security.metadata

# Base risk threshold
base_threshold := 80

# Deny if any MITRE finding meets the threshold in prod.
# Environment comes from the analyzer metadata block.
deny contains msg if {
  some f in input.mitre_findings

  threshold := base_threshold
  input.metadata.environment == "prod"
  f.risk_score >= threshold

  msg := sprintf(
    "[Policy %s][%s] MITRE technique(s) %v risk %d exceeds threshold",
    [metadata.policy_version, input.metadata.environment, f.mitre_techniques, f.risk_score]
  )
}
