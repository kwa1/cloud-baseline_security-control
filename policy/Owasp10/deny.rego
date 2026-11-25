package owasp.deny

import rego.v1

import data.owasp.severity.blocked_categories
import data.owasp.metadata.owasp_categories
import data.owasp.exceptions.allowed
import data.owasp.controls.owasp_to_controls

# Blocks only findings that have an upstream fix. A finding with no fix cannot be remediated by
# upgrading, so it is reported (see warn) rather than blocking the build.
deny contains msg if {
  some finding in input.findings
  finding.owasp in blocked_categories
  object.get(finding, "fixed_version", "") != ""

  not allowed with input.finding as finding

  controls := owasp_to_controls[finding.owasp]

  msg := sprintf(
    "OWASP %s (%s) blocked | ISO=%v | NIST=%v | Package=%s | Severity=%s",
    [
      finding.owasp,
      owasp_categories[finding.owasp],
      controls.iso,
      controls.nist,
      finding.package,
      finding.severity
    ]
  )
}

# Reported, non-blocking: blocked-category findings that have no upstream fix.
warn contains msg if {
  some finding in input.findings
  finding.owasp in blocked_categories
  object.get(finding, "fixed_version", "") == ""

  not allowed with input.finding as finding

  msg := sprintf(
    "OWASP %s (%s) has no upstream fix; reported, not blocking | Package=%s | Severity=%s",
    [finding.owasp, owasp_categories[finding.owasp], finding.package, finding.severity]
  )
}
