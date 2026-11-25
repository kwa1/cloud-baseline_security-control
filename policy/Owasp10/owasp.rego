package security.owasp

import rego.v1

import data.security.metadata

# Approved CVE exceptions are read from data.exceptions (loaded via --data exceptions/).
# Only findings whose exception has not expired are exempt.
approved_cve(id) if {
  some e in data.exceptions.exceptions
  e.vulnerability_id == id
  e.expires_at > time.now_ns()
}

# Map a finding's description to an OWASP Top 10 (2021) category.
owasp_category(vuln) := "A03:2021-Injection" if {
  desc := lower(vuln.Description)
  some pattern in ["sql injection", "command injection", "rce"]
  contains(desc, pattern)
}

owasp_category(vuln) := "A06:2021-Vulnerable and Outdated Components" if {
  desc := lower(vuln.Description)
  some pattern in ["unpatched", "library"]
  contains(desc, pattern)
}

owasp_category(vuln) := "A05:2021-Security Misconfiguration" if {
  desc := lower(vuln.Description)
  some pattern in ["misconfiguration", "default password"]
  contains(desc, pattern)
}

owasp_category(vuln) := "A01:2021-Broken Access Control" if {
  desc := lower(vuln.Description)
  some pattern in ["privilege escalation", "unauthorized"]
  contains(desc, pattern)
}

deny contains msg if {
  some result in input.Results
  some vuln in result.Vulnerabilities

  not approved_cve(vuln.VulnerabilityID)

  category := owasp_category(vuln)

  msg := sprintf(
    "[Policy %s] OWASP Violation: %s in %s triggers %s (Severity: %s)",
    [metadata.policy_version, vuln.VulnerabilityID, result.Target, category, vuln.Severity]
  )
}
