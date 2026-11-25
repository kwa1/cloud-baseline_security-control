package security.exceptions

import rego.v1

default allow := false

allow if {
  some e in data.exceptions.exceptions
  e.vulnerability_id == input.VulnerabilityID
  e.expires_at > time.now_ns()
}
