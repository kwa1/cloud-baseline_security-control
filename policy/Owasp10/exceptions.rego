package owasp.exceptions

import rego.v1

default allowed := false

allowed if {
  some exception in data.exceptions.exceptions
  exception.owasp == input.finding.owasp
  valid_date(exception.expires)
  not expired(exception.expires)
}

# Fail closed: an exception is expired when its date is on or before today (UTC).
# ISO-8601 dates (YYYY-MM-DD) compare correctly as strings.
expired(date) if {
  today := sprintf("%04d-%02d-%02d", time.date(time.now_ns()))
  date <= today
}

# Only well-formed YYYY-MM-DD values can grant an exception.
valid_date(date) if regex.match(`^\d{4}-\d{2}-\d{2}$`, date)
