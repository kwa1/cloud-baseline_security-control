package security.environment

import rego.v1

import data.security.metadata

deny contains msg if {
  not input.environment
  msg := "Environment not provided to policy engine"
}

deny contains msg if {
  not input.environment in metadata.required_environment
  msg := sprintf(
    "Invalid environment '%s'. Allowed: %v",
    [input.environment, metadata.required_environment]
  )
}
