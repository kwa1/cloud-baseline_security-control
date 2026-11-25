package security.sbom

import rego.v1

import data.security.metadata

# SBOM must be CycloneDX
deny contains msg if {
  input.bomFormat != "CycloneDX"
  msg := sprintf(
    "[Policy %s] SBOM must be CycloneDX format",
    [metadata.policy_version]
  )
}

# SBOM must have components
deny contains msg if {
  count(input.components) == 0
  msg := sprintf(
    "[Policy %s] SBOM contains no components",
    [metadata.policy_version]
  )
}

# Root component metadata required
deny contains msg if {
  not input.metadata.component
  msg := sprintf(
    "[Policy %s] SBOM missing root component metadata",
    [metadata.policy_version]
  )
}
