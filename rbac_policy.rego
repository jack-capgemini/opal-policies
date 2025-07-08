package rbac_policy

import rego.v1

default decision = false

# Always allow Admins
decision = {"result": "ALLOW"} if {
    "group:Admin" in input.identity.claims
}

# Allow Maintainers to read
decision = {"result": "ALLOW"} if {
    "group:Maintainer" in input.identity.claims
    input.permission.name == "catalog.entity.read"
}
