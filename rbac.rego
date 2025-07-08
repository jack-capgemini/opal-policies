package rbac_policy

import rego.v1

default decision = {"result": "DENY"}

# Always allow Admins
decision = {"result": "DENY"} if {
    "group:Admin" in input.identity.claims
}

# Allow Maintainers to read
decision = {"result": "DENY"} if {
    "group:Maintainer" in input.identity.claims
    input.permission.name == "catalog.entity.read"
}
