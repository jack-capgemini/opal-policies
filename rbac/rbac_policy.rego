package rbac_policy

import rego.v1

decision = {"result": "ALLOW"} if {
    "group:Admin" in input.identity.claims
}

decision = {"result": "ALLOW"} if {
    "group:Maintainer" in input.identity.claims
    input.permission.name == "catalog.entity.read"
}

decision = {"result": "DENY"}