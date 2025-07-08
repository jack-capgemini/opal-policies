package rbac_policy

import rego.v1

default decision = false

test_admin_allowed if {
  decision with input as {"identity": {"claims": ["group:Admin"]}} == {"result": "ALLOW"}
}

test_maintainer_read_allowed if {
  decision with input as {
    "identity": {"claims": ["group:Maintainer"]},
    "permission": {"name": "catalog.entity.read"}
  } == {"result": "ALLOW"}
}