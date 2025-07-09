package rbac_policy

test_admin_allowed {
    decision with input as {
        "identity": {"claims": ["group:Admin"]},
        "permission": {"name": "catalog.entity.read"}
    } == {"result": "ALLOW"}
}

test_maintainer_read_allowed {
    decision with input as {
        "identity": {"claims": ["group:Maintainer"]},
        "permission": {"name": "catalog.entity.read"}
    } == {"result": "ALLOW"}
}

test_maintainer_write_denied {
    decision with input as {
        "identity": {"claims": ["group:Maintainer"]},
        "permission": {"name": "catalog.entity.write"}
    } == {"result": "DENY"}
}

test_user_denied {
    decision with input as {
        "identity": {"claims": ["group:User"]},
        "permission": {"name": "catalog.entity.read"}
    } == {"result": "DENY"}
}