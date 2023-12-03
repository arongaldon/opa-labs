package rbac.authz

user_roles := {
	"Francisco": ["developer", "tester"],
	"Jacobo": ["developer"],
	"Victoria": ["tester"],
	"Nora": []
}

role_permissions := {
	"tester": [{"action": "read", "object": "UMS_src"}],
	"developer": [
		{"action": "read", "object": "UMS_src"},
		{"action": "write", "object": "UMS_src"},
	],
}

default allow = false

allow {
	roles := user_roles[input.user]
	r := roles[_]
	permissions := role_permissions[r]
	p := permissions[_]
	p == {"action": input.action, "object": input.object}
}
