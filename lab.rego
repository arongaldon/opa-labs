package rules

# Author: Aron Galdón Ginés
# Lab following an OPA course.

# Command line use:
# opa run -s lab.rego
# curl localhost:8181/v1/data/rules/allow -d '{"input": {"method": "POST", "path": ["coches"], "user": "Carlos"}}'

# VSCode use:
# Open the rego file, update the input JSON, Ctrl + P, "OPA: Evaluate Package"

###########
# JSON data

users := {
	"Alicia": {"manager": "charlie", "title": "salesperson"},
	"Bartolo": {"manager": "charlie", "title": "salesperson"},
	"Carlos": {"manager": "dave", "title": "manager"},
	"David": {"manager": null, "title": "ceo"},
}

#######
# Rules

default allow = false

allow {
	# anyone can read coches
	input.path == ["coches"]
	input.method == "GET"
}

allow {
	# only managers can create a new car
	user_is_manager
	input.path == ["coches"]
	input.method == "POST"
}

allow {
	# only employees can GET /coches/{carid}
	user_is_employee
	count(input.path) == 2
	input.path[0] == "coches"
	input.method == "GET"
}

allow {
	# only employees can GET /coches/{carid}/status
	user_is_employee
	count(input.path) == 3
	input.path[0] == "coches"
	input.path[2] == "status"
	input.method == "GET"
}

allow {
	# only employees can POST /coches/{carid}/status
	user_is_employee
	count(input.path) == 3
	input.path[0] == "coches"
	input.path[2] == "status"
	input.method == "POST"
}

allow {
	# only managers can PUT /coches/{carid}
	user_is_manager
	count(input.path) == 2
	input.path[0] == "coches"
	input.method == "PUT"
}

allow {
	# only managers can DELETE /coches/{carid}
	user_is_manager
	count(input.path) == 2
	input.path[0] == "coches"
	input.method == "DELETE"
}

#########
# Helpers

user_is_employee {
	users[input.user]
} else = false

user_is_manager {
	users[input.user].title != "salesperson"
} else = false

#######
# Tests

test_car_read_positive {
	testedInput = {
		"method": "GET",
		"path": ["coches"],
		"user": "Alicia",
	}
	allow == true with input as testedInput
}

test_car_read_negative {
	testedInput = {
		"method": "GET",
		"path": ["nonexistent"],
		"user": "Alicia",
	}
	allow == false with input as testedInput
}

test_car_create_negative {
	testedInput = {
		"method": "POST",
		"path": ["coches"],
		"user": "Alicia",
	}
	allow == false with input as testedInput
}

test_car_create_positive {
	testedInput = {
		"method": "POST",
		"path": ["coches"],
		"user": "Carlos",
	}
	allow == true with input as testedInput
}

test_carid_read_negative {
	testedInput = {
		"method": "GET",
		"path": ["coches", "id789-932"],
		"user": "unknown",
	}
	allow == false with input as testedInput
}

test_carid_read_positive {
	testedInput = {
		"method": "GET",
		"path": ["coches", "id789-932"],
		"user": "Alicia",
	}
	allow == true with input as testedInput
}

test_carid_status_read_negative {
	testedInput = {
		"method": "GET",
		"path": ["coches", "id789-932", "status"],
		"user": "unknown",
	}
	allow == false with input as testedInput
}

test_carid_status_read_positive {
	testedInput = {
		"method": "GET",
		"path": ["coches", "id789-932", "status"],
		"user": "Alicia",
	}
	allow == true with input as testedInput
}

test_carid_status_create_negative {
	testedInput = {
		"method": "POST",
		"path": ["coches", "id789-932", "status"],
		"user": "unknown",
	}
	allow == false with input as testedInput
}

test_carid_status_create_positive {
	testedInput = {
		"method": "POST",
		"path": ["coches", "id789-932", "status"],
		"user": "Alicia",
	}
	allow == true with input as testedInput
}

test_carid_update_negative {
	testedInput = {
		"method": "PUT",
		"path": ["coches", "id789-932"],
		"user": "Alicia",
	}
	allow == false with input as testedInput
}

test_carid_update_positive {
	testedInput = {
		"method": "PUT",
		"path": ["coches", "id789-932"],
		"user": "David",
	}
	allow == true with input as testedInput
}

test_carid_delete_negative {
	testedInput = {
		"method": "DELETE",
		"path": ["coches", "id789-932"],
		"user": "Alicia",
	}
	allow == false with input as testedInput
}

test_carid_delete_positive {
	testedInput = {
		"method": "DELETE",
		"path": ["coches", "id789-932"],
		"user": "David",
	}
	allow == true with input as testedInput
}
