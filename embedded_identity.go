package main

import "strings"

func validWorkerIdentity(actual, expected, privilege string, elevated bool) bool {
	return strings.HasPrefix(expected, "S-1-5-21-") && actual == expected &&
		((privilege == "standard" && !elevated) || (privilege == "administrator" && elevated))
}
