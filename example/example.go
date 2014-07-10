package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/seedboxtech/goauthorizer"
)

func main() {

	auth := goauthorizer.NewAuthorizerHandler(loginFn, authorizefn, "example", []byte("examplekey"), []byte("thishastobeexactly32charslong123"))
	http.HandleFunc("/login", auth.Login)
	http.HandleFunc("/logout", auth.Logout)
	http.HandleFunc("/", simpleHandler("/ is world-readable"))
	http.HandleFunc("/donkeys", auth.AuthorizeFunc(simpleHandler("/donkeys can be seen by foo and bar"),
		simpleHandler("/donkeys can't be seen by unauthenticated users.")))
	http.Handle("/monkeys", auth.AuthorizeHandler(&httphandler{simpleHandler("/monkeys can be seen by bar")}, simpleHandler("But not by foo.")))
	http.ListenAndServe(":8080", nil)
}

type httphandler struct {
	fn http.HandlerFunc
}

func (hh *httphandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	hh.fn(w, req)
}

func simpleHandler(message string) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintln(w, message)
	}
}

func loginFn(username, password string) bool {
	return (username == "foo" || username == "bar") && password == "baz"
}

func authorizefn(username, path string) bool {
	return !(strings.Contains(path, "monkeys") && username == "foo")
}
