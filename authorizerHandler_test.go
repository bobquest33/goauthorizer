package goauthorizer

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

var authorize_autosuccess = func(uname string, path string) bool { return true }
var authorize_autofail = func(uname string, path string) bool { return false }
var login_autosuccess = func(uname, pword string) bool { return true }
var login_autofail = func(uname, pword string) bool { return false }

func TestSuccessfulLogin(t *testing.T) {
	authhandler := NewAuthorizerHandler(login_autosuccess, authorize_autosuccess, "testcookie", []byte("testcookie"), []byte("testcookietestcookietestcookie12"))
	server := httptest.NewServer(&blankHandler{authhandler.Login})
	defer server.Close()

	res, err := http.Get(server.URL)
	message, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Error(err)
	}
	var response map[string]string
	json.Unmarshal(message, &response)

	assert.Equal(t, DefaultSuccessMessage["result"], response["result"])
}

func TestFailedLogin(t *testing.T) {
	authhandler := NewAuthorizerHandler(login_autofail, authorize_autosuccess, "testcookie", []byte("testcookie"), []byte("testcookietestcookietestcookie12"))
	server := httptest.NewServer(&blankHandler{authhandler.Login})
	defer server.Close()

	res, err := http.Get(server.URL)
	message, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Error(err)
	}
	var response map[string]string
	json.Unmarshal(message, &response)

	assert.Equal(t, DefaultFailureMessage["result"], response["result"])
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestUnauthorized(t *testing.T) {
	authhandler := NewAuthorizerHandler(login_autosuccess, authorize_autofail, "testcookie", []byte("testcookie"), []byte("testcookietestcookietestcookie12"))
	login := httptest.NewServer(&blankHandler{authhandler.Login})
	defer login.Close()

	allowed := func(w http.ResponseWriter, req *http.Request) { fmt.Fprint(w, "Authorized") }
	denied := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Denied")
	}
	auth := httptest.NewServer(&blankHandler{authhandler.AuthorizeFunc(allowed, denied)})
	defer auth.Close()
	jar, err := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	if err != nil {
		t.Error(err)
	}

	//Without a login, you should get unauthorized.
	res, err := client.Get(auth.URL)
	message, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

	//Login and then try the same url with an autofail authorize function.
	res, _ = client.Get(login.URL)
	res, err = client.Get(auth.URL)
	if err != nil {
		t.Error(err)
	}

	message, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
	}

	res.Body.Close()
	assert.Equal(t, "Denied", string(message))
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
}

func TestAuthorized(t *testing.T) {
	authhandler := NewAuthorizerHandler(login_autosuccess, authorize_autosuccess, "testcookie", []byte("testcookie"), []byte("testcookietestcookietestcookie12"))
	login := httptest.NewServer(&blankHandler{authhandler.Login})
	defer login.Close()

	allowed := func(w http.ResponseWriter, req *http.Request) { fmt.Fprint(w, "Authorized") }
	denied := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Denied")
	}
	auth := httptest.NewServer(authhandler.AuthorizeHandler(&blankHandler{allowed}, denied))
	defer auth.Close()
	jar, err := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	if err != nil {
		t.Error(err)
	}

	//Login and then try the same url with some authorize function.
	res, _ := client.Get(login.URL)
	res, err = client.Get(auth.URL)
	if err != nil {
		t.Error(err)
	}

	message, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
	}

	res.Body.Close()
	assert.Equal(t, "Authorized", string(message))
}

func TestBadCookie(t *testing.T) {
	authhandler := NewAuthorizerHandler(login_autosuccess, authorize_autosuccess, "testcookie", []byte("testcookie"), []byte("testcookietestcookietestcookie12"))
	login := httptest.NewServer(&blankHandler{authhandler.Login})
	defer login.Close()

	allowed := func(w http.ResponseWriter, req *http.Request) { fmt.Fprint(w, "Authorized") }
	denied := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Denied")
	}
	auth := httptest.NewServer(authhandler.AuthorizeHandler(&blankHandler{allowed}, denied))
	defer auth.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	client.Get(login.URL + "?uname=bob")
	req, _ := http.NewRequest("GET", auth.URL, nil)
	req.Header.Set("User-Agent", "Golang Spider Bot v. 3.0")
	res, _ := client.Do(req)

	res.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestTemperedCookie(t *testing.T) {
	authhandler := NewAuthorizerHandler(login_autosuccess, authorize_autosuccess, "testcookie", []byte("testcookie"), []byte("testcookietestcookietestcookie12"))
	login := httptest.NewServer(&blankHandler{authhandler.Login})
	defer login.Close()

	allowed := func(w http.ResponseWriter, req *http.Request) { fmt.Fprint(w, "Authorized") }
	denied := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Denied")
	}
	auth := httptest.NewServer(authhandler.AuthorizeHandler(&blankHandler{allowed}, denied))
	defer auth.Close()
	res, _ := http.Get(login.URL + "?uname=bob")
	cookie := res.Cookies()[0]
	//let's TEMPER WITH STUFF!
	cookie.Value = cookie.Value + "_AND_I_TEMPERED_WITH_IT"
	req, _ := http.NewRequest("GET", auth.URL, nil)
	req.AddCookie(cookie)
	res, _ = http.DefaultClient.Do(req)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	assert.Equal(t, res.Cookies()[0].Value, "")
}
