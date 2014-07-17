package goauthorizer

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/securecookie"
)

type LoginFunc func(uname, pword string) bool

type AuthorizerHandler struct {
	loginfn      LoginFunc
	authorizedfn func(uname string, resource string) bool

	//UnauthorizedHandler is used in cases where the user isn't logged in. By default it will write 401 and terminate the connection.
	UnauthorizedHandler http.HandlerFunc
	cookiename          string
	UserNameField       string
	PassWordField       string
	securecookie        *securecookie.SecureCookie

	//Status messages to users.
	UnauthorizedMessage string
	ForbiddenMessage    string
	LoginSuccessMessage string
	LoginFailureMessage string
}

var DefaultSuccessMessage = map[string]string{"result": "true"}
var DefaultFailureMessage = map[string]string{"result": "false", "reason": "Bad username or password"}
var DefaultUnauthorizedMessage = map[string]string{"result": "false", "reason": "401 Unauthorized"}
var DefaultForbiddenMessage = map[string]string{"result": "false", "reason": "403 Forbidden"}

//loginfn should be a function that accepts a username and password and returns true or false.
//authorizedfn should be a function that checks if a given username has access to a given resource.
//unauthorizedfn.
//Last parameter NEEDS to be 8, 16, or 32 bytes long. See securecookie documentation.
//Note that IF the last parameter is SET TO NIL,  ENCRYPTION OF THE COOKIE VALUE IS DISABLED.
func NewAuthorizerHandler(loginfn LoginFunc, authorizedfn func(string, string) bool, cookiename string, cookieHashKey, cookieBlockKey []byte) *AuthorizerHandler {
	var s = securecookie.New(cookieHashKey, cookieBlockKey)
	ah := &AuthorizerHandler{loginfn: loginfn, cookiename: cookiename, securecookie: s, authorizedfn: authorizedfn}
	ah.UserNameField = "uname"
	ah.PassWordField = "pword"
	b, _ := json.Marshal(DefaultSuccessMessage)
	b2, _ := json.Marshal(DefaultFailureMessage)
	unauthorized, _ := json.Marshal(DefaultUnauthorizedMessage)
	forbidden, _ := json.Marshal(DefaultForbiddenMessage)
	ah.LoginFailureMessage = string(b2)
	ah.LoginSuccessMessage = string(b)
	ah.UnauthorizedMessage = string(unauthorized)
	ah.ForbiddenMessage = string(forbidden)
	ah.UnauthorizedHandler = func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusUnauthorized) }
	return ah
}

//Generic login handler uses the specified login function to authenticate users.
//Returns a Forbidden when it fails.
func (lh *AuthorizerHandler) Login(w http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		log.Println(err)
	}
	original_ip := getOriginalIp(req)
	uname := req.FormValue(lh.UserNameField)

	if lh.loginfn(uname, req.FormValue(lh.PassWordField)) {
		//Encode IP, User Agent, and UserName in cookie.

		cookie := lh.encodeLoginCookie(uname, original_ip, req.UserAgent())

		http.SetCookie(w, cookie)
		w.Write([]byte(lh.LoginSuccessMessage))
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(lh.LoginFailureMessage))
	}
}

func (lh *AuthorizerHandler) Logout(w http.ResponseWriter, req *http.Request) {
	//If cookie doesn't exist, nothing to do.
	if cookie, err := req.Cookie(lh.cookiename); err == nil {
		cookie.Value = ""
		cookie.MaxAge = -1
		http.SetCookie(w, cookie)
	}

}

func getOriginalIp(req *http.Request) string {
	forwards := strings.Split(req.Header.Get("X-Forwarded-For"), ",")
	var original_ip string
	if len(forwards) > 0 {
		original_ip = forwards[0]
	}
	return original_ip
}

func (lh *AuthorizerHandler) encodeLoginCookie(uname string, original_ip string, user_agent string) *http.Cookie {
	secval, _ := lh.securecookie.Encode(lh.cookiename, map[string]string{lh.UserNameField: uname, "ip": original_ip, "ua": user_agent})
	cookie := &http.Cookie{}
	cookie.Name = lh.cookiename
	cookie.Value = secval
	return cookie
}

func (lh *AuthorizerHandler) AuthorizeHandler(allowhandler http.Handler, denyhandler http.HandlerFunc) http.Handler {
	return &blankHandler{lh.AuthorizeFunc(allowhandler.ServeHTTP, denyhandler)}
}

type blankHandler struct {
	fn http.HandlerFunc
}

func (bh *blankHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	bh.fn(w, req)
}

//Use this to wrap an http.HandlerFunc you pass to an http.ServeMux's HandleFunc.
func (lh *AuthorizerHandler) AuthorizeFunc(allowhandler http.HandlerFunc, denyhandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if cookie, err := req.Cookie(lh.cookiename); err == nil {
			if uname, err := lh.GetUserName(req); err == nil {
				//User is logged in.
				if lh.authorizedfn(uname, req.URL.String()) {

					allowhandler(w, req)
					return
				} else {
					denyhandler(w, req)
					return
				}
			} else {
				//Bad cookie, remove.
				cookie.Value = ""
				cookie.MaxAge = -1
				http.SetCookie(w, cookie)
			}
		}
		//By default you are not authorized.
		lh.UnauthorizedHandler(w, req)
	}
}

func (lh *AuthorizerHandler) GetUserName(req *http.Request) (string, error) {
	if cookie, err := req.Cookie(lh.cookiename); err == nil {
		value := make(map[string]string)
		if err := lh.securecookie.Decode(lh.cookiename, cookie.Value, &value); err == nil {
			//This is to check against cookie theft and/or forgery.
			if value["ip"] == getOriginalIp(req) && value["ua"] == req.UserAgent() {
				return value[lh.UserNameField], nil
			} else {
				return "", errors.New("Authorizer: Bad cookie.")
			}
		} else {
			return "", err
		}
	} else {
		return "", err
	}
}

func (lh *AuthorizerHandler) IsLoggedIn(req *http.Request) bool {
	u, e := lh.GetUserName(req)
	return u != "" && e == nil
}
