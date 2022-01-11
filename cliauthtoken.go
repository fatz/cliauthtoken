package cliauthtoken

import (
	"fmt"
	"os"
	"time"
  "context"

  "net"
  "net/http"
  "net/url"

  "text/template"

	"github.com/skratchdot/open-golang/open"
  "github.com/AlecAivazis/survey/v2"
  log "github.com/sirupsen/logrus"

)

const CallbackQueryParameter = "session"
const CallbackPath = "/"
const CallbackSuccessPage = `
<!DOCTYPE html><html lang="en"><body><h1>Success...</h1>
<p>You are authenticated, you can now return to the CLI. This will try to auto-close...</p>
<script>window.onload=function(){setTimeout(this.close, 2000)}</script></body></html>
`
const AuthRequestCallbackParameter = "redirect"

const AuthRequestCopyParameter = "sessioncopy"
const AuthRequestCopyParameterValue = "true"

var PromptPleaseOpen = "Please open {{.url}} in your Browser\n"
var PromptPasteToken = "Please paste the displayed token"
var PromptOpenBrowserURL = "You will now be taken to your browser for authentication. Or browse this URL {{.url}}\n"

// AuthRequestCallbackValueFunc gets the net.Listener from callback server and returns the
// callback parameter value
type AuthRequestCallbackValueFunc func(net.Listener) string

type CLIAuthToken struct {
  // AuthRequestURL is the url to be opened in users browser
  AuthRequestURL string
  // AuthRequestCopyParameter is the parameter to signal the auth server to show
  // copy paste dialog
  AuthRequestCopyParameter string
  // AuthRequestCopyParameterValue
  AuthRequestCopyParameterValue string
  // The AuthRequestCallbackParameter defining the url parameter for redirect callback
  AuthRequestCallbackParameter string
  // AuthRequestCallbackParameterValueFunc is a function receiving net.Listener to return
  // a value for `AuthRequestCallbackParameter`.
  // By default DefaultAuthRequestCallbackParameterValueFunc is being used returning the
  // local server URL
  AuthRequestCallbackParameterValueFunc AuthRequestCallbackValueFunc

  // CallbackQueryParameter is the query paramter we expect the token as a value
  CallbackQueryParameter string
  // Use a different path than `/` for expecting the callback
  CallbackPath string
  // Define the returned html after successfull callback.
  CallbackSuccessPage string

  TokenTimeout time.Duration

  // Should be 127.0.0.1
  ListenAddr string
  // Log specifies the logger to be used. `logrus.New()` is default
  Log *log.Logger
}

// DefaultAuthRequestCallbackParameterValueFunc build the callback parameter from net.Listener
// example: "http://127.0.0.1:12345"
func DefaultAuthRequestCallbackParameterValueFunc(listener net.Listener) string {
  if listener == nil {
    return ""
  }

  return fmt.Sprintf("http://%s", listener.Addr().String())
}

// NewCLIAuthToken creates a new *CLIAuthToken with defaults
func NewCLIAuthToken(authRequestURL string) (clia *CLIAuthToken) {
  clia = new(CLIAuthToken)

  clia.AuthRequestURL = authRequestURL
  clia.AuthRequestCallbackParameter = AuthRequestCallbackParameter
  clia.CallbackQueryParameter = CallbackQueryParameter
  clia.CallbackPath = CallbackPath
  clia.CallbackSuccessPage = CallbackSuccessPage
  clia.ListenAddr = "127.0.0.1"
  clia.AuthRequestCopyParameter = AuthRequestCopyParameter
  clia.AuthRequestCopyParameterValue = AuthRequestCopyParameterValue
  clia.AuthRequestCallbackParameterValueFunc = DefaultAuthRequestCallbackParameterValueFunc

  //set defaults
  clia.TokenTimeout = 5 * time.Minute

  clia.Log = log.New()
  return clia
}

func (clia *CLIAuthToken) RequestTokenPasteable() string {
  var session string
  url := clia.buildCopyURL()

  t := template.Must(template.New("prompt").Parse(PromptPleaseOpen))
  err := t.Execute(os.Stderr, map[string]string{"url": url})
  if err != nil {
    clia.Log.Fatalf("Unexpected parsing error - %v", err)
  }

  session = ""
  prompt := &survey.Multiline{
      Message: PromptPasteToken,
  }
  survey.AskOne(prompt, &session)

  return session
}

func (clia *CLIAuthToken) buildCopyURL() string {
  u, err := url.Parse(clia.AuthRequestURL)
  if err != nil {
    clia.Log.Fatalf("Cannot parse url %s - %v", clia.AuthRequestURL, err)
  }

  // set parameter
  query := u.Query()
  query.Set(clia.AuthRequestCopyParameter, clia.AuthRequestCopyParameterValue)
  u.RawQuery = query.Encode()

  return u.String()
}

// RequestTokenRedirected starts a local callback server and tries to open the users
// browser starting the callback procedure
func (clia *CLIAuthToken) RequestTokenRedirected() string {
  var session string

  listener, err := net.Listen("tcp", fmt.Sprintf("%s:0", clia.ListenAddr))
  if err != nil {
    clia.Log.Fatalf("Error opening listener %v", err)
  }

  sessSignal := make(chan string)
  server := clia.httpServer(sessSignal, listener)
  // time.Sleep(600 * time.Millisecond)
  url := clia.buildURL(listener)
  t := template.Must(template.New("prompt").Parse(PromptOpenBrowserURL))
  err = t.Execute(os.Stderr, map[string]string{"url": url})
  if err != nil {
    clia.Log.Fatalf("Unexpected parsing error - %v", err)
  }

  if err := open.Run(url); err != nil {
    clia.Log.Fatalf("Error opening Browser - %v", err)
  }

  // time.Sleep(1200 * time.Millisecond)
  session = <-sessSignal
  //shutdown server
  go func() {
		if err := server.Shutdown(context.Background()); err != nil {
			clia.Log.Debugf("Error during Shutdown(): %v", err)
		}
	}()

  clia.Log.Debugf("Received session - %s", session)
  return session
}

func (clia *CLIAuthToken) buildURL(listener net.Listener) string {
  u, err := url.Parse(clia.AuthRequestURL)
  if err != nil {
    clia.Log.Fatalf("Cannot parse url %s - %v", clia.AuthRequestURL, err)
    return ""
  }

  // set parameter
  query := u.Query()
  query.Set(clia.AuthRequestCallbackParameter, clia.AuthRequestCallbackParameterValueFunc(listener))
  u.RawQuery = query.Encode()

  return u.String()
}

func (clia *CLIAuthToken) callbackHandler(sessSignal chan string) func(w http.ResponseWriter, r *http.Request) {
  return func(w http.ResponseWriter, r *http.Request) {
    queryParts, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v", err)
		}
		session := queryParts.Get(clia.CallbackQueryParameter)
    if err != nil {
			fmt.Fprintf(os.Stderr, "%v", err)
		}
    _, err = fmt.Fprint(w, clia.CallbackSuccessPage)
		if err != nil {
			clia.Log.Fatalf("Error writing callback page %v", err)
		}

    clia.Log.Debugf("Received redirect with session: %s", session)
    sessSignal <- session
  }
}

func (clia *CLIAuthToken) httpServer(sessSignal chan string, listener net.Listener) *http.Server {
  mux := http.NewServeMux()
  mux.HandleFunc("/", clia.callbackHandler(sessSignal))
  srv := &http.Server{Addr: listener.Addr().String(), Handler: mux}

  go func() {
		if err := srv.Serve(listener); err != nil {
      // not really important
			clia.Log.Debugf("Error during Serve(): %v", err)
		}
	}()

	return srv
}
