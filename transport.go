package oauth

import (
	"fmt"
	"net/http"
	"net/http/httputil"
)

type Transport struct {
	Client Client
	Token  *Token
	Parent http.RoundTripper
}

func (t *Transport) RoundTrip(req *http.Request) (res *http.Response, err error) {
	if t.Client != nil {
		err = t.Client.Signature(req, t.Token, nil)
		if err != nil {
			return
		}
	}
	var transport http.RoundTripper
	if t.Parent != nil {
		transport = t.Parent
	} else {
		transport = http.DefaultTransport
	}
	if DEBUG {
		var isBody bool
		if req.Header.Get("Content-Type") == "application/x-www-form-urlencoded" || req.Header.Get("Content-Type") == "application/json" {
			isBody = true
		}
		dump, _ := httputil.DumpRequest(req, isBody)
		fmt.Println("")
		fmt.Println("")
		fmt.Println(string(dump))
		fmt.Println("")
		fmt.Println("")
	}

	res, err = transport.RoundTrip(req)

	if DEBUG {
		dump, _ := httputil.DumpResponse(res, true)
		fmt.Println("")
		fmt.Println("")
		fmt.Println(string(dump))
		fmt.Println("")
		fmt.Println("")
	}
	return
}
