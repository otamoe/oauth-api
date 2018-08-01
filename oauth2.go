package oauth

import (
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type (
	OAuth2 struct {
		Config
	}
)

var regexpScopeSep = regexp.MustCompile(",|\\s")

func (c *OAuth2) Version() string {
	return "2.0"
}

func (c *OAuth2) Cancel(query url.Values) bool {
	if query.Get("error") != "" {
		return true
	}
	if query.Get("denied") != "" {
		return true
	}
	if query.Get("code") == "" {
		return true
	}
	if query.Get("state") == "" {
		return true
	}
	return false
}
func (c *OAuth2) ID(query url.Values) (id string) {
	id = query.Get("state")
	return
}

func (c *OAuth2) Authorize(ctx context.Context, data interface{}, cache Cache, values url.Values) (authorizeURL *url.URL, err error) {
	state := RandString(48)

	if authorizeURL, err = url.Parse(c.Endpoint.AuthorizeURL); err != nil {
		return
	}

	query := authorizeURL.Query()
	var scope string
	if c.Scopes != nil && len(c.Scopes) > 0 {
		if c.Endpoint.ScopeSep == "" {
			scope = strings.Join(c.Scopes, " ")
		} else {
			scope = strings.Join(c.Scopes, c.Endpoint.ScopeSep)
		}
	}
	defaultValues := url.Values{
		"scope":         {scope},
		"redirect_uri":  {c.RedirectURI},
		"response_type": {"code"},
	}

	ClientIDKey := c.Endpoint.ClientIDKey
	if ClientIDKey == "" {
		ClientIDKey = "client_id"
	}
	AppendValues := url.Values{
		ClientIDKey: {c.ClientID},
		"state":     {state},
	}

	query = MergeValues(true, query, defaultValues, values, AppendValues)
	authorizeURL.RawQuery = query.Encode()

	if cache != nil {
		var dataString string
		if data != nil {
			var b []byte
			if b, err = json.Marshal(data); err != nil {
				return
			}
			dataString = string(b)
		}
		if err = cache.Set(c.cacheKey(state), strings.Join([]string{"0", dataString}, ",")); err != nil {
			return
		}
	}

	return
}

func (c *OAuth2) Exchange(ctx context.Context, query url.Values, data interface{}, cache Cache, values url.Values) (token *Token, err error) {
	state := query.Get("state")
	code := query.Get("code")

	if cache != nil {
		key := state
		if key == "" {
			err = ErrCancel
			return
		}
		key = c.cacheKey(key)
		var value string
		if value, err = cache.Get(key); err != nil {
			return
		}
		if value == "" {
			err = ErrDenied
			return
		}
		split := strings.SplitN(value, ",", 2)
		if len(split) != 2 {
			err = ErrDenied
			return
		}
		if split[0] != "0" {
			err = ErrDenied
			return
		}
		split[0] = "1"
		if err = cache.Set(key, strings.Join(split, ",")); err != nil {
			return
		}

		if split[1] != "" && data != nil {
			if err = json.Unmarshal([]byte(split[1]), data); err != nil {
				return
			}
		}
	}

	if c.Cancel(query) {
		err = ErrCancel
		return
	}

	if values == nil {
		values = url.Values{}
	}
	values.Set("code", code)
	token, err = c.AccessToken(ctx, values)
	return
}

func (c *OAuth2) AccessToken(ctx context.Context, values url.Values) (token *Token, err error) {
	defaultValues := url.Values{
		"redirect_uri": {c.RedirectURI},
	}
	AppendValues := url.Values{
		"grant_type": {"authorization_code"},
	}

	token = &Token{}
	err = c.RequestToken(ctx, c.Endpoint.AccessTokenURL, token, defaultValues, values, AppendValues)
	return
}

func (c *OAuth2) PassowrdToken(ctx context.Context, values url.Values) (token *Token, err error) {
	AppendValues := url.Values{
		"grant_type": {"password"},
	}
	token = &Token{}

	err = c.RequestToken(ctx, c.Endpoint.AccessTokenURL, token, values, AppendValues)
	return
}
func (c *OAuth2) ClientCredentialsToken(ctx context.Context, values url.Values) (token *Token, err error) {
	AppendValues := url.Values{
		"grant_type": {"client_credentials"},
	}

	token = &Token{}

	err = c.RequestToken(ctx, c.Endpoint.AccessTokenURL, token, values, AppendValues)
	return
}

func (c *OAuth2) RefreshToken(ctx context.Context, oldToken *Token, values url.Values) (newToken *Token, err error) {
	if oldToken.RefreshToken == "" {
		err = NewError("Cannot refresh the token", 500)
		return
	}

	if oldToken.ClientID != "" && oldToken.ClientID != c.ClientID {
		err = NewError("Token.ClientID does not match", 500)
		return
	}

	AppendValues := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {oldToken.RefreshToken},
	}

	newToken = oldToken.Copy()

	err = c.RequestToken(ctx, c.Endpoint.RefreshTokenURL, newToken, values, AppendValues)
	return
}

func (c *OAuth2) RevokeToken(ctx context.Context, token *Token, values url.Values) (err error) {
	if c.Endpoint.RevokeTokenURL == "" {
		err = NewError("Token cannot be revoked", 500)
		return
	}

	if token.ClientID != "" && token.ClientID != c.ClientID {
		err = NewError("Token.ClientID does not match", 500)
		return
	}

	defaultValues := url.Values{
		"token_type_hint": {"access_token"},
	}

	values = MergeValues(false, defaultValues, values)

	if values.Get("token") == "" {
		if values.Get("token_type_hint") == "refresh_token" {
			values.Set("token", token.RefreshToken)
		} else {
			values.Set("token", token.AccessToken)
		}
	}

	var req *http.Request
	if req, err = http.NewRequest("POST", c.Endpoint.RevokeTokenURL, strings.NewReader(values.Encode())); err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpClient := HTTPClient(ctx, c, nil)
	_, err = c.Response(ctx, httpClient, req)
	return
}

func (c *OAuth2) Signature(req *http.Request, token *Token, values url.Values) (err error) {
	if token == nil {
		if c.Endpoint.ClientHeader == "Basic" {
			req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
		} else {
			ClientIDKey := c.Endpoint.ClientIDKey
			ClientSecret := c.Endpoint.ClientSecretKey

			if ClientIDKey == "" {
				ClientIDKey = "client_id"
			}
			if ClientSecret == "" {
				ClientSecret = "client_secret"
			}
			values = MergeValues(false, values, url.Values{ClientIDKey: {c.ClientID}, ClientSecret: {c.ClientSecret}})
		}
	} else {
		if token.ClientID != "" && token.ClientID != c.ClientID {
			err = NewError("Token.ClientID does not match", 500)
			return
		}
		if c.Endpoint.TokenHeader != "" {
			req.Header.Set("Authorization", c.Endpoint.TokenHeader+" "+token.AccessToken)
		} else {
			values = MergeValues(false, values, url.Values{"access_token": {token.AccessToken}})
		}
	}
	if values != nil {
		setValues(req, values)
	}
	return
}

func (c *OAuth2) RequestToken(ctx context.Context, urlString string, token *Token, merges ...url.Values) (err error) {
	now := time.Now()
	var req *http.Request

	values := MergeValues(true, nil, merges...)
	if req, err = http.NewRequest("POST", urlString, strings.NewReader(values.Encode())); err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpClient := HTTPClient(ctx, c, nil)
	var raw map[string]interface{}
	if raw, err = c.Response(ctx, httpClient, req); err != nil {
		return
	}
	token.ClientID = c.ClientID
	if token.Created == nil {
		token.Created = &now
	}
	token.Updated = &now

	if v, ok := raw["access_token"].(string); ok {
		token.AccessToken = v
	}
	if v, ok := raw["token_type"].(string); ok {
		token.TokenType = v
	}
	if v, ok := raw["refresh_token"].(string); ok {
		token.RefreshToken = v
	}
	if v, ok := raw["id_token"].(string); ok {
		token.IDToken = v
	}
	e := raw["expires_in"]
	if e == nil {
		e = raw["expires"]
	}
	switch e.(type) {
	case string:
		e, _ = strconv.ParseFloat(e.(string), 64)
	}
	if s, ok := e.(float64); ok && s != 0 {
		expired := now.Add(time.Duration(s) * time.Second)
		token.Expired = &expired
	}

	scopes := raw["scope"]
	if scopes == nil {
		scopes = raw["scopes"]
	}
	if scopes != nil {
		switch scopes.(type) {
		case string:
			if scopes.(string) != "" {
				token.Scopes = regexpScopeSep.Split(scopes.(string), -1)
			}
		case []string:
			token.Scopes = scopes.([]string)
		}
		if token.Scopes != nil {
			for i, scope := range token.Scopes {
				if v, e := url.QueryUnescape(scope); e == nil {
					scope = v
				}
				token.Scopes[i] = strings.TrimSpace(scope)
			}
		}
	}

	delete(raw, "access_token")
	delete(raw, "token_type")
	delete(raw, "refresh_token")
	delete(raw, "id_token")
	token.Raw = raw
	return
}

func setValues(req *http.Request, values url.Values) (err error) {
	if req.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		b := []byte{}
		if req.Body != nil && req.Body != http.NoBody {
			if b, err = ioutil.ReadAll(req.Body); err != nil {
				return
			}
		}
		var body url.Values
		if body, err = url.ParseQuery(string(b)); err != nil {
			return
		}
		for key, val := range values {
			body.Set(key, val[0])
		}

		v := strings.NewReader(body.Encode())
		req.ContentLength = int64(v.Len())
		req.Body = ioutil.NopCloser(v)
		req.GetBody = func() (io.ReadCloser, error) {
			return req.Body, nil
		}
	} else {
		query := req.URL.Query()
		for key, val := range values {
			query.Set(key, val[0])
		}
		req.URL.RawQuery = query.Encode()
	}
	return
}
