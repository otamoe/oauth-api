package oauth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type (
	OAuth1 struct {
		Config
	}
)

func (c *OAuth1) Version() string {
	return "1.0"
}

func (c *OAuth1) ID(query url.Values) (id string) {
	if id = query.Get("oauth_token"); id == "" {
		id = query.Get("denied")
	}
	return
}

func (c *OAuth1) Cancel(query url.Values) bool {
	if query.Get("error") != "" {
		return true
	}
	if query.Get("denied") != "" {
		return true
	}
	if query.Get("oauth_token") == "" {
		return true
	}
	if query.Get("oauth_verifier") == "" {
		return true
	}

	return false
}

func (c *OAuth1) Authorize(ctx context.Context, data interface{}, cache Cache, values url.Values) (authorizeURL *url.URL, err error) {
	var oauthToken string
	var oauthTokenSecret string
	var req *http.Request
	if req, err = http.NewRequest("POST", c.Endpoint.RequestURL, nil); err != nil {
		return
	}
	req.Header.Set("Authorization", url.Values{"oauth_callback": {c.RedirectURI}}.Encode())
	httpClient := HTTPClient(ctx, c, nil)
	var raw map[string]interface{}
	if raw, err = c.Response(ctx, httpClient, req); err != nil {
		return
	}

	if raw["oauth_callback_confirmed"] != "true" {
		err = NewError("oauth_callback_confirmed was not true", 500)
		return
	}
	var ok bool
	if oauthToken, ok = raw["oauth_token"].(string); !ok || oauthToken == "" {
		err = NewError("oauth_token not string", 500)
		return
	}
	if oauthTokenSecret, ok = raw["oauth_token_secret"].(string); !ok || oauthTokenSecret == "" {
		err = NewError("oauth_token_secret not string", 500)
		return
	}

	if authorizeURL, err = url.Parse(c.Endpoint.AuthorizeURL); err != nil {
		return
	}

	AppendValues := url.Values{
		"oauth_token": {oauthToken},
	}
	query := authorizeURL.Query()
	query = MergeValues(true, query, values, AppendValues)
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
		if err = cache.Set(c.cacheKey(oauthToken), strings.Join([]string{"0", oauthTokenSecret, dataString}, ",")); err != nil {
			return
		}
	}
	return
}

func (c *OAuth1) Exchange(ctx context.Context, query url.Values, data interface{}, cache Cache, values url.Values) (token *Token, err error) {
	oauthToken := query.Get("oauth_token")
	oauthVerifier := query.Get("oauth_verifier")
	var oauthTokenSecret string

	if cache != nil {
		key := oauthToken
		if key == "" {
			key = query.Get("denied")
		}
		if key == "" {
			err = ErrDenied
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
		split := strings.SplitN(value, ",", 3)
		if len(split) != 3 {
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
		oauthTokenSecret = split[1]
		if split[2] != "" && data != nil {
			if err = json.Unmarshal([]byte(split[2]), data); err != nil {
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
	values.Set("oauth_token", oauthToken)
	values.Set("oauth_verifier", oauthVerifier)
	values.Set("oauth_token_secret", oauthTokenSecret)
	token, err = c.AccessToken(ctx, values)
	return
}

func (c *OAuth1) AccessToken(ctx context.Context, values url.Values) (token *Token, err error) {
	oauthToken := values.Get("oauth_token")
	oauthVerifier := values.Get("oauth_verifier")
	oauthTokenSecret := values.Get("oauth_token_secret")
	if oauthToken == "" || oauthVerifier == "" || oauthTokenSecret == "" {
		err = ErrDenied
		return
	}
	values.Del("oauth_token")
	values.Del("oauth_verifier")
	values.Del("oauth_token_secret")
	now := time.Now()
	var req *http.Request
	var body io.Reader
	if values != nil {
		body = strings.NewReader(values.Encode())
	}
	if req, err = http.NewRequest("POST", c.Endpoint.AccessTokenURL, body); err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", url.Values{"oauth_verifier": {oauthVerifier}}.Encode())
	httpClient := HTTPClient(ctx, c, &Token{AccessToken: oauthToken, TokenSecret: oauthTokenSecret})

	token = &Token{
		ClientID: c.ClientID,
		Created:  &now,
		Updated:  &now,
	}
	var raw map[string]interface{}
	if raw, err = c.Response(ctx, httpClient, req); err != nil {
		return
	}

	if v, ok := raw["oauth_token"].(string); ok {
		token.AccessToken = v
	}
	if v, ok := raw["oauth_token_secret"].(string); ok {
		token.TokenSecret = v
	}
	if v, ok := raw["id_token"].(string); ok {
		token.IDToken = v
	}
	if v, ok := raw["openid"].(string); ok {
		token.OpenID = v
	}
	delete(raw, "oauth_token")
	delete(raw, "oauth_token_secret")
	delete(raw, "id_token")
	delete(raw, "openid")
	token.Raw = raw
	return
}

func (c *OAuth1) PassowrdToken(ctx context.Context, values url.Values) (token *Token, err error) {
	err = NewError("Oauth1 does not support", 500)
	return
}
func (c *OAuth1) ClientCredentialsToken(ctx context.Context, values url.Values) (token *Token, err error) {
	err = NewError("Oauth1 does not support", 500)
	return
}

func (c *OAuth1) RefreshToken(ctx context.Context, oldToken *Token, values url.Values) (newToken *Token, err error) {
	err = NewError("Oauth1 does not support", 500)
	return
}

func (c *OAuth1) RevokeToken(ctx context.Context, token *Token, values url.Values) (err error) {
	err = NewError("Oauth1 does not support", 500)
	return
}

func (c *OAuth1) Signature(req *http.Request, token *Token, values url.Values) (err error) {
	if token != nil && token.Expired != nil && token.Expired.Before(time.Now()) {
		err = ErrTokenExpired
		return
	}
	clientHeader := "OAuth "
	if c.Endpoint.ClientHeader != "" {
		clientHeader = c.Endpoint.ClientHeader + " "
	}
	header := url.Values{}
	if auth := req.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, clientHeader) {
			err = NewError("The request has been signed", 500)
			return
		}
		if header, err = url.ParseQuery(auth); err != nil {
			return
		}
	}
	header.Set("oauth_signature_method", "HMAC-SHA1")
	header.Set("oauth_consumer_key", c.ClientID)
	header.Set("oauth_timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	header.Set("oauth_nonce", RandString(16))
	header.Set("oauth_version", "1.0")

	var tokenSecret string
	if token != nil {
		if token.ClientID != "" && token.ClientID != c.ClientID {
			err = NewError("Token.ClientID does not match", 500)
			return
		}
		header.Set("oauth_token", token.AccessToken)
		tokenSecret = token.TokenSecret
	}

	params := url.Values{}

	query := req.URL.Query()
	for key, val := range query {
		params.Set(key, val[0])
	}
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
		for key, val := range body {
			params.Set(key, val[0])
		}

		if values != nil {
			for key, val := range values {
				body.Set(key, val[0])
				params.Set(key, val[0])
			}
		}

		v := strings.NewReader(body.Encode())
		req.ContentLength = int64(v.Len())
		req.Body = ioutil.NopCloser(v)
		req.GetBody = func() (io.ReadCloser, error) {
			return req.Body, nil
		}
	} else {
		if values != nil {
			for key, val := range values {
				query.Set(key, val[0])
				params.Set(key, val[0])
			}
			req.URL.RawQuery = query.Encode()
		}
	}

	for key, val := range header {
		params.Set(key, val[0])
	}

	baseUrl := strings.Split(req.URL.String(), "?")

	signatureBase := strings.Join([]string{req.Method, url.QueryEscape(baseUrl[0]), url.QueryEscape(params.Encode())}, "&")
	signingKey := strings.Join([]string{c.ClientSecret, tokenSecret}, "&")
	mac := hmac.New(sha1.New, []byte(signingKey))
	mac.Write([]byte(signatureBase))
	header.Set("oauth_signature", base64.StdEncoding.EncodeToString(mac.Sum(nil)))

	var headerBuffer bytes.Buffer
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		val := header[key][0]
		if headerBuffer.Len() > 0 {
			headerBuffer.WriteString(", ")
		}
		headerBuffer.WriteString(url.QueryEscape(key))
		headerBuffer.WriteByte('=')
		headerBuffer.WriteByte('"')
		headerBuffer.WriteString(url.QueryEscape(val))
		headerBuffer.WriteByte('"')
	}

	req.Header.Set("Authorization", clientHeader+headerBuffer.String())
	return
}
