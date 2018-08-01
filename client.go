package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"gx/ipfs/QmTEmsyNnckEq8rEfALfdhLHjrEHGoSGFDrAYReuetn7MC/go-net/context/ctxhttp"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type (
	Endpoint struct {
		Name            string   `json:"name"`
		RequestURL      string   `json:"request_url,omitempty"`
		AuthorizeURL    string   `json:"authorize_url,omitempty"`
		AccessTokenURL  string   `json:"access_token_url,omitempty"`
		RefreshTokenURL string   `json:"refresh_token_url,omitempty"`
		RevokeTokenURL  string   `json:"revoke_token_url,omitempty"`
		APIURL          string   `json:"api_url,omitempty"`
		Errors          []string `json:"errors,omitempty"`
		ScopeSep        string   `json:"scope_sep,omitempty"`
		ClientHeader    string   `json:"clien_header,omitempty"`
		ClientIDKey     string   `json:"client_id_key,omitempty"`
		ClientSecretKey string   `json:"client_secret_key,omitempty"`
		TokenHeader     string   `json:"token_header,omitempty"`
	}

	Config struct {
		HTTPClient   *http.Client `json:"-"`
		Endpoint     Endpoint     `json:"endpoint"`
		ClientID     string       `json:"client_id"`
		ClientSecret string       `json:"client_secret"`
		Scopes       []string     `json:"scopes"`
		RedirectURI  string       `json:"redirect_uri"`
	}

	Client interface {
		Name() string
		Version() string
		Cancel(query url.Values) bool

		Authorize(ctx context.Context, data interface{}, cache Cache, values url.Values) (authorizeURL *url.URL, err error)
		Exchange(ctx context.Context, query url.Values, data interface{}, cache Cache, values url.Values) (token *Token, err error)
		AccessToken(ctx context.Context, values url.Values) (token *Token, err error)
		PassowrdToken(ctx context.Context, values url.Values) (token *Token, err error)
		ClientCredentialsToken(ctx context.Context, values url.Values) (token *Token, err error)
		RefreshToken(ctx context.Context, oldToken *Token, values url.Values) (newToken *Token, err error)
		RevokeToken(ctx context.Context, token *Token, values url.Values) (err error)
		Signature(req *http.Request, token *Token, values url.Values) (err error)
		Response(ctx context.Context, httpClient *http.Client, req *http.Request) (data map[string]interface{}, err error)
		User(ctx context.Context, token *Token) (user *User, err error)
	}

	xmlStack struct {
		Name   string
		Value  interface{}
		Parant *xmlStack
	}
)

var ContextHTTPClient = "OAUTH_CONTEXT_HTTP_CLIENT"
var DEBUG = false

var regexpCallback = regexp.MustCompile("^[0-9a-zA-Z._]+\\((.*)\\);?$")

func (c *Config) Name() string {
	return c.Endpoint.Name
}

func (c *Config) Response(ctx context.Context, httpClient *http.Client, req *http.Request) (data map[string]interface{}, err error) {
	var res *http.Response

	if res, err = ctxhttp.Do(ctx, httpClient, req); err != nil {
		return
	}
	defer res.Body.Close()

	var body []byte
	body, err = ioutil.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		err = fmt.Errorf("Cannot fetch token: %v", err)
		return
	}

	body = bytes.TrimSpace(body)

	if len(body) > 2 {
		if body[len(body)-1] == ')' || (body[len(body)-1] == ';' && body[len(body)-2] == ')') {
			body = regexpCallback.ReplaceAll(body, []byte("${1}"))
			body = bytes.TrimSpace(body)
		}
	}

	contentType, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	var typ string
	if v := strings.Split(contentType, "/"); len(v) > 1 {
		typ = v[1]
	}

	data = make(map[string]interface{}, 0)

	switch {
	case len(body) < 2:
		data["result"] = string(body)
	case body[0] == '<' && body[len(body)-1] == '>' && (typ == "xml" || typ == "rss+xml"):
		decoder := xml.NewDecoder(bytes.NewReader(body))
		stack := &xmlStack{
			Name: "root",
		}
		for {
			var t xml.Token
			t, err = decoder.Token()
			if err != nil {
				if err == io.EOF {
					err = nil
					break
				}
				break
			}
			switch t := t.(type) {
			case xml.StartElement:
				stack2 := &xmlStack{
					Name:   t.Name.Local,
					Parant: stack,
				}
				stack = stack2
			case xml.EndElement:
				parant := stack.Parant
				if parant != nil {
					mapValue, ok := parant.Value.(map[string]interface{})
					if !ok {
						mapValue = map[string]interface{}{}
					}
					mapValue[stack.Name] = stack.Value
					parant.Value = mapValue
					data = mapValue
				}
				stack = parant
			case xml.CharData:
				stack.Value = string(t)
			}
		}
	case typ == "x-www-form-urlencoded" || typ == "plain" || body[0] != '{':
		var vals url.Values
		if vals, err = url.ParseQuery(string(body)); err != nil {
			return
		}
		for key, val := range vals {
			if len(val) == 1 {
				data[key] = val[0]
			} else {
				data[key] = val
			}
		}
	default:
		if err = json.Unmarshal(body, &data); err != nil {
			return
		}
	}
	status := res.StatusCode
	errors := []string{"error_description", "error", "errors"}
	if c.Endpoint.Errors != nil {
		errors = append(errors, c.Endpoint.Errors...)
	}
	for _, name := range errors {
		val, ok := data[name]
		if !ok {
			continue
		}
		var message string
		switch val.(type) {
		case string:
			message = val.(string)
		case float64, float32:
			val := val.(float64)
			if val != 0 {
				message = fmt.Sprintf("oauth error: %s: %s", name, strconv.FormatFloat(val, 'f', 0, 64))
			}
		case int, int64, int32:
			val := val.(int64)
			if val != 0 {
				message = fmt.Sprintf("oauth error: %s: %d", name, val)
			}
		default:
			message = fmt.Sprintf("oauth error: %s: %v", name, val)
		}
		if message != "" {
			if status < 400 {
				status = 400
			}
			err = NewError(message, status)
			return
		}
	}
	if status < 200 || status > 299 {
		if status < 400 {
			status = 400
		}
		err = NewError(fmt.Sprintf("Status code error: %d", res.StatusCode), status)
		return
	}
	return
}

func (c *Config) cacheKey(key string) string {
	hash := sha1.New()
	hash.Write([]byte(key))
	return strings.Join([]string{"oauth", c.Name(), c.ClientID, base64.StdEncoding.EncodeToString(hash.Sum(nil))}, ".")
}

func (c *Config) User(ctx context.Context, token *Token) (user *User, err error) {
	err = NewError("not support", 500)
	return
}

var randRunes = []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func MergeValues(deleteEmpty bool, values url.Values, merges ...url.Values) url.Values {
	if values == nil {
		values = url.Values{}
	}
	for _, merge := range merges {
		if merge != nil {
			for key, val := range merge {
				values.Set(key, val[0])
			}
		}
	}
	if deleteEmpty {
		for key, val := range values {
			if val[0] == "" {
				values.Del(key)
			}
		}
	}
	return values
}

func HTTPClient(ctx context.Context, client Client, token *Token) (httpClient *http.Client) {
	httpClient = http.DefaultClient
	if ctx != nil {
		if v, ok := ctx.Value(ContextHTTPClient).(*http.Client); ok {
			httpClient = v
		}
	}
	httpClient2 := *httpClient
	httpClient3 := httpClient2
	httpClient = &httpClient3

	// 移除处理过的
	if httpClient.Transport != nil {
		switch httpClient.Transport.(type) {
		case *Transport:
			transport := httpClient.Transport.(*Transport)
			httpClient.Transport = transport.Parent
		}
	}

	httpClient.Transport = &Transport{
		Parent: httpClient.Transport,
		Client: client,
		Token:  token,
	}
	return
}

func RandString(n int) string {
	b := make([]byte, n)
	for i := range b {
		bn, err := rand.Int(rand.Reader, big.NewInt(int64(len(randRunes))))
		if err != nil {
			log.Fatalln(err)
		}
		b[i] = randRunes[bn.Int64()]
	}
	return string(b)
}
func FormatLocale(locale string) string {
	locale = strings.Replace(locale, "_", "-", -1)
	split := strings.Split(locale, "-")

	split[0] = strings.ToLower(split[0])
	switch len(split) {
	case 1:

	case 2:
		split[1] = strings.ToUpper(split[1])
	case 3:
		if len(split[1]) > 0 {
			split[1] = strings.ToUpper(split[1]) + strings.ToLower(split[0][1:])
		}
		split[2] = strings.ToUpper(split[2])
	default:
		if len(split[1]) > 0 {
			split[1] = strings.ToUpper(split[1]) + strings.ToLower(split[0][1:])
		}
		split[2] = strings.ToUpper(split[2])
		split[3] = strings.ToUpper(split[3])
	}

	return strings.Join(split, "-")
}
