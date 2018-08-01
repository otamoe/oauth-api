package baidu

import (
	"context"
	"net/http"
	"net/url"
	"time"

	oauth "github.com/lian-yue/oauth-api"
)

type (
	Client struct {
		oauth.OAuth2
	}
)

var Endpoint = oauth.Endpoint{
	Name:            "baidu",
	AuthorizeURL:    "https://openapi.baidu.com/oauth/2.0/authorize",
	AccessTokenURL:  "https://openapi.baidu.com/oauth/2.0/token",
	RefreshTokenURL: "https://openapi.baidu.com/oauth/2.0/token",
	RevokeTokenURL:  "https://openapi.baidu.com/rest/2.0/passport/auth/expireSession",
	APIURL:          "https://openapi.baidu.com/rest/2.0",
}

func (c *Client) RevokeToken(ctx context.Context, token *oauth.Token, values url.Values) (err error) {
	var req *http.Request
	if req, err = http.NewRequest("POST", c.Endpoint.RevokeTokenURL, nil); err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpClient := oauth.HTTPClient(ctx, c, token)
	_, err = c.Response(ctx, httpClient, req)
	return
}

func (c *Client) User(ctx context.Context, token *oauth.Token) (user *oauth.User, err error) {
	now := time.Now()
	var req *http.Request
	if req, err = http.NewRequest("GET", c.Endpoint.APIURL+"/passport/users/getInfo", nil); err != nil {
		return
	}
	httpClient := oauth.HTTPClient(ctx, c, token)

	var raw map[string]interface{}
	if raw, err = c.Response(ctx, httpClient, req); err != nil {
		return
	}

	user = &oauth.User{
		ID:      raw["userid"].(string),
		Raw:     raw,
		Updated: &now,
	}

	if v, ok := raw["username"].(string); ok && v != "" {
		user.Username = v
	}
	if v, ok := raw["name"].(string); ok && v != "" {
		user.Name = v
	}
	if v, ok := raw["userdetail"].(string); ok {
		user.Description = v
	}
	if v, ok := raw["birthday"].(string); ok && v != "" && v != "0000-00-00" {
		if birthday, err := time.Parse("2006/01/02", v); err == nil {
			user.Birthday = &birthday
		}
	}
	if v, ok := raw["portrait"].(string); ok && v != "" {
		user.Avatar = "http://tb.himg.baidu.com/sys/portrait/item/" + v
	}
	if v, ok := raw["sex"].(string); ok {
		switch v {
		case "1":
			user.Gender = "male"
		case "0":
			user.Gender = "female"
		}
	}

	return
}
