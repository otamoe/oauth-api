package wechat

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/otamoe/oauth-client"
)

type (
	Client struct {
		oauth.OAuth2
	}
)

var Endpoint = oauth.Endpoint{
	Name:            "wechat",
	AuthorizeURL:    "https://open.weixin.qq.com/connect/oauth2/authorize#wechat_redirect",
	AccessTokenURL:  "https://api.weixin.qq.com/sns/oauth2/access_token",
	RefreshTokenURL: "https://api.weixin.qq.com/sns/oauth2/refresh_token",
	APIURL:          "https://api.weixin.qq.com",
	Errors:          []string{"errmsg", "errcode"},
	ClientIDKey:     "appid",
	ClientSecretKey: "secret",
}

func (c *Client) Authorize(ctx context.Context, state string, values url.Values) (authorizeURL *url.URL, data map[string]interface{}, err error) {
	if authorizeURL, data, err = c.OAuth2.Authorize(ctx, state, values); err != nil {
		return
	}
	var qrcode bool
	if values != nil && values.Get("qrcode") != "" {
		values.Del("qrcode")
		qrcode = true
	}
	if qrcode {
		authorizeURL.Path = "/connect/qrconnect"
	}
	return
}

func (c *Client) Signature(req *http.Request, token *oauth.Token, values url.Values) (err error) {
	if token.OpenID == "" {
		err = oauth.NewError("Token.OpenID is required", 500)
		return
	}

	if values == nil {
		values = url.Values{}
	}

	values.Set("openid", token.OpenID)
	err = c.OAuth2.Signature(req, token, values)
	return
}

func (c *Client) User(ctx context.Context, token *oauth.Token) (user *oauth.User, err error) {
	now := time.Now()
	var req *http.Request
	if req, err = http.NewRequest("GET", c.Endpoint.APIURL+"/sns/userinfo?lang=en", nil); err != nil {
		return
	}
	httpClient := oauth.HTTPClient(ctx, c, token)

	var raw map[string]interface{}
	if raw, err = c.Response(ctx, httpClient, req); err != nil {
		return
	}
	id := token.OpenID
	if v, ok := raw["openid"].(string); ok && v != "" {
		id = v
	}
	if v, ok := raw["unionid"].(string); ok && v != "" {
		id = v
	}

	user = &oauth.User{
		ID:      id,
		Raw:     raw,
		Updated: &now,
	}
	if v, ok := raw["nickname"].(string); ok {
		user.Nickname = v
	}

	if v, ok := raw["headimgurl"].(string); ok && v != "" {
		avatar := strings.Split(v, "/")
		if len(avatar[len(avatar)-1]) > 1 && len(avatar[len(avatar)-1]) < 4 {
			avatar[len(avatar)-1] = "0"
		}
		user.Avatar = strings.Join(avatar, "/")
	}

	if v, ok := raw["country"].(string); ok {
		user.Locale = oauth.FormatLocale(v)
	}

	if v, ok := raw["gender"].(string); ok {
		switch v {
		case "1":
			user.Gender = "male"
		case "2":
			user.Gender = "female"
		}
	}
	return
}
