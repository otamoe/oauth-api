package qq

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
	Name:            "qq",
	AuthorizeURL:    "https://graph.qq.com/oauth2.0/authorize",
	AccessTokenURL:  "https://graph.qq.com/oauth2.0/token",
	RefreshTokenURL: "https://graph.qq.com/oauth2.0/token",
	APIURL:          "https://graph.qq.com",
	ScopeSep:        ",",
	Errors:          []string{"msg", "ret"},
}

func (c *Client) Exchange(ctx context.Context, query url.Values, data interface{}, cache oauth.Cache, values url.Values) (token *oauth.Token, err error) {
	if token, err = c.OAuth2.Exchange(ctx, query, data, cache, values); err == nil {
		err = c.OpenID(ctx, token)
	}
	return
}

func (c *Client) AccessToken(ctx context.Context, values url.Values) (token *oauth.Token, err error) {
	if token, err = c.OAuth2.AccessToken(ctx, values); err == nil {
		err = c.OpenID(ctx, token)
	}
	return
}

func (c *Client) RefreshToken(ctx context.Context, oldToken *oauth.Token, values url.Values) (newToken *oauth.Token, err error) {
	if newToken, err = c.OAuth2.RefreshToken(ctx, oldToken, values); err == nil {
		err = c.OpenID(ctx, newToken)
	}
	return
}

func (c *Client) OpenID(ctx context.Context, token *oauth.Token) (err error) {
	if token.Raw == nil {
		token.Raw = make(map[string]interface{}, 0)
	}
	if token.OpenID != "" {
		return
	}

	var req *http.Request
	if req, err = http.NewRequest("GET", c.Endpoint.APIURL+"/oauth2.0/me?access_token="+token.AccessToken, nil); err != nil {
		return
	}

	httpClient := oauth.HTTPClient(ctx, nil, nil)
	var raw map[string]interface{}
	if raw, err = c.Response(ctx, httpClient, req); err != nil {
		return
	}
	openid, ok := raw["openid"].(string)
	if !ok || openid == "" {
		err = oauth.NewError("openid not string", 500)
		return
	}
	token.OpenID = openid
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
	values.Set("oauth_consumer_key", token.ClientID)
	values.Set("openid", token.OpenID)

	err = c.OAuth2.Signature(req, token, values)
	return
}

func (c *Client) User(ctx context.Context, token *oauth.Token) (user *oauth.User, err error) {
	now := time.Now()
	var req *http.Request
	if req, err = http.NewRequest("GET", c.Endpoint.APIURL+"/user/get_user_info", nil); err != nil {
		return
	}
	httpClient := oauth.HTTPClient(ctx, c, token)

	var raw map[string]interface{}
	if raw, err = c.Response(ctx, httpClient, req); err != nil {
		return
	}

	user = &oauth.User{
		ID:      token.OpenID,
		Raw:     raw,
		Updated: &now,
	}
	if v, ok := raw["nickname"].(string); ok {
		user.Nickname = v
	}
	if v, ok := raw["figureurl_qq_1"].(string); ok && v != "" {
		user.Avatar = v
	}
	if v, ok := raw["figureurl_qq_2"].(string); ok && v != "" {
		user.Avatar = v
	}

	if v, ok := raw["gender"].(string); ok {
		switch v {
		case "男":
			user.Gender = "male"
		case "女":
			user.Gender = "female"
		}
	}
	return
}
