package weibo

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
	Name:            "weibo",
	AuthorizeURL:    "https://api.weibo.com/oauth2/authorize",
	AccessTokenURL:  "https://api.weibo.com/oauth2/access_token",
	RefreshTokenURL: "https://api.weibo.com/oauth2/access_token",
	RevokeTokenURL:  "https://api.weibo.com/oauth2/revokeoauth2",
	APIURL:          "https://api.weibo.com/2",
	ScopeSep:        ",",
	ClientHeader:    "Basic",
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
	uid, ok := token.Raw["uid"].(string)
	if !ok || uid == "" {
		err = oauth.NewError("Token.Raw.uid is required", 500)
		return
	}
	var req *http.Request
	if req, err = http.NewRequest("GET", c.Endpoint.APIURL+"/users/show.json?uid="+uid, nil); err != nil {
		return
	}
	httpClient := oauth.HTTPClient(ctx, c, token)

	var raw map[string]interface{}
	if raw, err = c.Response(ctx, httpClient, req); err != nil {
		return
	}

	user = &oauth.User{
		ID:      uid,
		Raw:     raw,
		Updated: &now,
	}

	if v, ok := raw["created_at"].(string); ok && v != "" {
		if created, err := time.Parse(time.RubyDate, v); err == nil {
			user.Created = &created
		}
	}
	if v, ok := raw["profile_url"].(string); ok && v != "" {
		user.Link = "https://weibo.com/" + v
	}

	if v, ok := raw["domain"].(string); ok && v != "" {
		user.Username = v
	}
	if v, ok := raw["name"].(string); ok {
		user.Nickname = v
	}
	if v, ok := raw["description"].(string); ok {
		user.Description = v
	}
	if v, ok := raw["gender"].(string); ok {
		switch v {
		case "m":
			user.Gender = "male"
		case "f":
			user.Gender = "female"
		}
	}

	if v, ok := raw["lang"].(string); ok {
		user.Locale = oauth.FormatLocale(v)
	}
	if v, ok := raw["profile_image_url"].(string); ok && v != "" {
		user.Avatar = v
	}
	if v, ok := raw["avatar_large"].(string); ok && v != "" {
		user.Avatar = v
	}
	if v, ok := raw["avatar_hd"].(string); ok && v != "" {
		user.Avatar = v
	}

	return
}
