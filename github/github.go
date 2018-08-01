package github

import (
	"context"
	"net/http"
	"strconv"
	"time"

	oauth "github.com/otamoe/oauth-api"
)

type (
	Client struct {
		oauth.OAuth2
	}
)

var Endpoint = oauth.Endpoint{
	Name:            "github",
	AuthorizeURL:    "https://github.com/login/oauth/authorize",
	AccessTokenURL:  "https://github.com/login/oauth/access_token",
	RefreshTokenURL: "https://github.com/login/oauth/access_token",
	APIURL:          "https://api.github.com",
	ClientHeader:    "Basic",
	TokenHeader:     "token",
}

func (c *Client) User(ctx context.Context, token *oauth.Token) (user *oauth.User, err error) {
	now := time.Now()
	var req *http.Request
	if req, err = http.NewRequest("GET", c.Endpoint.APIURL+"/user", nil); err != nil {
		return
	}
	httpClient := oauth.HTTPClient(ctx, c, token)

	var raw map[string]interface{}
	if raw, err = c.Response(ctx, httpClient, req); err != nil {
		return
	}

	user = &oauth.User{
		ID:      strconv.FormatFloat(raw["id"].(float64), 'f', 0, 64),
		Raw:     raw,
		Updated: &now,
	}

	if v, ok := raw["login"].(string); ok {
		user.Username = v
	}
	if v, ok := raw["avatar_url"].(string); ok {
		user.Avatar = v
	}
	if v, ok := raw["html_url"].(string); ok {
		user.Link = v
	}
	if v, ok := raw["name"].(string); ok {
		user.Nickname = v
	}

	if v, ok := raw["created_at"].(string); ok && v != "" {
		if created, err := time.Parse(time.RFC3339, v); err == nil {
			user.Created = &created
		}
	}

	if v, ok := raw["email"].(string); ok && v != "" {
		if user.Auths == nil {
			user.Auths = make([]*oauth.Auth, 0)
		}
		user.Auths = append(user.Auths, &oauth.Auth{
			Type:     "email",
			Value:    v,
			Verified: true,
		})
	}

	return
}
