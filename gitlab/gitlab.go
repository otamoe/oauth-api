package gitlab

import (
	"context"
	"net/http"
	"strconv"
	"time"

	oauth "github.com/lian-yue/oauth-api"
)

type (
	Client struct {
		oauth.OAuth2
	}
)

var Endpoint = oauth.Endpoint{
	Name:            "gitlab",
	AuthorizeURL:    "https://gitlab.com/oauth/authorize",
	AccessTokenURL:  "https://gitlab.com/oauth/token",
	RefreshTokenURL: "https://gitlab.com/oauth/token",
	APIURL:          "https://gitlab.com/api/v4",
	ClientHeader:    "Basic",
	TokenHeader:     "Bearer",
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

	if v, ok := raw["username"].(string); ok && v != "" {
		user.Username = v
		user.Link = "https://gitlab.com/" + v
	}
	if v, ok := raw["avatar_url"].(string); ok {
		user.Avatar = v
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
		var verified bool
		if state, ok := raw["state"].(string); ok && state == "active" {
			verified = true
		}
		if user.Auths == nil {
			user.Auths = make([]*oauth.Auth, 0)
		}
		user.Auths = append(user.Auths, &oauth.Auth{
			Type:     "email",
			Value:    v,
			Verified: verified,
		})
	}
	return
}
