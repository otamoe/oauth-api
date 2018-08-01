package line

import (
	"context"
	"net/http"
	"time"

	oauth "github.com/otamoe/oauth-api"
)

type (
	Client struct {
		oauth.OAuth2
	}
)

var Endpoint = oauth.Endpoint{
	Name:           "line",
	AuthorizeURL:   "https://access.line.me/oauth2/v2.1/authorize",
	AccessTokenURL: "https://api.line.me/oauth2/v2.1/token",
	RevokeTokenURL: "https://api.line.me/oauth2/v2.1/token",
	APIURL:         "https://api.line.me/v2",
	ClientHeader:   "Basic",
	TokenHeader:    "Bearer",
}

func (c *Client) User(ctx context.Context, token *oauth.Token) (user *oauth.User, err error) {
	now := time.Now()
	var req *http.Request
	if req, err = http.NewRequest("GET", c.Endpoint.APIURL+"/profile", nil); err != nil {
		return
	}
	httpClient := oauth.HTTPClient(ctx, c, token)

	var raw map[string]interface{}
	if raw, err = c.Response(ctx, httpClient, req); err != nil {
		return
	}

	user = &oauth.User{
		ID:      raw["userId"].(string),
		Raw:     raw,
		Updated: &now,
	}

	if v, ok := raw["displayName"].(string); ok {
		user.Nickname = v
	}
	if v, ok := raw["pictureUrl"].(string); ok {
		user.Avatar = v
	}
	return
}
