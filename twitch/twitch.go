package twitch

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
	Name:            "twitch",
	AuthorizeURL:    "https://id.twitch.tv/oauth2/authorize",
	AccessTokenURL:  "https://id.twitch.tv/oauth2/token",
	RefreshTokenURL: "https://id.twitch.tv/oauth2/token",
	RevokeTokenURL:  "https://id.twitch.tv/oauth2/revoke",
	APIURL:          "https://api.twitch.tv/helix",
	ClientHeader:    "Bearer",
	TokenHeader:     "Bearer",
}

func (c *Client) User(ctx context.Context, token *oauth.Token) (user *oauth.User, err error) {
	now := time.Now()
	var req *http.Request
	if req, err = http.NewRequest("GET", c.Endpoint.APIURL+"/users", nil); err != nil {
		return
	}
	httpClient := oauth.HTTPClient(ctx, c, token)

	var raw map[string]interface{}
	if raw, err = c.Response(ctx, httpClient, req); err != nil {
		return
	}
	var ok bool
	var data []interface{}
	if data, ok = raw["data"].([]interface{}); !ok || data == nil || len(data) == 0 {
		err = oauth.NewError("raw.data is empty", 500)
		return
	}
	if raw, ok = data[0].(map[string]interface{}); !ok || raw == nil || len(raw) == 0 {
		err = oauth.NewError("raw.data is empty", 500)
		return
	}
	user = &oauth.User{
		ID:      raw["id"].(string),
		Raw:     raw,
		Updated: &now,
	}

	if v, ok := raw["login"].(string); ok {
		user.Username = v
	}
	if v, ok := raw["display_name"].(string); ok {
		user.Nickname = v
	}
	if v, ok := raw["profile_image_url"].(string); ok {
		user.Avatar = v
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
