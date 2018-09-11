package amazon

import (
	"context"
	"net/http"
	"time"

	"github.com/otamoe/oauth-client"
)

type (
	Client struct {
		oauth.OAuth2
	}
)

var Endpoint = oauth.Endpoint{
	Name:            "amazon",
	AuthorizeURL:    "https://www.amazon.com/ap/oa",
	AccessTokenURL:  "https://api.amazon.com/auth/o2/token",
	RefreshTokenURL: "https://api.amazon.com/auth/o2/token",
	APIURL:          "https://drive.amazonaws.com",
	ClientHeader:    "Basic",
	TokenHeader:     "Bearer",
}

// https://drive.amazonaws.com/drive/v1/account/endpoint

func (c *Client) User(ctx context.Context, token *oauth.Token) (user *oauth.User, err error) {
	now := time.Now()
	var req *http.Request
	if req, err = http.NewRequest("GET", "https://api.amazon.com/user/profile", nil); err != nil {
		return
	}

	httpClient := oauth.HTTPClient(ctx, c, token)

	var raw map[string]interface{}
	if raw, err = c.Response(ctx, httpClient, req); err != nil {
		return
	}

	user = &oauth.User{
		ID:      raw["user_id"].(string),
		Raw:     raw,
		Updated: &now,
	}
	if v, ok := raw["name"].(string); ok {
		user.Username = v
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
