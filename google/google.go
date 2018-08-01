package google

import (
	"context"
	"net/http"
	"time"

	oauth "github.com/lian-yue/oauth-api"
)

type (
	Client struct {
		oauth.OAuth2
	}
)

var Endpoint = oauth.Endpoint{
	Name:            "google",
	AuthorizeURL:    "https://accounts.google.com/o/oauth2/auth",
	AccessTokenURL:  "https://accounts.google.com/o/oauth2/token",
	RefreshTokenURL: "https://accounts.google.com/o/oauth2/token",
	RevokeTokenURL:  "https://accounts.google.com/o/oauth2/revoke",
	APIURL:          "https://www.googleapis.com",
	ClientHeader:    "Basic",
	TokenHeader:     "Bearer",
}

func (c *Client) User(ctx context.Context, token *oauth.Token) (user *oauth.User, err error) {
	now := time.Now()
	var req *http.Request
	// if req, err = http.NewRequest("GET", c.Endpoint.APIURL+"/userinfo/v2/me", nil); err != nil {
	if req, err = http.NewRequest("GET", c.Endpoint.APIURL+"/oauth2/v2/userinfo", nil); err != nil {
		return
	}
	httpClient := oauth.HTTPClient(ctx, c, token)

	var raw map[string]interface{}
	if raw, err = c.Response(ctx, httpClient, req); err != nil {
		return
	}

	user = &oauth.User{
		ID:      raw["id"].(string),
		Raw:     raw,
		Updated: &now,
	}

	if v, ok := raw["family_name"].(string); ok {
		user.FamilyName = v
	}
	if v, ok := raw["given_name"].(string); ok {
		user.GivenName = v
	}
	if v, ok := raw["name"].(string); ok {
		user.Name = v
	}
	if v, ok := raw["picture"].(string); ok {
		user.Avatar = v
	}
	if v, ok := raw["locale"].(string); ok {
		user.Locale = oauth.FormatLocale(v)
	}
	if v, ok := raw["gender"].(string); ok {
		user.Gender = v
	}
	if v, ok := raw["link"].(string); ok {
		user.Link = v
	}

	if v, ok := raw["email"].(string); ok && v != "" {
		verified, _ := raw["verified_email"].(bool)
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
