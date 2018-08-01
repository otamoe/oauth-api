package twitter

import (
	"context"
	"net/http"
	"strings"
	"time"

	oauth "github.com/lian-yue/oauth-api"
)

type (
	Client struct {
		oauth.OAuth1
	}
)

var Endpoint = oauth.Endpoint{
	Name:           "twitter",
	RequestURL:     "https://api.twitter.com/oauth/request_token",
	AuthorizeURL:   "https://api.twitter.com/oauth/authorize",
	AccessTokenURL: "https://api.twitter.com/oauth/access_token",
	APIURL:         "https://api.twitter.com/1.1",
}

func (c *Client) User(ctx context.Context, token *oauth.Token) (user *oauth.User, err error) {
	now := time.Now()
	var req *http.Request
	if req, err = http.NewRequest("GET", c.Endpoint.APIURL+"/account/verify_credentials.json?include_email=true", nil); err != nil {
		return
	}
	httpClient := oauth.HTTPClient(ctx, c, token)

	var raw map[string]interface{}
	if raw, err = c.Response(ctx, httpClient, req); err != nil {
		return
	}

	user = &oauth.User{
		ID:      raw["id_str"].(string),
		Raw:     raw,
		Updated: &now,
	}

	if v, ok := raw["created_at"].(string); ok && v != "" {
		if created, err := time.Parse(time.RubyDate, v); err == nil {
			user.Created = &created
		}
	}

	if v, ok := raw["screen_name"].(string); ok && v != "" {
		user.Username = v
		user.Link = "https://twitter.com/" + v
	}
	if v, ok := raw["name"].(string); ok {
		user.Name = v
	}
	if v, ok := raw["description"].(string); ok {
		user.Description = v
	}
	if v, ok := raw["profile_image_url_https"].(string); ok {
		user.Avatar = strings.Replace(v, "_normal.jpeg", ".jpeg", 1)
	}
	if v, ok := raw["lang"].(string); ok {
		user.Locale = oauth.FormatLocale(v)
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
