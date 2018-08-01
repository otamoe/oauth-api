package bitbucket

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
	Name:            "bitbucket",
	AuthorizeURL:    "https://bitbucket.org/site/oauth2/authorize",
	AccessTokenURL:  "https://bitbucket.org/site/oauth2/access_token",
	RefreshTokenURL: "https://bitbucket.org/site/oauth2/access_token",
	APIURL:          "https://api.bitbucket.org/2.0",
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
		ID:      raw["account_id"].(string),
		Raw:     raw,
		Updated: &now,
	}

	if v, ok := raw["username"].(string); ok && v != "" {
		user.Username = v
		user.Link = "https://bitbucket.com/" + v + "/"
	}
	if v, ok := raw["display_name"].(string); ok && v != "" {
		user.Nickname = v
	}
	if v, ok := raw["created_on"].(string); ok && v != "" {
		if created, err := time.Parse(time.RFC3339, v); err == nil {
			user.Created = &created
		}
	}
	if links, ok := raw["links"].(map[string]interface{}); ok && links != nil {
		if vv, ok := links["avatar"].(map[string]interface{}); ok && vv != nil {
			if vvv, ok := vv["href"].(string); ok && vvv != "" {
				user.Avatar = vvv
			}
		}
		if vv, ok := links["html"].(map[string]interface{}); ok && vv != nil {
			if vvv, ok := vv["href"].(string); ok && vvv != "" {
				user.Link = vvv
			}
		}
	}

	{
		if req, err := http.NewRequest("GET", c.Endpoint.APIURL+"/user/emails", nil); err == nil {
			if raw, err := c.Response(ctx, httpClient, req); err == nil {
				user.Raw["email"] = raw
				if values, ok := raw["values"].([]interface{}); ok && values != nil {
					for _, value := range values {
						if val, ok := value.(map[string]interface{}); ok && val != nil {
							if user.Auths == nil {
								user.Auths = make([]*oauth.Auth, 0)
							}
							user.Auths = append(user.Auths, &oauth.Auth{
								Type:     "email",
								Value:    val["email"].(string),
								Verified: val["is_confirmed"].(bool),
							})
						}
					}
				}
			}
		}
	}
	return
}
