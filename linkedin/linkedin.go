package linkedin

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
	Name:            "linkedin",
	AuthorizeURL:    "https://www.linkedin.com/oauth/v2/authorization",
	AccessTokenURL:  "https://www.linkedin.com/oauth/v2/accessToken",
	RefreshTokenURL: "https://www.linkedin.com/oauth/v2/accessToken",
	APIURL:          "https://api.linkedin.com/v1",
	Errors:          []string{"message"},
	ClientHeader:    "",
	TokenHeader:     "Bearer",
}

func (c *Client) Signature(req *http.Request, token *oauth.Token, values url.Values) (err error) {
	if req.Header.Get("X-Li-Format") == "" {
		req.Header.Set("X-Li-Format", "json")
	}
	err = c.OAuth2.Signature(req, token, values)
	return
}

func (c *Client) User(ctx context.Context, token *oauth.Token) (user *oauth.User, err error) {
	now := time.Now()
	var req *http.Request
	if req, err = http.NewRequest("GET", c.Endpoint.APIURL+"/people/~:(id,first-name,last-name,maiden-name,formatted-name,phonetic-first-name,phonetic-last-name,formatted-phonetic-name,headline,location,industry,current-share,num-connections,num-connections-capped,summary,specialties,positions,picture-url,picture-urls::(original),site-standard-profile-request,api-standard-profile-request,public-profile-url,email-address)", nil); err != nil {
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

	if v, ok := raw["lastName"].(string); ok {
		user.FamilyName = v
	}
	if v, ok := raw["firstName"].(string); ok {
		user.GivenName = v
	}
	if v, ok := raw["formattedName"].(string); ok {
		user.Name = v
	}

	if v, ok := raw["publicProfileUrl"].(string); ok {
		user.Link = v
	}
	if v, ok := raw["emailAddress"].(string); ok && v != "" {
		if user.Auths == nil {
			user.Auths = make([]*oauth.Auth, 0)
		}
		user.Auths = append(user.Auths, &oauth.Auth{
			Type:     "email",
			Value:    v,
			Verified: true,
		})
	}
	if location, ok := raw["location"].(map[string]interface{}); ok && location != nil {
		if country, ok := location["country"].(map[string]interface{}); ok && country != nil {
			if code, ok := country["code"].(string); ok {
				user.Locale = oauth.FormatLocale(code)
			}
		}
	}
	return
}
