package microsoft

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/otamoe/oauth-client"
)

//  https://apps.dev.microsoft.com/portal/register-app
type (
	Client struct {
		oauth.OAuth2
	}
)

var Endpoint = oauth.Endpoint{
	Name:            "microsoft",
	AuthorizeURL:    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
	AccessTokenURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/token",
	RefreshTokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
	APIURL:          "https://graph.microsoft.com/v1.0",
	TokenHeader:     "Bearer",
}

func (c *Client) User(ctx context.Context, token *oauth.Token) (user *oauth.User, err error) {
	now := time.Now()
	var req *http.Request
	if req, err = http.NewRequest("GET", c.Endpoint.APIURL+"/me", nil); err != nil {
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

	if v, ok := raw["displayName"].(string); ok && v != "" {
		user.Nickname = v
	}
	if v, ok := raw["givenName"].(string); ok {
		user.GivenName = v
	}
	if v, ok := raw["surname"].(string); ok {
		user.FamilyName = v
	}

	if v, ok := raw["mail"].(string); ok && v != "" {
		if user.Auths == nil {
			user.Auths = make([]*oauth.Auth, 0)
		}
		user.Auths = append(user.Auths, &oauth.Auth{
			Type:     "email",
			Value:    v,
			Verified: true,
		})
	}
	if v, ok := raw["userPrincipalName"].(string); ok && v != "" && strings.IndexAny(v, "@") != -1 {
		if user.Auths == nil {
			user.Auths = make([]*oauth.Auth, 0)
		}
		user.Auths = append(user.Auths, &oauth.Auth{
			Type:     "email",
			Value:    v,
			Verified: false,
		})
	}
	if v, ok := raw["mobilePhone"].(string); ok && v != "" {
		if user.Auths == nil {
			user.Auths = make([]*oauth.Auth, 0)
		}
		user.Auths = append(user.Auths, &oauth.Auth{
			Type:     "mobile_phone",
			Value:    v,
			Verified: true,
		})
	}
	return
}
