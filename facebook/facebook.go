package facebook

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	oauth "github.com/otamoe/oauth-api"
)

type (
	Client struct {
		oauth.OAuth2
	}
)

var Endpoint = oauth.Endpoint{
	Name:            "fackbook",
	AuthorizeURL:    "https://www.facebook.com/dialog/oauth",
	AccessTokenURL:  "https://graph.facebook.com/v3.0/oauth/access_token",
	RefreshTokenURL: "https://graph.facebook.com/v3.0/oauth/access_token",
	APIURL:          "https://graph.facebook.com/v3.0",
	ClientHeader:    "Basic",
	TokenHeader:     "Bearer",
}

func (c *Client) FbExchangeToken(ctx context.Context, oldToken *oauth.Token, values url.Values) (newToken *oauth.Token, err error) {
	if oldToken.ClientID != "" && oldToken.ClientID != c.ClientID {
		err = oauth.NewError("Token.ClientID does not match", 500)
		return
	}

	AppendValues := url.Values{
		"grant_type":        {"fb_exchange_token"},
		"fb_exchange_token": {oldToken.AccessToken},
	}
	newToken = oldToken.Copy()
	err = c.RequestToken(ctx, c.Endpoint.AccessTokenURL, newToken, values, AppendValues)
	return
}

func (c *Client) ClientCode(ctx context.Context, token *oauth.Token, values url.Values) (code string, err error) {
	if token.ClientID != "" && token.ClientID != c.ClientID {
		err = oauth.NewError("Token.ClientID does not match", 500)
		return
	}
	defaultValues := url.Values{
		"redirect_uri": {c.RedirectURI},
	}
	AppendValues := url.Values{
		"access_token": {token.AccessToken},
	}
	values = oauth.MergeValues(false, defaultValues, values, AppendValues)

	var req *http.Request
	if req, err = http.NewRequest("POST", c.Endpoint.APIURL+"/oauth/client_code", strings.NewReader(values.Encode())); err != nil {
		return
	}
	httpClient := oauth.HTTPClient(ctx, c, nil)

	var raw map[string]interface{}
	if raw, err = c.Response(ctx, httpClient, req); err != nil {
		return
	}
	var ok bool
	if code, ok = raw["code"].(string); !ok || code == "" {
		err = oauth.NewError("Raw.code is empty", 500)
		return
	}
	return
}

func (c *Client) User(ctx context.Context, token *oauth.Token) (user *oauth.User, err error) {
	now := time.Now()
	var req *http.Request
	if req, err = http.NewRequest("GET", c.Endpoint.APIURL+"/me?fields=first_name,address,birthday,email,context,gender,id,last_name,name,name_format,short_name,link,location,languages,hometown,middle_name,picture.type(large).redirect(false)", nil); err != nil {
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

	if v, ok := raw["last_name"].(string); ok {
		user.FamilyName = v
	}
	if v, ok := raw["first_name"].(string); ok {
		user.GivenName = v
	}
	if v, ok := raw["name"].(string); ok {
		user.Nickname = v
		user.Name = v
	}
	if v, ok := raw["name"].(string); ok {
		user.Nickname = v
		user.Name = v
	}
	if v, ok := raw["birthday"].(string); ok && v != "" {
		if birthday, err := time.Parse("01/02/2006", v); err == nil {
			user.Birthday = &birthday
		}
	}
	if v, ok := raw["picture"].(map[string]interface{}); ok {
		if v, ok := v["data"].(map[string]interface{}); ok {
			if v, ok := v["url"].(string); ok {
				user.Avatar = v
			}
		}
	}
	if v, ok := raw["gender"].(string); ok {
		if v == "male" || v == "female" {
			user.Gender = v
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
