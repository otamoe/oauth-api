package oauth

import "time"

type (
	Token struct {
		ClientID     string                 `json:"client_id"`
		TokenType    string                 `json:"token_type,omitempty"`
		AccessToken  string                 `json:"access_token"`
		TokenSecret  string                 `json:"token_secret,omitempty"`
		RefreshToken string                 `json:"refresh_token,omitempty"`
		IDToken      string                 `json:"id_token,omitempty"`
		OpenID       string                 `json:"openid,omitempty"`
		Scopes       []string               `json:"scopes,omitempty"`
		Raw          map[string]interface{} `json:"params,omitempty"`
		User         *User                  `json:"user,omitempty"`
		Created      *time.Time             `json:"created"`
		Updated      *time.Time             `json:"updated"`
		Expired      *time.Time             `json:"expired,omitempty"`
	}

	User struct {
		ID          string                 `json:"id"`
		Username    string                 `json:"username,omitempty"`
		Nickname    string                 `json:"nickname,omitempty"`
		Name        string                 `json:"name,omitempty"`
		FamilyName  string                 `json:"family_name,omitempty"`
		GivenName   string                 `json:"given_name,omitempty"`
		Avatar      string                 `json:"avatar,omitempty"`
		Gender      string                 `json:"gender,omitempty"`
		Locale      string                 `json:"locale,omitempty"`
		Description string                 `json:"description,omitempty"`
		Link        string                 `json:"link,omitempty"`
		Auths       []*Auth                `json:"auths,omitempty"`
		Raw         map[string]interface{} `json:"raw,omitempty"`
		Birthday    *time.Time             `json:"birthday,omitempty"`
		Created     *time.Time             `json:"created,omitempty"`
		Updated     *time.Time             `json:"updated"`
	}

	Auth struct {
		Type     string `json:"type"`
		Value    string `json:"value"`
		Verified bool   `json:"verified,omitempty"`
	}
)

func (t Token) Copy() (token *Token) {
	if t.Scopes != nil {
		scopes := make([]string, len(t.Scopes))
		copy(scopes, t.Scopes)
		t.Scopes = scopes
	}
	if t.Raw != nil {
		raw := make(map[string]interface{}, len(t.Raw))
		for key, val := range t.Raw {
			raw[key] = val
		}
		t.Raw = raw
	}
	if t.User != nil {
		user2 := *t.User
		user3 := user2
		t.User = &user3
	}
	token = &t
	return
}
