package oauth

type (
	Error struct {
		Message string
		Status  int
	}
)

var ErrCancel = NewError("access_cancel", 403)
var ErrDenied = NewError("access_denied", 403)
var ErrTokenExpired = NewError("token_expired", 401)
var ErrTokenInvalid = NewError("token_invalid", 401)

func (e Error) Error() string {
	return e.Message
}

func NewError(message string, status int) error {
	return &Error{
		Message: message,
		Status:  status,
	}
}
