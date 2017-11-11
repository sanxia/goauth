package goauth

/* ================================================================================
 * Oauth
 * qq group: 582452342
 * email   : 2091938785@qq.com
 * author  : 美丽的地球啊
 * ================================================================================ */

const (
	AuthorizeCodeUri OauthUriType = iota
	AccessTokenUri
	OpenIdUri
	UserInfoUri
)

type (
	OauthUriType int

	IOauth interface {
		SetUri(uriType OauthUriType, uri string)
		SetScope(scope string)

		GetAuthorizeUrl() string
		GetAccessToken(code string) (*OauthToken, error)
		RefreshAccessToken(refreshToken string) (*OauthToken, error)
		GetOpenId(accessToken string) (string, error)
		GetUserInfo(accessToken, openId string) (*OauthUser, error)
	}

	Oauth struct {
		ClientId     string //app id
		ClientSecret string //app secret

		CallbackUri      string //回调地址
		AuthorizeCodeUri string //请求code地址
		AccessTokenUri   string //请求access_token地址
		OpenIdUri        string //请求open_id地址
		UserInfoUri      string //请求用户信息地址

		Scope string
	}

	OauthToken struct {
		AccessToken  string
		RefreshToken string
		ExpiresIn    int
		RawContent   string
	}

	OauthUser struct {
		Avatar     string
		Nickname   string
		Sex        string
		RawContent string
	}
)
