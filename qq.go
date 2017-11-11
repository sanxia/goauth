package goauth

import (
	"fmt"
)

import (
	"github.com/sanxia/glib"
)

/* ================================================================================
 * Oauth Qq
 * qq group: 582452342
 * email   : 2091938785@qq.com
 * author  : 美丽的地球啊
 * ================================================================================ */

type (
	OauthQq struct {
		Oauth
	}
)

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 新Oauth
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func NewOauthQq(clientId, clientSecret, callbackUri string) IOauth {
	defaultCallbackUri := "http://www.woshiyiren.com/passport/oauth/qq/callback"
	if callbackUri == "" {
		callbackUri = defaultCallbackUri
	}
	oauth := new(OauthQq)
	oauth.ClientId = clientId
	oauth.ClientSecret = clientSecret
	oauth.CallbackUri = callbackUri

	oauth.AuthorizeCodeUri = "https://graph.qq.com/oauth2.0/authorize"
	oauth.AccessTokenUri = "https://graph.qq.com/oauth2.0/token"
	oauth.OpenIdUri = "https://graph.qq.com/oauth2.0/me"
	oauth.UserInfoUri = "https://graph.qq.com/user/get_user_info"

	return oauth
}

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 设置Uri
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func (s *OauthQq) SetUri(uriType OauthUriType, uri string) {
	switch uriType {
	case AuthorizeCodeUri:
		s.AuthorizeCodeUri = uri
	case AccessTokenUri:
		s.AccessTokenUri = uri
	case OpenIdUri:
		s.OpenIdUri = uri
	case UserInfoUri:
		s.UserInfoUri = uri
	}
}

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 设置Scope
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func (s *OauthQq) SetScope(scope string) {
	s.Scope = scope
}

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 获取鉴权地址
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func (s *OauthQq) GetAuthorizeUrl() string {
	display := "mobile"
	scope := s.Scope
	if s.Scope == "" {
		scope = "get_user_info"
	}

	param := ""
	params := map[string]string{
		"client_id":     s.ClientId,
		"redirect_uri":  s.CallbackUri,
		"display":       display,
		"scope":         scope,
		"state":         "qq",
		"response_type": "code",
	}

	for k, v := range params {
		param = param + fmt.Sprintf("%s=%s&", k, v)
	}

	param = param[0 : len(param)-1]

	return s.AuthorizeCodeUri + "?" + param
}

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 获取AccessToken
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func (s *OauthQq) GetAccessToken(code string) (*OauthToken, error) {
	var oauthToken *OauthToken
	param := ""
	params := map[string]string{
		"client_id":     s.ClientId,
		"client_secret": s.ClientSecret,
		"redirect_uri":  s.CallbackUri,
		"code":          code,
		"grant_type":    "authorization_code",
	}

	for k, v := range params {
		param = param + fmt.Sprintf("%s=%s&", k, v)
	}
	param = param[0 : len(param)-1]

	resp, err := glib.HttpGet(s.AccessTokenUri, param)
	if err == nil {
		accessToken, refreshToken, expiresIn := ParseAccessTokenForQq(resp)
		oauthToken = &OauthToken{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    expiresIn,
			RawContent:   resp,
		}
	}

	return oauthToken, err
}

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 刷新AccessToken
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func (s *OauthQq) RefreshAccessToken(refreshToken string) (*OauthToken, error) {
	var oauthToken *OauthToken

	param := ""
	params := map[string]string{
		"client_id":     s.ClientId,
		"client_secret": s.ClientSecret,
		"refresh_token": refreshToken,
		"grant_type":    "refresh_token",
	}

	for k, v := range params {
		param = param + fmt.Sprintf("%s=%s&", k, v)
	}

	param = param[0 : len(param)-1]
	resp, err := glib.HttpGet(s.AccessTokenUri, param)
	if err == nil {
		accessToken, refreshToken, expiresIn := ParseAccessTokenForQq(resp)
		oauthToken = &OauthToken{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    expiresIn,
			RawContent:   resp,
		}
	}

	return oauthToken, err
}

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 获取OpenId
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func (s *OauthQq) GetOpenId(accessToken string) (string, error) {
	openId := ""
	param := fmt.Sprintf("%s=%s", "access_token", accessToken)
	resp, err := glib.HttpGet(s.OpenIdUri, param)
	if err == nil {
		openId = ParseOpenIdForQq(resp)
	}

	return openId, err
}

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 获取用户信息
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func (s *OauthQq) GetUserInfo(accessToken, openId string) (*OauthUser, error) {
	var oauthUser *OauthUser
	param := ""
	params := map[string]string{
		"oauth_consumer_key": s.ClientId,
		"access_token":       accessToken,
		"openid":             openId,
		"format":             "json",
	}

	for k, v := range params {
		param = param + fmt.Sprintf("%s=%s&", k, v)
	}

	param = param[0 : len(param)-1]
	resp, err := glib.HttpGet(s.UserInfoUri, param)
	if err == nil {
		oauthUser = ParseUserInfoForQq(resp)
		if oauthUser == nil {
			oauthUser = new(OauthUser)
		}
		oauthUser.RawContent = resp
	}

	return oauthUser, err
}
