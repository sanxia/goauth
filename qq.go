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
 * 初始化Qq授权
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func NewQq(clientId, clientSecret, callbackUri string) IOauth {
	oauth := new(OauthQq)
	oauth.ClientId = clientId
	oauth.ClientSecret = clientSecret
	oauth.CallbackUri = callbackUri

	oauth.AuthorizeCodeUri = "https://graph.qq.com/oauth2.0/authorize"
	oauth.AccessTokenUri = "https://graph.qq.com/oauth2.0/token"
	oauth.RefreshTokenUri = "https://graph.qq.com/oauth2.0/token"
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
	case RefreshTokenUri:
		s.RefreshTokenUri = uri
	case OpenIdUri:
		s.OpenIdUri = uri
	case UserInfoUri:
		s.UserInfoUri = uri
	}
}

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 获取鉴权地址
 * state, scope
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func (s *OauthQq) GetAuthorizeUrl(args ...string) string {
	state, scope := "qq", "get_user_info"
	display := "mobile"

	argCount := len(args)
	if argCount > 0 {
		state = args[0]

		if argCount > 1 {
			scope = args[1]
		}
	}

	param := ""
	params := map[string]string{
		"client_id":     s.ClientId,
		"redirect_uri":  glib.UrlEncode(s.CallbackUri),
		"display":       display,
		"scope":         scope,
		"state":         state,
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
	param := ""
	params := map[string]string{
		"client_id":     s.ClientId,
		"client_secret": s.ClientSecret,
		"redirect_uri":  glib.UrlEncode(s.CallbackUri),
		"code":          code,
		"grant_type":    "authorization_code",
	}

	for k, v := range params {
		param = param + fmt.Sprintf("%s=%s&", k, v)
	}
	param = param[0 : len(param)-1]

	//获取api接口响应数据
	resp, err := glib.HttpGet(s.AccessTokenUri, param)
	if err == nil {
		//响应数据解析
		accessToken, refreshToken, expiresIn := ParseAccessTokenForQq(resp)
		s.Token = &OauthToken{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    expiresIn,
			RawContent:   resp,
		}

		if s.Token.AccessToken != "" {
			if openId, err := s.GetOpenId(s.Token.AccessToken); err == nil {
				s.Token.OpenId = openId
			}
		}
	}

	return s.Token, err
}

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 刷新AccessToken
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func (s *OauthQq) RefreshAccessToken(refreshToken string) (*OauthToken, error) {
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

	//获取api接口响应数据
	resp, err := glib.HttpGet(s.RefreshTokenUri, param)
	if err == nil {
		//响应数据解析
		accessToken, refreshToken, expiresIn := ParseAccessTokenForQq(resp)
		s.Token.AccessToken = accessToken
		s.Token.RefreshToken = refreshToken
		s.Token.ExpiresIn = expiresIn
		s.Token.RawContent = resp
	}

	return s.Token, err
}

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 获取OpenId
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func (s *OauthQq) GetOpenId(accessToken string) (string, error) {
	openId := ""
	param := fmt.Sprintf("%s=%s", "access_token", accessToken)

	//获取api接口响应数据
	resp, err := glib.HttpGet(s.OpenIdUri, param)
	if err == nil {
		//响应数据解析
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

	//获取api接口响应数据
	resp, err := glib.HttpGet(s.UserInfoUri, param)
	if err == nil {
		//响应数据解析
		oauthUser = ParseUserInfoForQq(resp)
		if oauthUser == nil {
			oauthUser = new(OauthUser)
		}
		oauthUser.RawContent = resp
	}

	return oauthUser, err
}
