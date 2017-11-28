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
	QqUserInfoResponse struct {
		Ret             int    `form:"ret" json:"ret"`
		Msg             string `form:"msg" json:"msg"`
		Nickname        string `form:"nickname" json:"nickname"`                     //昵称
		Gender          string `form:"gender" json:"gender"`                         //性别。 如果获取不到则默认返回"男"
		Year            string `form:"year" json:"year"`                             //出生年
		Province        string `form:"province" json:"province"`                     //省
		City            string `form:"city" json:"city"`                             //市
		FigureUrl       string `form:"figureurl" json:"figureurl"`                   //大小为30×30像素的QQ空间头像URL
		FigureUrl1      string `form:"figureurl_1" json:"figureurl_1"`               //大小为50×50像素的QQ空间头像URL
		FigureUrl2      string `form:"figureurl_2" json:"figureurl_2"`               //大小为100×100像素的QQ空间头像URL
		FigureUrlQq1    string `form:"figureurl_qq_1" json:"figureurl_qq_1"`         //大小为40×40像素的QQ头像URL
		FigureUrlQq2    string `form:"figureurl_qq_2" json:"figureurl_qq_2"`         //大小为100×100像素的QQ头像URL。需要注意，不是所有的用户都拥有QQ的100x100的头像，但40x40像素则是一定会有
		Vip             string `form:"vip" json:"vip"`                               //标识用户是否为黄钻用户（0：不是；1：是）
		Level           string `form:"level" json:"level"`                           //黄钻等级
		YellowVipLevel  string `form:"yellow_vip_level" json:"yellow_vip_level"`     //黄钻等级
		IsYellowVip     string `form:"is_yellow_vip" json:"is_yellow_vip"`           //标识用户是否为黄钻用户（0：不是；1：是）
		IsYellowYearVip string `form:"is_yellow_year_vip" json:"is_yellow_year_vip"` //标识是否为年费黄钻用户（0：不是； 1：是）
	}

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
 * args: state, scope
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func (s *OauthQq) GetAuthorizeUrl(args ...string) string {
	state, scope, display := "qq", "get_user_info", "mobile"

	argCount := len(args)
	if argCount > 0 {
		state = args[0]

		if argCount > 1 {
			scope = args[1]
		}

		if argCount > 2 {
			display = args[2]
		}
	}

	params := map[string]interface{}{
		"client_id":     s.ClientId,
		"redirect_uri":  glib.QueryEncode(s.CallbackUri),
		"display":       display,
		"scope":         scope,
		"state":         state,
		"response_type": "code",
	}

	queryString := glib.ToQueryString(params)

	return s.AuthorizeCodeUri + "?" + queryString
}

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 获取AccessToken
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func (s *OauthQq) GetAccessToken(code string) (*OauthToken, error) {
	var oauthToken *OauthToken

	params := map[string]interface{}{
		"client_id":     s.ClientId,
		"client_secret": s.ClientSecret,
		"redirect_uri":  glib.QueryEncode(s.CallbackUri),
		"code":          code,
		"grant_type":    "authorization_code",
	}

	queryString := glib.ToQueryString(params)

	//获取api响应数据
	resp, err := glib.HttpGet(s.AccessTokenUri, queryString)
	if err == nil {
		//响应数据解析
		accessToken, refreshToken, expiresIn := ParseAccessTokenForQq(resp)

		oauthToken = &OauthToken{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    expiresIn,
		}

		if oauthToken.AccessToken != "" {
			if openId, err := s.GetOpenId(oauthToken.AccessToken); err == nil {
				oauthToken.OpenId = openId
			}
		}
	}

	return oauthToken, err
}

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 刷新AccessToken
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func (s *OauthQq) RefreshAccessToken(refreshToken string) (*OauthToken, error) {
	var oauthToken *OauthToken

	params := map[string]interface{}{
		"client_id":     s.ClientId,
		"client_secret": s.ClientSecret,
		"refresh_token": refreshToken,
		"grant_type":    "refresh_token",
	}

	queryString := glib.ToQueryString(params)

	//获取api响应数据
	resp, err := glib.HttpGet(s.RefreshTokenUri, queryString)
	if err == nil {
		//响应数据解析
		accessToken, refreshToken, expiresIn := ParseAccessTokenForQq(resp)
		oauthToken = &OauthToken{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    expiresIn,
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

	//获取api响应数据
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
	params := map[string]interface{}{
		"oauth_consumer_key": s.ClientId,
		"access_token":       accessToken,
		"openid":             openId,
		"format":             "json",
	}

	queryString := glib.ToQueryString(params)

	//获取api响应数据
	resp, err := glib.HttpGet(s.UserInfoUri, queryString)
	if err == nil {
		//解析json数据
		var response *QqUserInfoResponse
		err = glib.FromJson(resp, &response)
		if err == nil && response.Ret == 0 {
			oauthUser = new(OauthUser)
			oauthUser.Nickname = response.Nickname

			avatar := response.FigureUrlQq2
			if avatar == "" {
				avatar = response.FigureUrlQq1
			}
			oauthUser.Avatar = avatar

			sex := "secret"
			if response.Gender == "男" {
				sex = "male"
			} else if response.Gender == "女" {
				sex = "female"
			}

			oauthUser.Sex = sex
			oauthUser.Year = response.Year
			oauthUser.Province = response.Province
			oauthUser.City = response.City
		}
	}

	return oauthUser, err
}
