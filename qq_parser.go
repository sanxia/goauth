package goauth

import (
	"regexp"
	"strconv"
)

/* ================================================================================
 * Oauth Qq
 * qq group: 582452342
 * email   : 2091938785@qq.com
 * author  : 美丽的地球啊
 * ================================================================================ */

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 解析QQ返回的AccessToken
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func ParseAccessTokenForQq(source string) (string, string, int) {
	accessToken := ""
	refreshToken := ""
	var expiresIn int

	if source != "" {
		pattern := "access_token=(.*).+expires_in=(.*).+refresh_token=(.*)"
		re, _ := regexp.Compile(pattern)
		if matchs := re.FindStringSubmatch(source); len(matchs) == 4 {
			accessToken = matchs[1]
			if matchs[2] != "" {
				if _expiresIn, err := strconv.Atoi(matchs[2]); err == nil {
					expiresIn = _expiresIn
				}
			}

			refreshToken = matchs[3]
		}
	}

	return accessToken, refreshToken, expiresIn
}

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 解析QQ返回的OpenId
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func ParseOpenIdForQq(source string) string {
	openId := ""

	if source != "" {
		pattern := "callback.+{\"client_id\":\"(.*)\",\"openid\":\"(.*)\"\\}.+"
		re, _ := regexp.Compile(pattern)
		if matchs := re.FindStringSubmatch(source); len(matchs) == 3 {
			openId = matchs[2]
		}
	}

	return openId
}

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 解析QQ返回的UserInfo
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func ParseUserInfoForQq(source string) *OauthUser {
	var oauthUser *OauthUser

	if source != "" {
		pattern := "\"nickname\":\"(.*?)\".+\"figureurl_qq_1\":\"(.*?)\".+\"figureurl_qq_2\":\"(.*?)\".+\"gender\":\"(.*?)\""
		re, _ := regexp.Compile(pattern)
		if matchs := re.FindStringSubmatch(source); len(matchs) == 5 {
			nickname := matchs[1]
			avatar40 := matchs[2]
			avatar100 := matchs[3]
			gender := matchs[4]

			if gender == "男" {
				gender = "male"
			} else if gender == "女" {
				gender = "female"
			} else {
				gender = "secret"
			}

			if avatar100 != "" {
				avatar40 = avatar100
			}

			oauthUser = &OauthUser{
				Nickname: nickname,
				Avatar:   avatar40,
				Sex:      gender,
			}
		}
	}

	return oauthUser
}
