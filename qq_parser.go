package goauth

import (
	"regexp"
	"strconv"
)

/* ================================================================================
 * Oauth Qq
 * qq group: 582452342
 * email   : 2091938785@qq.com
 * author  : 美丽的地球啊 - mliu
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
