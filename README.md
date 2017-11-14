# goauth
Oauth2 QQ and WeChat for Golang

Example:
---------------
import "github.com/sanxia/goauth"

//QQ oauth
qqOauth := goauth.NewQq("you app id", "you app secret", "you callback url")
qqToken, err := qqOauth.GetAccessToken(code)
qqUserInfo, err := qqOauth.GetUserInfo(qqToken.AccessToken, qqToken.OpenId)

//WeChat Oauth
weChatOauth := goauth.NewWeChat("you app id", "you app secret", "you callback url")
weChatToken, err := weChatOauth.GetAccessToken(code)
weChatUserInfo, err := weChatOauth.GetUserInfo(weChatToken.AccessToken, weChatToken.OpenId)
