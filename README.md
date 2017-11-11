# goauth
Oauth2 QQ and WeChat for Golang

Example:
---------------

oauthQQ := goauth.NewOauthQq("you app id", "you app secret", "you callback url")

token, err := oauthQQ.GetAccessToken(code)

openId, err := oauthQQ.GetOpenId(token.AccessToken)

oauthUserInfo, err := oauthQQ.GetUserInfo(token.AccessToken, openId)
