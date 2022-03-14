package goauth

/* ================================================================================
 * Oauth Token
 * qq group: 582452342
 * email   : 2091938785@qq.com
 * author  : 美丽的地球啊 - mliu
 * ================================================================================ */
type OauthToken struct {
	AccessToken  string
	RefreshToken string
	OpenId       string
	UnionId      string
	ExpiresIn    int
	Scope        string
}