package goauth

import (
	"fmt"
	"time"
)

import (
	"github.com/sanxia/glib"
)

/* ================================================================================
 * Oauth State
 * qq group: 582452342
 * email   : 2091938785@qq.com
 * author  : 美丽的地球啊 - mliu
 * ================================================================================ */
type (
	OauthState struct {
		encryptKey string //密钥
		minutes    int    //有效分钟数
	}
)

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 初始化OauthState
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func NewOauthState(encryptKey string, minutes int) *OauthState {
	return &OauthState{
		encryptKey: encryptKey,
		minutes:    minutes,
	}
}

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 获取状态值
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func (s *OauthState) GetState() string {
	state := glib.ToBase64(glib.Guid())
	expired := glib.ToBase64(fmt.Sprintf("%d", glib.DatetimeAddMinute(time.Now(), s.minutes).Unix()))
	sign := glib.HmacSha256(fmt.Sprintf("%s.%s", state, expired), s.encryptKey)

	return glib.ToBase64(fmt.Sprintf("%s.%d.%s", state, expired, sign), true)
}

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 判断状态值是否有效
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
func (s *OauthState) IsValid(rawState string) bool {
	if len(rawState) == 0 {
		return false
	}

	state, err := glib.FromBase64(rawState, true)
	if err != nil {
		return false
	}

	states := glib.StringToStringSlice(state, ".")
	if len(states) != 3 {
		return false
	}

	//签名是否有效
	if sign := glib.HmacSha256(fmt.Sprintf("%s.%s", states[0], states[1]), s.encryptKey); sign != states[3] {
		return false
	}

	//是否过期
	expired, err := glib.FromBase64(states[1])
	if err != nil {
		return false
	}

	expiredDate := glib.UnixTimestampToDate(glib.StringToInt64(expired))
	if isExpired := time.Now().UTC().After(expiredDate); isExpired {
		return false
	}

	return true
}
