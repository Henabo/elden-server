package controller

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/hiro942/elden-server/global"
	"github.com/hiro942/elden-server/model"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/utils"
	"github.com/hiro942/elden-server/utils/gxios"
	"github.com/tjfoc/gmsm/x509"
	"log"
	"time"
)

// @Summary authentication for normal(fast) access phrase
// @Router /auth/normal?type=hashed/encrypted [post]

func NormalAccess(c *gin.Context) {
	var (
		DefaultSuccessMessage = "normal authentication success"
		DefaultErrorMessage   = "normal authentication error"
	)

	// 解析请求体
	var NARWithSig request.MessageWithSig
	if err := c.ShouldBindJSON(&NARWithSig); err != nil {
		panic("failed to bind request")
	}

	// 取得URL参携带的参数
	keyType := c.Query("type")

	if keyType == "hashed" {

		NAR := utils.JsonUnmarshal[request.NAR[request.HashedSessionKey]](NARWithSig.Plain)

		// HTTP[GET] 获取用户信息
		user := gxios.QueryNodeById(NAR.HashedIMSI)

		// 判断账本中有无该设备的接入记录
		hasAccessRecord := false
		for _, record := range user.AccessRecord[NAR.MacAddr] {
			if record.SatelliteId == global.MySatelliteId {
				hasAccessRecord = true
				break
			}
		}

		// 无接入纪录，设备需要进行首次认证
		if !hasAccessRecord {
			response.FailWithDescription(DefaultErrorMessage, "the device have not accessed before", c)
			return
		}

		// 获取用户公钥
		userPublicKey, err := x509.ReadPublicKeyFromHex(user.PublicKey[NAR.MacAddr])
		if err != nil {
			log.Panic(fmt.Printf("failed to resolve public key: %+v", err))
		}

		// 验证消息签名
		if !utils.Sm2Verify(userPublicKey, NARWithSig.Plain, NARWithSig.Signature) {
			response.FailWithDescription(DefaultErrorMessage, "failed to verify signature", c)
			return
		}

		// 通过消息时间戳判断消息是否新鲜（replay-attach校验）
		if NAR.TimeStamp < time.Now().Unix()-15 {
			response.FailWithDescription(DefaultErrorMessage, "(replay) the message is not fresh", c)
			return
		}

		// 通过当前会话集合判断消息是否新鲜（replay-attach校验）
		if _, ok := global.CurrentSessions[NAR.HashedIMSI]; ok {
			response.FailWithDescription(DefaultErrorMessage, "(replay) user is now in session", c)
			return
		}

		// 验证请求内的卫星ID是否为自己
		if NAR.SatelliteId != global.MySatelliteId {
			response.FailWithDescription(DefaultErrorMessage, "wrong satellite id in request", c)
			return
		}

		// 读本地会话记录
		sessionRecordsFilePath := global.BaseSessionRecordsFilePath + fmt.Sprintf("%s.json", NAR.HashedIMSI)
		sessionRecords := utils.ReadSessionRecords(sessionRecordsFilePath)

		var currentSessionKey []byte
		var currentExpDate int64
		// 遍历到对应设备
		for _, record := range sessionRecords {
			if record.MacAddr == NAR.MacAddr {
				currentSessionKey = []byte(record.SessionKey)
				currentExpDate = record.ExpirationDate
				// 判断会话密钥哈希是否正确
				localSessionKeyHash := utils.Sm3Hash([]byte(record.SessionKey))
				if NAR.SessionKeyInfo.(string) != localSessionKeyHash {
					response.FailWithDescription(DefaultErrorMessage, "wrong session key", c)
					return
				}
				// 判断会话密钥是否过期
				if record.ExpirationDate < time.Now().Unix()+15 {
					response.FailWithDescription(DefaultErrorMessage, "session key has already expired", c)
					return
				}
				break
			}
		}

		// 记录当前会话
		global.CurrentSessions[NAR.HashedIMSI] = model.Session{
			SessionKey:     currentSessionKey,
			ExpirationDate: currentExpDate,
		}

		// 更新用户认证状态
		gxios.POST(
			fmt.Sprintf("%s/node/user/changeAuthStatus", global.FabricAppBaseUrl),
			request.ChangeAuthStatus{Id: NAR.HashedIMSI},
		)

		response.OKWithMessage(DefaultSuccessMessage, c)

	} else if keyType == "encrypted" {
		NAR := utils.JsonUnmarshal[request.NAR[request.SessionKeyKeyWithExpDate]](NARWithSig.Plain)

		// HTTP[GET] 获取用户信息
		user := gxios.QueryNodeById(NAR.HashedIMSI)

		// 判断账本中有无该设备的接入记录
		hasAccessRecord := false
		for _, record := range user.AccessRecord[NAR.MacAddr] {
			if record.SatelliteId == global.MySatelliteId {
				hasAccessRecord = true
				break
			}
		}

		// 无接入纪录，设备需要进行首次认证
		if !hasAccessRecord {
			response.FailWithDescription(DefaultErrorMessage, "the device have not accessed before", c)
			return
		}

		// 获取用户公钥
		userPublicKey, err := x509.ReadPublicKeyFromHex(user.PublicKey[NAR.MacAddr])
		if err != nil {
			log.Panic(fmt.Printf("failed to resolve public key: %+v", err))
		}

		// 验证消息签名
		if !utils.Sm2Verify(userPublicKey, NARWithSig.Plain, NARWithSig.Signature) {
			response.FailWithDescription(DefaultErrorMessage, "failed to verify signature", c)
			return
		}

		// 通过消息时间戳判断消息是否新鲜（replay-attach校验）
		if NAR.TimeStamp+10 < time.Now().Unix() {
			response.FailWithDescription(DefaultErrorMessage, "(replay) the message is not fresh", c)
			return
		}

		// 通过当前会话集合判断消息是否新鲜（replay-attach校验）
		if _, ok := global.CurrentSessions[NAR.HashedIMSI]; ok {
			response.FailWithDescription(DefaultErrorMessage, "(replay) user is now in session", c)
			return
		}

		// 验证请求内的卫星ID是否为自己
		if NAR.SatelliteId != global.MySatelliteId {
			response.FailWithDescription(DefaultErrorMessage, "wrong satellite id in request", c)
			return
		}

		// 读本地会话记录
		sessionRecordsFilePath := global.BaseSessionRecordsFilePath + fmt.Sprintf("%s.json", NAR.HashedIMSI)
		sessionRecords := utils.ReadSessionRecords(sessionRecordsFilePath)

		// 遍历到对应设备
		for _, record := range sessionRecords {
			if record.MacAddr == NAR.MacAddr {
				// 判断会话密钥是否过期
				if record.ExpirationDate > time.Now().Unix()+15 {
					response.FailWithDescription(DefaultErrorMessage, "session key has not expired", c)
					return
				}
				break
			}
		}

		// 记录当前会话
		var currentSessionKey = []byte(NAR.SessionKeyInfo.(request.SessionKeyKeyWithExpDate).EncryptedSessionKey)
		var currentExpDate = NAR.SessionKeyInfo.(request.SessionKeyKeyWithExpDate).ExpirationDate
		global.CurrentSessions[NAR.HashedIMSI] = model.Session{
			SessionKey:     currentSessionKey,
			ExpirationDate: currentExpDate,
		}

		// 更新用户认证状态
		gxios.POST(
			fmt.Sprintf("%s/node/user/changeAuthStatus", global.FabricAppBaseUrl),
			request.ChangeAuthStatus{Id: NAR.HashedIMSI},
		)

		response.OKWithMessage(DefaultSuccessMessage, c)

	} else {
		response.FailWithDescription(DefaultErrorMessage, "wrong type", c)
		return
	}

	//response.OKWithMessage(DefaultSuccessMessage, c)
}
