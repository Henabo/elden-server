package controller

import (
	"github.com/gin-gonic/gin"
	"github.com/hiro942/elden-server/global"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/utils"
	"github.com/hiro942/elden-server/utils/gxios"
	"log"
)

// @Summary 接收其他卫星发来的预切换消息
// @Router /auth/prehandover/sig [post]

func PreHandoverSigFromOtherSatellite(c *gin.Context) {
	var (
		DefaultSuccessMessage = "get handover signature success"
		DefaultErrorMessage   = "get handover signature error"
	)

	var preHandoverWithSig request.MessageWithSig
	if err := c.ShouldBindJSON(&preHandoverWithSig); err != nil {
		log.Panicln("failed to bind request")
	}

	preHandover := utils.JsonUnmarshal[request.PreHandoverToOtherSatellite](preHandoverWithSig.Plain)

	// HTTP[GET] 获取原卫星公钥
	previousSatellitePublicKeyHex, _ := gxios.QuerySatellitePublicKey(preHandover.PreviousSatelliteId)
	previousSatellitePublicKey := utils.ReadPublicKeyFromHex(previousSatellitePublicKeyHex)

	// 验证消息签名
	if !utils.Sm2Verify(previousSatellitePublicKey, preHandoverWithSig.Plain, preHandoverWithSig.Signature) {
		response.FailWithDescription(DefaultErrorMessage, "failed to verify signature", c)
		return
	}

	// 将该用户设备加入待切换名单
	global.UserHandoverSet[preHandover.HashedIMSI] = preHandover.PreviousSatelliteId
	log.Printf("[Handover-Access] Successfully receive the handover signature from the %s.\n", preHandover.PreviousSatelliteId)

	response.OKWithMessage(DefaultSuccessMessage, c)
}
