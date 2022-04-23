package controller

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/hiro942/elden-server/global"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/utils"
	"github.com/hiro942/elden-server/utils/gxios"
	"github.com/tjfoc/gmsm/x509"
	"log"
)

// @Summary 接收其他卫星发来的预切换消息
// @Router /auth/prehandover [post]

func PreHandover(c *gin.Context) {
	var (
		DefaultSuccessMessage = "pre-handover success"
		DefaultErrorMessage   = "pre-handover error"
	)

	var preHandoverWithSig request.MessageWithSig
	if err := c.ShouldBindJSON(&preHandoverWithSig); err != nil {
		panic("failed to bind request")
	}

	preHandover := utils.JsonUnmarshal[request.PreHandover](preHandoverWithSig.Plain)

	// HTTP[GET] 获取原卫星公钥
	previousSatellitePublicKeyHex := gxios.QuerySatellitePublicKey(preHandover.PreviousSatelliteId)
	previousSatellitePublicKey, err := x509.ReadPublicKeyFromHex(previousSatellitePublicKeyHex)
	if err != nil {
		log.Panic(fmt.Printf("failed to resolve public key: %+v", err))
	}

	// 验证消息签名
	if !utils.Sm2Verify(previousSatellitePublicKey, preHandoverWithSig.Plain, preHandoverWithSig.Signature) {
		response.FailWithDescription(DefaultErrorMessage, "failed to verify signature", c)
		return
	}

	// 将该用户设备加入待切换名单
	global.PreHandoverId[preHandover.HashedIMSI] = struct{}{}

	response.OKWithMessage(DefaultSuccessMessage, c)
}

// @Summary 接收用户设备的切换接入请求
// @Router /auth/handover [post]

func Handover(c *gin.Context) {

}
