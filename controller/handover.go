package controller

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/hiro942/elden-server/global"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/service"
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
	global.UserHandoverSet[preHandover.HashedIMSI] = struct{}{}

	response.OKWithMessage(DefaultSuccessMessage, c)
}

// @Summary 接收用户发送的切换请求
// @Router /auth/handover?type=hashed/encrypted [post]

func Handover(c *gin.Context) {
	var (
		DefaultSuccessMessage = "handover success"
		DefaultErrorMessage   = "handover error"
	)

	var HARWithSig request.MessageWithSig
	if err := c.ShouldBindJSON(&HARWithSig); err != nil {
		panic("failed to bind request")
	}

	// 取得URL参携带的参数
	keyType := c.Query("type")
	if keyType != "hashed" && keyType != "encrypted" {
		response.FailWithDescription(DefaultErrorMessage, "wrong type: 'type' should be `hashed` or `encrypted`", c)
		return
	}

	if keyType == "hashed" {
		HAR := utils.JsonUnmarshal[request.NARHashed](HARWithSig.Plain)
		// 判断该用户是否在切换集合内
		if _, ok := global.UserHandoverSet[HAR.HashedIMSI]; !ok {
			response.FailWithDescription(DefaultErrorMessage, "user not found in handover-set", c)
			return
		}
		// 逻辑同快速认证
		if err := service.NormalAccessTypeHashed(HARWithSig); err != nil {
			response.FailWithDescription(DefaultErrorMessage, err.Error(), c)
			return
		}
	} else {
		HAR := utils.JsonUnmarshal[request.NAREncrypted](HARWithSig.Plain)
		// 判断该用户是否在切换集合内
		if _, ok := global.UserHandoverSet[HAR.HashedIMSI]; !ok {
			response.FailWithDescription(DefaultErrorMessage, "user not found in handover-set", c)
			return
		}
		// 逻辑同快速认证
		if err := service.NormalAccessTypeEncrypted(HARWithSig); err != nil {
			response.FailWithDescription(DefaultErrorMessage, err.Error(), c)
			return
		}
	}

	response.OKWithMessage(DefaultSuccessMessage, c)
}
