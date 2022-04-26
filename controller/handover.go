package controller

import (
	"github.com/gin-gonic/gin"
	"github.com/hiro942/elden-server/global"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/service"
	"github.com/hiro942/elden-server/utils"
	"log"
)

// @Summary 接收用户发送的切换请求
// @Router /auth/handover?type=hashed/encrypted [post]

func Handover(c *gin.Context) {
	var (
		DefaultSuccessMessage = "handover success"
		DefaultErrorMessage   = "handover error"
	)

	var HARWithSig request.MessageWithSig
	if err := c.ShouldBindJSON(&HARWithSig); err != nil {
		log.Panicln("failed to bind request")
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
		log.Println("已确认用户在切换集合内")
		// 将该用户移出切换集合
		delete(global.UserHandoverSet, HAR.HashedIMSI)
		// 逻辑同快速认证
		if err := service.NormalAccessTypeHashed(HARWithSig, true); err != nil {
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
		log.Println("已确认用户在切换集合内")
		// 将该用户移出切换集合
		delete(global.UserHandoverSet, HAR.HashedIMSI)
		// 逻辑同快速认证
		if err := service.NormalAccessTypeEncrypted(HARWithSig, true); err != nil {
			response.FailWithDescription(DefaultErrorMessage, err.Error(), c)
			return
		}
	}

	response.OKWithMessage(DefaultSuccessMessage, c)
}
