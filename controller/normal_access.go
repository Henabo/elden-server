package controller

import (
	"github.com/gin-gonic/gin"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/service"
	"log"
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
		log.Panicln("failed to bind request")
	}

	// 取得URL参携带的参数
	keyType := c.Query("type")
	if keyType != "hashed" && keyType != "encrypted" {
		response.FailWithDescription(DefaultErrorMessage, "wrong type: 'type' should be `hashed` or `encrypted`", c)
		return
	}

	if keyType == "hashed" {
		if err := service.NormalAccessTypeHashed(NARWithSig, false); err != nil {
			response.FailWithDescription(DefaultErrorMessage, err.Error(), c)
			return
		}
	} else {
		if err := service.NormalAccessTypeEncrypted(NARWithSig, false); err != nil {
			response.FailWithDescription(DefaultErrorMessage, err.Error(), c)
			return
		}
	}

	response.OKWithMessage(DefaultSuccessMessage, c)
}
