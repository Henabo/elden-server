package controller

import (
	"github.com/gin-gonic/gin"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/service"
)

// @Summary authentication for first access phrase, step 1
// @Router /auth/first/step1 [post]

func FirstAccessStep1(c *gin.Context) {
	var (
		DefaultSuccessMessage = "first authentication (step 1) success"
		DefaultErrorMessage   = "first authentication (step 1) error"
	)

	var FARWithSig request.MessageWithSig
	if err := c.ShouldBindJSON(&FARWithSig); err != nil {
		panic("failed to bind request")
	}

	FARResponse, err := service.FirstAccessStep1(FARWithSig)
	if err != nil {
		response.FailWithDescription(DefaultErrorMessage, err.Error(), c)
		return
	}

	response.OKWithData[[]byte](FARResponse, DefaultSuccessMessage, c)
}

// @Summary authentication for first access phrase, step 2
// @Router /auth/first/step2?id=xxx&mac=xxx [post]

func FirstAccessStep2(c *gin.Context) {
	var (
		DefaultSuccessMessage = "first authentication (step 2) success"
		DefaultErrorMessage   = "first authentication (step 2) error"
	)

	var FARCipher request.MessageCipher
	if err := c.ShouldBindJSON(&FARCipher); err != nil {
		panic("failed to bind request")
	}

	userId := c.Query("id")
	userMacAddr := c.Query("mac")

	if err := service.FirstAccessStep2(FARCipher, userId, userMacAddr); err != nil {
		response.FailWithDescription(DefaultErrorMessage, err.Error(), c)
		return
	}

	response.OKWithMessage(DefaultSuccessMessage, c)
}
