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
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"log"
	"math/rand"
	"time"
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

	FAR := utils.JsonUnmarshal[request.FAR](FARWithSig.Plain)

	// HTTP[GET] 获取用户公钥
	userPublicKeyHex := gxios.QueryUserPublicKey(FAR.HashedIMSI, FAR.MacAddr)
	userPublicKey, err := x509.ReadPublicKeyFromHex(userPublicKeyHex)
	if err != nil {
		log.Panic(fmt.Printf("failed to resolve public key: %+v", err))
	}

	// 验证消息签名
	if !utils.Sm2Verify(userPublicKey, FARWithSig.Plain, FARWithSig.Signature) {
		response.FailWithDescription(DefaultErrorMessage, "failed to verify signature", c)
		return
	}

	// 验证请求内的卫星ID是否为自己
	if FAR.SatelliteId != global.MySatelliteId {
		response.FailWithDescription(DefaultErrorMessage, "wrong satellite id in request", c)
		return
	}

	// 获取FAR响应
	// 将与该用户的会话记入当前会话集合，包括会话密钥和失效日期
	FARResponseCipher := GetFARResponse(FAR.HashedIMSI, userPublicKey)

	// 返回响应
	response.OKWithData(FARResponseCipher, DefaultSuccessMessage, c)
}

// @Summary authentication for first access phrase, step 2
// @Router /auth/first/step2?id=xxx&mac [post]

func FirstAccessStep2(c *gin.Context) {
	var (
		DefaultSuccessMessage = "first authentication (step 2) success"
		DefaultErrorMessage   = "first authentication (step 2) error"
	)

	userId := c.Query("id")
	userMacAddr := c.Query("mac")

	var FARCipher request.MessageCipher
	if err := c.ShouldBindJSON(&FARCipher); err != nil {
		panic("failed to bind request")
	}

	// 对称解密得到随机数
	FARWithRandBytes := utils.Sm4Decrypt(global.SessionKeys[userId], []byte(FARCipher.Cipher))
	FARWithRand := utils.JsonUnmarshal[request.FARWithRand](FARWithRandBytes)

	// 判断随机数是否正确
	if FARWithRand.Rand != global.RandNums[userId] {
		// 认证失败，将该用户从会话集合种删除
		delete(global.CurrentSessions, userId)
		// 返回失败响应
		response.FailWithDescription(DefaultErrorMessage, "wrong rand num", c)
		return
	}

	// 删除该随机数，避免冗余
	delete(global.RandNums, userId)

	// 将会话密钥保存至本地
	sessionRecordsFilePath := global.BaseSessionRecordsFilePath + fmt.Sprintf("%s.json", userId)
	utils.WriteNewSessionRecord(sessionRecordsFilePath, model.SessionRecord{
		MacAddr:        userMacAddr,
		SessionKey:     string(global.CurrentSessions[userId].SessionKey),
		ExpirationDate: global.CurrentSessions[userId].ExpirationDate,
	})

	// First Access 认证成功
	fmt.Println("首次认证成功！")
	// 更新用户认证状态
	gxios.POST(
		fmt.Sprintf("%s/node/user/changeAuthStatus", global.FabricAppBaseUrl),
		request.ChangeAuthStatus{Id: userId},
	)

	response.OKWithMessage(DefaultSuccessMessage, c)
}

func GetFARResponse(userId string, userPublicKey *sm2.PublicKey) (cipher string) {
	sessionKeyBytes := utils.GenerateSm4Key()
	expirationDate := time.Now().Unix() + global.DefaultSessionKeyAge
	rand.Seed(time.Now().UnixNano())
	randNum := rand.Int()
	global.RandNums[userId] = randNum
	res := response.FAR{
		SessionKey:     string(sessionKeyBytes),
		ExpirationDate: expirationDate,
		Rand:           randNum,
		Timestamp:      time.Now().Unix(),
	}

	// 记入当前会话集合
	global.CurrentSessions[userId] = model.Session{
		SessionKey:     sessionKeyBytes,
		ExpirationDate: expirationDate,
	}

	// 加签名
	resBytes := utils.JsonMarshal(res)
	resWithSig := response.MessageWithSig{
		Plain:     resBytes,
		Signature: utils.Sm2Sign(global.PrivateKey, resBytes),
	}

	// 加密
	resCipher := utils.Sm2Encrypt(userPublicKey, utils.JsonMarshal(resWithSig))

	return string(resCipher)
}
