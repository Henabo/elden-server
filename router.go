package main

import (
	"github.com/gin-gonic/gin"
	"github.com/hiro942/elden-server/constant"
	"github.com/hiro942/elden-server/model"
	"github.com/hiro942/elden-server/model/enums"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/utils"
	"log"
	"net/http"
	"time"
)

func (auth *Authentication) Routers() *gin.Engine {
	r := gin.Default()
	r.Use(auth.cors())

	authGroup := r.Group("auth")
	{
		authGroup.POST("first/step1", auth.HandlerFirstAccessStep1)                     //首次接入请求第一步
		authGroup.POST("first/step2", auth.HandlerFirstAccessStep2)                     //首次接入请求第二步
		authGroup.POST("normal", auth.HandlerNormalAccess)                              //常规接入请求
		authGroup.POST("prehandover/sig", auth.HandlerPreHandoverSigFromOtherSatellite) //预切换时，接收其他卫星的签名消息
		authGroup.POST("handover", auth.HandlerHandover)                                // 交接接入请求
		authGroup.POST("disconnect", auth.HandlerDisconnect)                            // 断开请求
	}

	return r
}

func (auth *Authentication) cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method

		origin := c.Request.Header.Get("Origin")

		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Headers", "Content-Type,AccessToken,X-CSRF-Token, Authorization, Token,X-Token,X-User-ID")
		c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS,DELETE,PUT")
		c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Content-Type")
		c.Header("Access-Control-Allow-Credentials", "true")

		// 放行所有OPTIONS方法
		if method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
		}
		// 处理请求
		c.Next()
	}
}

// Disconnect 断开会话，上传本次会话信息
// [POST] /auth/disconnect [post]

func (auth *Authentication) HandlerDisconnect(c *gin.Context) {
	var r request.Disconnect
	err := c.ShouldBindJSON(&r)
	if err != nil {
		response.FailWithDescription("failed to bind request", err.Error(), c)
		return
	}

	session := auth.SessionPool.GetSession(r.ID)

	// 在账本中添加用户访问记录
	if err = auth.SessionPool.Satellite.Ledger.CreateAccessRecord(model.CreateAccessRecord{
		ID:      r.ID,
		MacAddr: r.MacAddr,
		AccessRecord: model.UserAccessRecord{
			AccessType:          session.AccessType.Format(),
			SatelliteID:         auth.SessionPool.Satellite.ID,
			PreviousSatelliteID: session.PreviousSatelliteID,
			StartAt:             time.Unix(session.StartAt, 0).Format(constant.TimeLayout),
			EndAt:               time.Now().Format(constant.TimeLayout),
		},
	}); err != nil {
		response.FailWithDescription("failed to create access record", err.Error(), c)
		return
	}

	// 非切换需要更新用户认证态为Uncertified
	if !r.IsHandover {
		if err = auth.SessionPool.Satellite.Ledger.UpdateClientAuthStatus(r.ID, enums.LedgerAuthStatusCodeUnCertified); err != nil {
			response.FailWithDescription("failed to update user auth status into ledger", err.Error(), c)
			return
		}
	}

	// 删除该用户会话
	delete(auth.SessionPool.SessionMap, r.ID)

	response.OK(c)
}

// @Summary 接收用户发送的切换请求
// @Router /auth/handover?type=hashed/encrypted [post]

func (auth *Authentication) HandlerHandover(c *gin.Context) {
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
		if _, ok := auth.SessionPool.Satellite.Cache.ClientHandoverSet[HAR.HashedIMSI]; !ok {
			response.FailWithDescription(DefaultErrorMessage, "user not found in handover-set", c)
			return
		}
		log.Println("【交接认证】已确认用户在切换集合内")
		// 逻辑同快速认证
		if err := auth.NormalAccessTypeHashed(c, HARWithSig, true); err != nil {
			response.FailWithDescription(DefaultErrorMessage, err.Error(), c)
			return
		}
		// 认证完成后将该用户移出切换集合
		delete(auth.SessionPool.Satellite.Cache.ClientHandoverSet, HAR.HashedIMSI)
	} else {
		HAR := utils.JsonUnmarshal[request.NAREncrypted](HARWithSig.Plain)
		// 判断该用户是否在切换集合内
		if _, ok := auth.SessionPool.Satellite.Cache.ClientHandoverSet[HAR.HashedIMSI]; !ok {
			response.FailWithDescription(DefaultErrorMessage, "user not found in handover-set", c)
			return
		}
		log.Println("【交接认证】已确认用户在切换集合内")
		// 逻辑同快速认证
		if err := auth.NormalAccessTypeEncrypted(c, HARWithSig, true); err != nil {
			response.FailWithDescription(DefaultErrorMessage, err.Error(), c)
			return
		}
		// 认证完成后将该用户移出切换集合
		delete(auth.SessionPool.Satellite.Cache.ClientHandoverSet, HAR.HashedIMSI)
	}

	response.OKWithMessage(DefaultSuccessMessage, c)
}

// @Summary 接收其他卫星发来的预切换消息
// @Router /auth/prehandover/sig [post]

func (auth *Authentication) HandlerPreHandoverSigFromOtherSatellite(c *gin.Context) {
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
	previousSatellitePublicKeyHex, _ := auth.SessionPool.Satellite.Ledger.QuerySatellitePublicKey(preHandover.PreviousSatelliteID)
	previousSatellitePublicKey := utils.ReadPublicKeyFromHex(previousSatellitePublicKeyHex)

	// 验证消息签名
	if !utils.Sm2Verify(previousSatellitePublicKey, preHandoverWithSig.Plain, preHandoverWithSig.Signature) {
		response.FailWithDescription(DefaultErrorMessage, "failed to verify signature", c)
		return
	}

	// 将该用户设备加入待切换名单
	auth.SessionPool.Satellite.Cache.SetClientHandoverSet(preHandover.HashedIMSI, preHandover.PreviousSatelliteID)
	log.Printf("【交接认证】成功收到来自卫星「%s」的背书签名。\n", preHandover.PreviousSatelliteID)

	response.OKWithMessage(DefaultSuccessMessage, c)
}

// @Summary authentication for normal(fast) access phrase
// @Router /auth/normal?type=hashed/encrypted [post]

func (auth *Authentication) HandlerNormalAccess(c *gin.Context) {
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
		if err := auth.NormalAccessTypeHashed(c, NARWithSig, false); err != nil {
			response.FailWithDescription(DefaultErrorMessage, err.Error(), c)
			return
		}
	} else {
		if err := auth.NormalAccessTypeEncrypted(c, NARWithSig, false); err != nil {
			response.FailWithDescription(DefaultErrorMessage, err.Error(), c)
			return
		}
	}

	response.OKWithMessage(DefaultSuccessMessage, c)
}

// @Summary authentication for first access phrase, step 1
// @Router /auth/first/step1 [post]

func (auth *Authentication) HandlerFirstAccessStep1(c *gin.Context) {
	var (
		DefaultSuccessMessage = "first authentication (step 1) success"
		DefaultErrorMessage   = "first authentication (step 1) error"
	)

	var FARWithSig request.MessageWithSig
	if err := c.ShouldBindJSON(&FARWithSig); err != nil {
		log.Panicln("failed to bind request")
	}

	FARResponse, err := auth.FirstAccessStep1(c, FARWithSig)
	if err != nil {
		response.FailWithDescription(DefaultErrorMessage, err.Error(), c)
		return
	}

	response.OKWithData[[]byte](FARResponse, DefaultSuccessMessage, c)
}

// @Summary authentication for first access phrase, step 2
// @Router /auth/first/step2?id=xxx&mac=xxx [post]

func (auth *Authentication) HandlerFirstAccessStep2(c *gin.Context) {
	var (
		DefaultSuccessMessage = "first authentication (step 2) success"
		DefaultErrorMessage   = "first authentication (step 2) error"
	)

	var FARCipher request.MessageCipher
	if err := c.ShouldBindJSON(&FARCipher); err != nil {
		log.Panicln("failed to bind request")
	}

	userID := c.Query("id")
	userMacAddr := c.Query("mac")

	if err := auth.FirstAccessStep2(FARCipher, userID, userMacAddr); err != nil {
		response.FailWithDescription(DefaultErrorMessage, err.Error(), c)
		return
	}

	response.OKWithMessage(DefaultSuccessMessage, c)
}
