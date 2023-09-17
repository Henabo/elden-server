package main

import (
	"github.com/gin-gonic/gin"
	"github.com/hiro942/elden-server/constant"
	"github.com/hiro942/elden-server/model/enums"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/utils"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
	"log"
	"math/rand"
	"time"
)

func (auth *Authentication) FirstAccessStep1(c *gin.Context, farWithSign request.MessageWithSig) (resp []byte, err error) {
	sessionPool := auth.SessionPool
	satellite := sessionPool.Satellite
	ledger := satellite.Ledger

	far := utils.JsonUnmarshal[request.FAR](farWithSign.Plain)

	// 缓存客户端 socket
	auth.SessionPool.Satellite.Cache.SetClientSocket(far.HashedIMSI, c.ClientIP()+":20000")

	// 获取用户公钥
	clientPublicKeyHex, err := ledger.QueryClientPublicKey(far.HashedIMSI, far.MacAddr)
	if err != nil {
		return nil, err
	}
	clientPublicKey := utils.ReadPublicKeyFromHex(clientPublicKeyHex)

	// 验证消息签名
	if !utils.Sm2Verify(clientPublicKey, farWithSign.Plain, farWithSign.Signature) {
		return nil, errors.New("failed to verify signature")
	}

	// 验证请求内的卫星ID是否为自己
	if far.SatelliteID != auth.SessionPool.Satellite.ID {
		return nil, errors.New("wrong satellite id in request")
	}

	// 获取FAR响应
	// 将与该用户的会话记入当前会话集合，包括会话密钥和失效日期
	return auth.GetFARStep1Response(far.HashedIMSI, clientPublicKey), nil
}

func (auth *Authentication) GetFARStep1Response(clientID string, clientPublicKey *sm2.PublicKey) (cipher []byte) {
	sessionPool := auth.SessionPool
	cache := sessionPool.Satellite.Cache

	sessionKeyBytes := utils.GenerateSm4Key()
	expirationDate := time.Now().Unix() + constant.DefaultSessionKeyAge
	rand.Seed(time.Now().UnixNano())
	randNum := rand.Int()
	cache.SetRandNumber(clientID, randNum)
	res := response.FAR{
		SessionKey:     string(sessionKeyBytes),
		ExpirationDate: expirationDate,
		Rand:           randNum,
		Timestamp:      time.Now().Unix(),
	}

	// 记入会话集合
	sessionPool.SetSession(clientID, &Session{
		ClientID:            clientID,
		ClientSocket:        cache.GetClientSocket(clientID),
		AccessType:          enums.AccessTypeStrict,
		PreviousSatelliteID: "",
		SessionKey:          sessionKeyBytes,
		ExpirationDate:      expirationDate,
		StartAt:             time.Now().Unix(),
	})

	// 加签名
	resBytes := utils.JsonMarshal(res)
	resWithSig := response.MessageWithSig{
		Plain:     resBytes,
		Signature: utils.Sm2Sign(auth.SessionPool.Satellite.PrivateKey, resBytes),
	}

	// 加密
	resCipher := utils.Sm2Encrypt(clientPublicKey, utils.JsonMarshal(resWithSig))

	return resCipher
}

func (auth *Authentication) FirstAccessStep2(FARCipher request.MessageCipher, clientID string, clientMacAddr string) error {
	satellite := auth.SessionPool.Satellite
	ledger := satellite.Ledger
	cache := satellite.Cache

	// 对称解密得到随机数
	FARWithRandBytes := utils.Sm4Decrypt(auth.SessionPool.GetSession(clientID).SessionKey, FARCipher.Cipher)
	FARWithRand := utils.JsonUnmarshal[request.FARWithRand](FARWithRandBytes)

	// 判断随机数是否正确
	if FARWithRand.Rand != cache.RandNums[clientID] {
		// 认证失败，将该用户从会话集合种删除
		delete(auth.SessionPool.SessionMap, clientID)
		return errors.New("wrong rand num")
	}

	// 随机数正确，删除临时保存的随机数
	delete(cache.RandNums, clientID)

	// 将会话密钥保存至本地
	satellite.WriteNewSessionRecordByClientID(clientID, SessionRecord{
		ClientMacAddr:  clientMacAddr,
		SessionKey:     string(auth.SessionPool.GetSession(clientID).SessionKey),
		ExpirationDate: auth.SessionPool.GetSession(clientID).ExpirationDate,
	})

	// 更新用户认证状态
	err := ledger.UpdateClientAuthStatus(clientID, enums.LedgerAuthStatusCodeCertified)
	if err != nil {
		return err
	}

	// First Access 认证成功
	log.Printf("【快速认证】客户端「%s」的认证通过！\n", clientID)

	return nil
}
