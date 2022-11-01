package service

import (
	"fmt"
	"github.com/hiro942/elden-server/global"
	"github.com/hiro942/elden-server/model"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/utils"
	"github.com/hiro942/elden-server/utils/gxios"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
	"log"
	"math/rand"
	"time"
)

func FirstAccessStep1(FARWithSig request.MessageWithSig) (resp []byte, err error) {
	log.Println("[First-Access] Go First Access Authentication.")

	FAR := utils.JsonUnmarshal[request.FAR](FARWithSig.Plain)

	// HTTP[GET] 获取用户公钥
	userPublicKeyHex, _ := gxios.QueryUserPublicKey(FAR.HashedIMSI, FAR.MacAddr)
	userPublicKey := utils.ReadPublicKeyFromHex(userPublicKeyHex)

	// 验证消息签名
	if !utils.Sm2Verify(userPublicKey, FARWithSig.Plain, FARWithSig.Signature) {
		return nil, errors.New("failed to verify signature")
	}

	// 验证请求内的卫星ID是否为自己
	if FAR.SatelliteId != global.MySatelliteId {
		return nil, errors.New("wrong satellite id in request")
	}

	// 获取FAR响应
	// 将与该用户的会话记入当前会话集合，包括会话密钥和失效日期
	return GetFARStep1Response(FAR.HashedIMSI, userPublicKey), nil
}

func GetFARStep1Response(userId string, userPublicKey *sm2.PublicKey) (cipher []byte) {
	sessionKeyBytes := utils.GenerateSm4Key()
	expirationDate := time.Now().Unix() + global.DefaultSessionKeyAge
	rand.Seed(time.Now().UnixNano())
	randNum := rand.Int()
	global.RandNums[userId] = randNum
	global.SessionKeys[userId] = sessionKeyBytes
	res := response.FAR{
		SessionKey:     string(sessionKeyBytes),
		ExpirationDate: expirationDate,
		Rand:           randNum,
		Timestamp:      time.Now().Unix(),
	}

	// 记入当前会话集合
	global.CurrentSessions[userId] = model.Session{
		Socket:              global.UserSockets[userId],
		AccessType:          global.FirstAccess,
		PreviousSatelliteId: "",
		SessionKey:          sessionKeyBytes,
		ExpirationDate:      expirationDate,
		StartAt:             time.Now().Unix(),
	}

	// 加签名
	resBytes := utils.JsonMarshal(res)
	resWithSig := response.MessageWithSig{
		Plain:     resBytes,
		Signature: utils.Sm2Sign(global.PrivateKey, resBytes),
	}

	// 加密
	resCipher := utils.Sm2Encrypt(userPublicKey, utils.JsonMarshal(resWithSig))

	return resCipher
}

func FirstAccessStep2(FARCipher request.MessageCipher, userId string, userMacAddr string) error {
	// 对称解密得到随机数
	FARWithRandBytes := utils.Sm4Decrypt(global.SessionKeys[userId], FARCipher.Cipher)
	FARWithRand := utils.JsonUnmarshal[request.FARWithRand](FARWithRandBytes)

	// 判断随机数是否正确
	if FARWithRand.Rand != global.RandNums[userId] {
		// 认证失败，将该用户从会话集合种删除
		delete(global.CurrentSessions, userId)
		return errors.New("wrong rand num")
	}

	// 删除临时保存的随机数和会话密钥
	delete(global.RandNums, userId)
	delete(global.SessionKeys, userId)

	// 将会话密钥保存至本地
	sessionRecordsFilePath := global.BaseSessionRecordsFilePath + fmt.Sprintf("%s.json", userId)
	utils.WriteNewSessionRecord(sessionRecordsFilePath, model.SessionRecord{
		MacAddr:        userMacAddr,
		SessionKey:     string(global.CurrentSessions[userId].SessionKey),
		ExpirationDate: global.CurrentSessions[userId].ExpirationDate,
	})

	// 更新用户认证状态
	gxios.ChangeUserAuthStatus(userId, global.AuthStatusCodeCertified)

	// First Access 认证成功
	log.Printf("[First-Access] First Access Authentication For %s Passed!\n", userId)

	return nil
}
