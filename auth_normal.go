package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/hiro942/elden-server/model"
	"github.com/hiro942/elden-server/model/enums"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/utils"
	"github.com/pkg/errors"
	"log"
	"strings"
	"time"
)

func (auth *Authentication) NormalAccessTypeHashed(c *gin.Context, NARWithSig request.MessageWithSig, isHandover bool) error {
	logHeader := "【快速认证】"
	if isHandover {
		logHeader = "【交接认证】"
	}

	log.Println(logHeader + "（密钥哈希模式）开始。")

	nar := utils.JsonUnmarshal[request.NARHashed](NARWithSig.Plain)

	// 缓存客户端 socket
	auth.SessionPool.Satellite.Cache.SetClientSocket(nar.HashedIMSI, c.ClientIP()+":20000")

	// 获取客户端信息
	client, err := auth.SessionPool.Satellite.Ledger.QueryNodeByID(nar.HashedIMSI)
	if err != nil {
		return err
	}

	if !isHandover {
		// 判断账本中有无接入记录, 若无接入纪录则设备需要先进行首次认证
		if ok := auth.HasAccessRecords(client, nar.MacAddr); !ok {
			return errors.New("该客户端未接入过，请发起首次认证请求。")
		}
	}

	// 获取用户公钥
	userPublicKey := utils.ReadPublicKeyFromHex(client.PublicKey[nar.MacAddr])

	// 验证消息签名
	if !utils.Sm2Verify(userPublicKey, NARWithSig.Plain, NARWithSig.Signature) {
		return errors.New("签名校验失败")
	}

	// 重放攻击校验
	if err = auth.CheckReplayAttach(nar.HashedIMSI, nar.TimeStamp); err != nil {
		return err
	}

	// 验证请求内的卫星ID是否为自己
	if nar.SatelliteID != auth.SessionPool.Satellite.ID {
		return errors.New("卫星ID错误")
	}

	// 验证会话密钥的哈希值是否正确。若正确，则将密钥取出，记入当前会话
	if err = auth.CheckHashedSessionKey(nar.HashedIMSI, nar.MacAddr, nar.HashedSessionKey, isHandover); err != nil {
		return err
	}

	// 更新用户认证状态
	if err = auth.SessionPool.Satellite.Ledger.UpdateClientAuthStatus(nar.HashedIMSI, enums.LedgerAuthStatusCodeCertified); err != nil {
		return err
	}

	log.Printf(logHeader+"（密钥哈希模式）对客户端「%s」的认证成功!\n", nar.HashedIMSI)

	return nil
}

func (auth *Authentication) NormalAccessTypeEncrypted(c *gin.Context, NARWithSig request.MessageWithSig, isHandover bool) error {
	logHeader := "【快速认证】"
	if isHandover {
		logHeader = "【交接认证】"
	}

	log.Println(logHeader + "（加密密钥模式）开始。")

	nar := utils.JsonUnmarshal[request.NAREncrypted](NARWithSig.Plain)

	// 缓存客户端 socket
	auth.SessionPool.Satellite.Cache.SetClientSocket(nar.HashedIMSI, c.ClientIP()+":20000")

	// 获取用户信息
	user, err := auth.SessionPool.Satellite.Ledger.QueryNodeByID(nar.HashedIMSI)
	if err != nil {
		return errors.Wrap(err, "【快速认证】获取用户信息失败")
	}

	if !isHandover {
		// 判断账本中有无该用户设备的接入记录, 若无接入纪录则设备需要先进行首次认证
		if ok := auth.HasAccessRecords(user, nar.MacAddr); !ok {
			return errors.New("该客户端未接入过，请发起首次认证请求。")
		}
	}

	// 获取用户公钥
	userPublicKey := utils.ReadPublicKeyFromHex(user.PublicKey[nar.MacAddr])

	// 验证消息签名
	if !utils.Sm2Verify(userPublicKey, NARWithSig.Plain, NARWithSig.Signature) {
		return errors.New("签名校验失败")
	}

	// 重放攻击校验
	if err := auth.CheckReplayAttach(nar.HashedIMSI, nar.TimeStamp); err != nil {
		return err
	}

	// 验证请求内的卫星ID是否为自己
	if nar.SatelliteID != auth.SessionPool.Satellite.ID {
		return errors.New("错误的卫星ID")
	}

	// 再次校验本地存储的会话密钥是否过期，如果确实过期的话，将新会话密钥更新至文件
	if err := auth.CheckEncryptedSessionKey(nar.HashedIMSI, nar.MacAddr, nar.EncryptedSessionKey, nar.ExpirationDate, isHandover); err != nil {
		return err
	}

	// 更新用户认证状态
	if err := auth.SessionPool.Satellite.Ledger.UpdateClientAuthStatus(nar.HashedIMSI, enums.LedgerAuthStatusCodeCertified); err != nil {
		return err
	}

	log.Printf(logHeader + fmt.Sprintf("（密钥哈希模式）对客户端「%s」的认证成功!\n", nar.HashedIMSI))

	return nil
}

// HasAccessRecords	判断账本中有无该用户设备的接入记录
func (auth *Authentication) HasAccessRecords(client model.Node, clientMacAddr string) bool {
	for _, record := range client.AccessRecord[clientMacAddr] {
		if record.SatelliteID == auth.SessionPool.Satellite.ID {
			return true
		}
	}
	return false
}

// CheckReplayAttach 通过时间戳和用户会话是否存在来校验重放攻击
func (auth *Authentication) CheckReplayAttach(clientID string, timeStamp int64) error {
	// 通过消息时间戳判断消息是否新鲜（replay-attach校验）
	if timeStamp < time.Now().Unix()-15 {
		return errors.New("【重放攻击检查】该请求已过期")
	}

	// 通过当前会话集合判断消息是否新鲜（replay-attach校验）
	if _, ok := auth.SessionPool.SessionMap[clientID]; ok {
		return errors.New("【重放攻击检查】用户已经处于会话中。")
	}

	return nil
}

// CheckHashedSessionKey 检查设备发送的密钥哈希是否正确且没有过期
func (auth *Authentication) CheckHashedSessionKey(clientID string, clientMacAddr string, hashedSessionKey string, isHandover bool) error {
	// 读本地会话记录
	sessionRecords := auth.SessionPool.Satellite.SessionRecordsMap[clientID]
	if sessionRecords == nil {
		auth.SessionPool.Satellite.LoadSessionRecordsByClientID(clientID)
	}

	var currentSessionKey []byte
	var currentExpDate int64
	// 遍历到对应设备
	for _, record := range sessionRecords {
		if record.ClientMacAddr == clientMacAddr {
			currentSessionKey = []byte(record.SessionKey)
			currentExpDate = record.ExpirationDate
			// 判断会话密钥哈希是否正确
			localSessionKeyHash := utils.Sm3Hash([]byte(record.SessionKey))
			if strings.Compare(hashedSessionKey, localSessionKeyHash) != 0 {
				return errors.New("会话密钥错误。")
			}
			// 判断会话密钥是否过期
			if record.ExpirationDate < time.Now().Unix()+15 {
				return errors.New("会话密钥已经过期。")
			}
			break
		}
	}

	accessType := enums.AccessTypeNormal
	if isHandover {
		accessType = enums.AccessTypeHandover
	}

	previousSatelliteID := ""
	if isHandover {
		previousSatelliteID = auth.SessionPool.Satellite.Cache.GetClientHandoverSet(clientID)
	}
	// 记录当前会话
	auth.SessionPool.SessionMap[clientID] = &Session{
		ClientID:            clientID,
		ClientMacAddr:       clientMacAddr,
		ClientSocket:        auth.SessionPool.Satellite.Cache.GetClientSocket(clientID),
		AccessType:          accessType,
		PreviousSatelliteID: previousSatelliteID,
		SessionKey:          currentSessionKey,
		ExpirationDate:      currentExpDate,
		StartAt:             time.Now().Unix(),
	}

	return nil
}

// CheckEncryptedSessionKey 检查会话密钥是否确实已经过期
// 若没过期，那么用户不应发送新的会话密钥，返回错误
// 若已过期，那么把用户发送的新会话密钥记入当前会话
func (auth *Authentication) CheckEncryptedSessionKey(clientID string, clientMacAddr string, encryptedSessionKey []byte, ExpDate int64, isHandover bool) error {
	// 读本地会话记录，再次检查密钥是否已失效
	sessionRecordsFilePath := auth.SessionPool.Satellite.GetSessionRecordFilePathByClientID(clientID)

	// 若存在会话记录文件，则校验密钥是否过期
	if utils.FileExist(sessionRecordsFilePath) {
		sessionRecords := auth.SessionPool.Satellite.SessionRecordsMap[clientID]
		for _, record := range sessionRecords {
			if record.ClientMacAddr == clientMacAddr {
				// 没过期
				if record.ExpirationDate > time.Now().Unix()+15 {
					return errors.New("会话密钥已经过期")
				}
				break
			}
		}
	} else if !isHandover {
		return errors.New("快速接入模式下，本地缺少会话记录。")
	}

	// 密钥已过期，或切换认证时不存在本地会话记录文件
	// 生成会话密钥并将其保存至本地
	sessionKeyBytes := utils.Sm2Decrypt(auth.SessionPool.Satellite.PrivateKey, encryptedSessionKey)
	auth.SessionPool.Satellite.WriteNewSessionRecordByClientID(clientID, SessionRecord{
		ClientMacAddr:  clientMacAddr,
		SessionKey:     string(sessionKeyBytes),
		ExpirationDate: ExpDate,
	})

	accessType := enums.AccessTypeNormal
	if isHandover {
		accessType = enums.AccessTypeHandover
	}

	previousSatelliteID := ""
	if isHandover {
		previousSatelliteID = auth.SessionPool.Satellite.Cache.GetClientHandoverSet(clientID)
	}

	// 记录当前会话
	auth.SessionPool.SessionMap[clientID] = &Session{
		ClientID:            clientID,
		ClientMacAddr:       clientMacAddr,
		ClientSocket:        auth.SessionPool.Satellite.Cache.GetClientSocket(clientID),
		AccessType:          accessType,
		PreviousSatelliteID: previousSatelliteID,
		SessionKey:          sessionKeyBytes,
		ExpirationDate:      ExpDate,
		StartAt:             time.Now().Unix(),
	}

	return nil
}
