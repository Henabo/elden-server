package service

import (
	"fmt"
	"github.com/hiro942/elden-server/global"
	"github.com/hiro942/elden-server/model"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/utils"
	"github.com/hiro942/elden-server/utils/gxios"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/x509"
	"log"
	"strings"
	"time"
)

func NormalAccessTypeHashed(NARWithSig request.MessageWithSig) error {
	log.Println("Go Normal Access (hashed form) Authentication.")

	NAR := utils.JsonUnmarshal[request.NARHashed](NARWithSig.Plain)

	// HTTP[GET] 获取用户信息
	user, _ := gxios.QueryNodeById(NAR.HashedIMSI)

	// 判断账本中有无该用户设备的接入记录, 若无接入纪录则设备需要先进行首次认证
	if ok := HasAccessRecords(user, NAR.MacAddr); !ok {
		return errors.New("the device have not accessed before, please go first access")
	}

	// 获取用户公钥
	userPublicKey, err := x509.ReadPublicKeyFromHex(user.PublicKey[NAR.MacAddr])
	if err != nil {
		log.Panicln(fmt.Printf("failed to resolve public key: %+v", err))
	}

	// 验证消息签名
	if !utils.Sm2Verify(userPublicKey, NARWithSig.Plain, NARWithSig.Signature) {
		return errors.New("failed to verify signature")
	}

	// 重放攻击校验
	if err = CheckReplayAttach(NAR.HashedIMSI, NAR.TimeStamp); err != nil {
		return err
	}

	// 验证请求内的卫星ID是否为自己
	if NAR.SatelliteId != global.MySatelliteId {
		return errors.New("wrong satellite id in request")
	}

	// 验证会话密钥的哈希值是否正确。若正确，则将密钥取出，记入当前会话
	if err = CheckHashedSessionKey(NAR.HashedIMSI, NAR.MacAddr, NAR.HashedSessionKey); err != nil {
		return err
	}

	// 更新用户认证状态
	gxios.ChangeUserAuthStatus(NAR.HashedIMSI, global.AuthStatusCodeCertified)

	log.Printf("Normal Access (hashed form) Authentication For %s Passed!\n", NAR.HashedIMSI)

	return nil
}

func NormalAccessTypeEncrypted(NARWithSig request.MessageWithSig) error {
	log.Println("Go Normal Access (encrypted form) Authentication.")

	NAR := utils.JsonUnmarshal[request.NAREncrypted](NARWithSig.Plain)

	// HTTP[GET] 获取用户信息
	user, _ := gxios.QueryNodeById(NAR.HashedIMSI)

	// 判断账本中有无该用户设备的接入记录, 若无接入纪录则设备需要先进行首次认证
	if ok := HasAccessRecords(user, NAR.MacAddr); !ok {
		return errors.New("the device have not accessed before, please go first access")
	}

	// 获取用户公钥
	userPublicKey, err := x509.ReadPublicKeyFromHex(user.PublicKey[NAR.MacAddr])
	if err != nil {
		log.Panicln(fmt.Printf("failed to resolve public key: %+v", err))
	}

	// 验证消息签名
	if !utils.Sm2Verify(userPublicKey, NARWithSig.Plain, NARWithSig.Signature) {
		return errors.New("failed to verify signature")
	}

	// 重放攻击校验
	if err = CheckReplayAttach(NAR.HashedIMSI, NAR.TimeStamp); err != nil {
		return err
	}

	// 验证请求内的卫星ID是否为自己
	if NAR.SatelliteId != global.MySatelliteId {
		return errors.New("wrong satellite id in request")
	}

	// 再次校验本地存储的会话密钥是否过期，如果确实过期的话，将新会话密钥更新至文件
	if err = CheckEncryptedSessionKey(NAR.HashedIMSI, NAR.MacAddr, NAR.EncryptedSessionKey, NAR.ExpirationDate); err != nil {
		return err
	}

	// 更新用户认证状态
	gxios.ChangeUserAuthStatus(NAR.HashedIMSI, global.AuthStatusCodeCertified)

	log.Printf("Normal Access (encrypted form) Authentication For %s Passed!\n", NAR.HashedIMSI)

	return nil
}

// HasAccessRecords	判断账本中有无该用户设备的接入记录
func HasAccessRecords(user model.Node, macAddr string) bool {
	for _, record := range user.AccessRecord[macAddr] {
		if record.SatelliteId == global.MySatelliteId {
			return true
		}
	}
	return false
}

// CheckReplayAttach 通过时间戳和用户会话是否存在来校验重放攻击
func CheckReplayAttach(userId string, timeStamp int64) error {
	// 通过消息时间戳判断消息是否新鲜（replay-attach校验）
	if timeStamp < time.Now().Unix()-15 {
		return errors.New("(replay) the message is not fresh")
	}

	// 通过当前会话集合判断消息是否新鲜（replay-attach校验）
	if _, ok := global.CurrentSessions[userId]; ok {
		return errors.New("(replay) user has already in session")
	}

	return nil
}

// CheckHashedSessionKey 检查设备发送的密钥哈希是否正确且没有过期
func CheckHashedSessionKey(id string, macAddr string, hashedSessionKey string) error {
	// 读本地会话记录
	sessionRecordsFilePath := global.BaseSessionRecordsFilePath + fmt.Sprintf("%s.json", id)
	sessionRecords := utils.ReadSessionRecords(sessionRecordsFilePath)

	var currentSessionKey []byte
	var currentExpDate int64
	// 遍历到对应设备
	for _, record := range sessionRecords {
		if record.MacAddr == macAddr {
			currentSessionKey = []byte(record.SessionKey)
			currentExpDate = record.ExpirationDate
			// 判断会话密钥哈希是否正确
			localSessionKeyHash := utils.Sm3Hash([]byte(record.SessionKey))
			if strings.Compare(hashedSessionKey, localSessionKeyHash) != 0 {
				return errors.New("wrong session key")
			}
			// 判断会话密钥是否过期
			if record.ExpirationDate < time.Now().Unix()+15 {
				return errors.New("session key has already expired")
			}
			break
		}
	}

	// 记录当前会话
	global.CurrentSessions[id] = model.Session{
		Socket:         "localhost:19999",
		AccessType:     "normal",
		SessionKey:     currentSessionKey,
		ExpirationDate: currentExpDate,
		StartAt:        time.Now().Unix(),
	}

	return nil
}

// CheckEncryptedSessionKey 检查会话密钥是否确实已经过期
// 若没过期，那么用户不应发送新的会话密钥，返回错误
// 若已过期，那么把用户发送的新会话密钥记入当前会话
func CheckEncryptedSessionKey(id string, macAddr string, encryptedKey []byte, ExpDate int64) error {
	// 读本地会话记录，再次检查密钥是否已失效
	sessionRecordsFilePath := global.BaseSessionRecordsFilePath + fmt.Sprintf("%s.json", id)
	sessionRecords := utils.ReadSessionRecords(sessionRecordsFilePath)

	var sessionKeyBytes []byte

	for _, record := range sessionRecords {
		if record.MacAddr == macAddr {
			// 没过期
			if record.ExpirationDate > time.Now().Unix()+15 {
				return errors.New("session key has not expired")
			}
			// 过期了
			// 将会话密钥保存至本地
			sessionKeyBytes = utils.Sm2Decrypt(global.PrivateKey, encryptedKey)
			utils.WriteNewSessionRecord(sessionRecordsFilePath, model.SessionRecord{
				MacAddr:        macAddr,
				SessionKey:     string(sessionKeyBytes),
				ExpirationDate: ExpDate,
			})
			break
		}
	}

	log.Println("Received Session Key:", string(sessionKeyBytes))

	// 记录当前会话
	global.CurrentSessions[id] = model.Session{
		Socket:         "localhost:19999",
		AccessType:     "normal",
		SessionKey:     sessionKeyBytes,
		ExpirationDate: ExpDate,
		StartAt:        time.Now().Unix(),
	}

	return nil
}
