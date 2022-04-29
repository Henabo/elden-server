package global

import (
	"github.com/hiro942/elden-server/model"
	"github.com/tjfoc/gmsm/sm2"
)

const (
	TimeTemplate = "2006-01-02 15:04:05"
)

const (
	// FabricAppBaseUrl fabric app 地址
	FabricAppBaseUrl = "http://39.107.126.155:8080"

	// DefaultAuthenticationPort 认证服务默认端
	DefaultAuthenticationPort = "20000"
)

const (
	AuthStatusCodeCertified   = "1"
	AuthStatusCodeUnCertified = "0"

	FirstAccess    = "first"
	NormalAccess   = "normal"
	HandoverAccess = "handover"
)

const (
	// CryptoPath 加密材料存储路径
	CryptoPath                 = "./.crypto/"
	PrivateKeyPemFileName      = "id_sm2"
	PublicKeyPemFileName       = "id_sm2.pub"
	PrivateKeyPath             = CryptoPath + PrivateKeyPemFileName
	PublicKeyPath              = CryptoPath + PublicKeyPemFileName
	BaseSessionRecordsFilePath = CryptoPath + "session_records/"

	// DefaultFilePerm 文件权限
	DefaultFilePerm = 0777

	// DefaultSessionKeyAge 会话密钥默认寿命
	DefaultSessionKeyAge = 3600 * 24
)

var (
	MySatelliteId string

	PrivateKey       *sm2.PrivateKey
	PublicKey        *sm2.PublicKey
	SatelliteSockets = map[string]string{}
	UserSockets      = map[string]string{}

	// PrivateKeyPwd 私钥加密密码
	PrivateKeyPwd = []byte("elden")

	RandNums    = map[string]int{}    // key = H-IMSI
	SessionKeys = map[string][]byte{} // key: H-IMSI

	CurrentSessions = map[string]model.Session{} // key: H-IMSI

	// UserHandoverSet 预切换的用户ID
	UserHandoverSet = map[string]string{} // H-IMSI -> PreviousSatellite
)
