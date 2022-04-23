package global

import (
	"github.com/hiro942/elden-server/model"
	"github.com/tjfoc/gmsm/sm2"
)

const (
	// FabricAppBaseUrl fabric app 地址
	FabricAppBaseUrl = "http://39.107.126.155:8080"

	// DefaultAuthenticationPort 认证服务默认端口
	DefaultAuthenticationPort = ":20000"
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
	DefaultSessionKeyAge = 60 * 60 * 24
)

var (
	MySatelliteId string

	PrivateKey *sm2.PrivateKey
	PublicKey  *sm2.PublicKey
	//SatelliteIPAddr = map[string]string{}  //

	// PrivateKeyPwd 私钥加密密码
	PrivateKeyPwd = []byte("elden")

	RandNums    = map[string]int{}    // key = H-IMSI
	SessionKeys = map[string][]byte{} // key: H-IMSI

	CurrentSessions = map[string]model.Session{} // key: H-IMSI

	// PreHandoverId 预切换的用户ID
	PreHandoverId = map[string]struct{}{} // H-IMSI 的集合，value为空struct，不占内存
)
