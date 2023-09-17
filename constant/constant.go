package constant

const (
	TimeLayout = "2006-01-02 15:04:05"
)

const (
	// CryptoPath 加密材料存储路径
	CryptoPath                 = "./.crypto/"
	PrivateKeyPemFileName      = "id_sm2"
	PublicKeyPemFileName       = "id_sm2.pub"
	PrivateKeyFilePath         = CryptoPath + PrivateKeyPemFileName
	PublicKeyFilePath          = CryptoPath + PublicKeyPemFileName
	BaseSessionRecordsFilePath = CryptoPath + "session_records/"

	// DefaultFilePerm 文件权限
	DefaultFilePerm = 0777

	// DefaultSessionKeyAge 会话密钥默认寿命
	DefaultSessionKeyAge = 3600 * 24
)
