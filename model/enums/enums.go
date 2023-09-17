package enums

type (
	// AccessType 接入类型
	AccessType int8

	// LedgerAuthStatusCode 账本内的客户端认证状态
	LedgerAuthStatusCode string

	// AccessKeyMode 快速接入模式
	AccessKeyMode int8

	// Cipher 密文
	Cipher []byte
)

const (
	LedgerAuthStatusCodeCertified   = "1" // 已认证
	LedgerAuthStatusCodeUnCertified = "0" // 未认证

	AccessTypeStrict   AccessType = 1 // 首次认证
	AccessTypeNormal   AccessType = 2 // 快速认证
	AccessTypeHandover AccessType = 3 // 交接认证

	AccessKeyModeHashed    AccessKeyMode = 1 // 发送哈希
	AccessKeyModeEncrypted AccessKeyMode = 2 // 发送新会话密钥
)

func (accessType AccessType) Format() string {
	switch accessType {
	case AccessTypeStrict:
		return "strict"
	case AccessTypeNormal:
		return "normal"
	case AccessTypeHandover:
		return "handover"
	}
	return ""
}

func (mode AccessKeyMode) Format() string {
	switch mode {
	case AccessKeyModeHashed:
		return "hashed"
	case AccessKeyModeEncrypted:
		return "encrypted"
	}
	return ""
}
