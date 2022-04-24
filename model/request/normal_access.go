package request

// NARHashed normal access request with hashed session key
type NARHashed struct {
	HashedIMSI       string `json:"hashedIMSI"`
	MacAddr          string `json:"macAddr"`
	SatelliteId      string `json:"satelliteId"`
	TimeStamp        int64  `json:"timeStamp"`
	HashedSessionKey string `json:"hashedSessionKey"`
}

// NAREncrypted normal access request with encrypted session key
type NAREncrypted struct {
	HashedIMSI  string `json:"hashedIMSI"`
	MacAddr     string `json:"macAddr"`
	SatelliteId string `json:"satelliteId"`
	TimeStamp   int64  `json:"timeStamp"`
	SessionKeyKeyWithExpDate
}

type SessionKeyKeyWithExpDate struct {
	EncryptedSessionKey string `json:"encryptedSessionKey"`
	ExpirationDate      int64  `json:"expirationDate"`
}
