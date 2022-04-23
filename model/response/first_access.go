package response

type FAR struct {
	SessionKey     string `json:"sessionKey"`
	ExpirationDate int64  `json:"expirationDate"`
	Timestamp      int64  `json:"timestamp"`
	Rand           int    `json:"rand"`
}
