package request

// PreHandoverToOtherSatellite indicates the pre-handover message from another satellite
type PreHandoverToOtherSatellite struct {
	PreviousSatelliteId string `json:"prevSatelliteId"`
	HashedIMSI          string `json:"hashedIMSI"`
	TimeStamp           int64  `json:"timeStamp"`
}
