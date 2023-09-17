package request

// PreHandoverToOtherSatellite indicates the pre-handover message from another satellite
type PreHandoverToOtherSatellite struct {
	PreviousSatelliteID string `json:"prevSatelliteID"`
	HashedIMSI          string `json:"hashedIMSI"`
	TimeStamp           int64  `json:"timeStamp"`
}
