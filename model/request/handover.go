package request

// PreHandover indicates the pre-handover message from another satellite
type PreHandover struct {
	PreviousSatelliteId string `json:"prevSatelliteId"`
	HashedIMSI          string `json:"hashedIMSI"`
	TimeStamp           int64  `json:"timeStamp"`
}

//// Handover indicates handover access request
//type Handover NAR
