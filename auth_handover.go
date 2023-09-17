package main

import (
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/utils"
	"github.com/hiro942/elden-server/utils/ghttp"
	"log"
	"strconv"
	"time"
)

func (auth *Authentication) PreHandover(clientID string) error {
	url := auth.SessionPool.Satellite.Ledger.URL

	log.Println("【交接认证】得到客户端坐标。")

	// 请求终端设备位置信息
	_, err := ghttp.POST[any](url.RequestForClientLocation(clientID), "")
	if err != nil {
		return err
	}

	// 根据用户位置信息选出一个合适的交接卫星

	newSID := GetNewSatelliteIDByClientPosition(auth.SessionPool.GetSession(clientID).ClientPosition)
	log.Printf("【交接认证】为当前客户端选择的新卫星为「%s」。\n", newSID)
	log.Println("【交接认证】发送给新卫星一个签名消息，为当前客户端做信任背书。")

	// 给选择的新卫星发送签名消息
	preHandoverSig := request.PreHandoverToOtherSatellite{
		PreviousSatelliteID: auth.SessionPool.Satellite.ID,
		HashedIMSI:          clientID,
		TimeStamp:           time.Now().Unix(),
	}
	preHandoverSigBytes := utils.JsonMarshal(preHandoverSig)

	_, err = ghttp.POST[any](
		url.SignatureToNewSatellite(newSID),
		request.MessageWithSig{
			Plain:     preHandoverSigBytes,
			Signature: utils.Sm2Sign(auth.SessionPool.Satellite.PrivateKey, preHandoverSigBytes),
		})
	if err != nil {
		return err
	}

	log.Println("【交接认证】发送新卫星ID给客户端。")

	// 将新卫星发送给用户设备
	_, err = ghttp.POST[any](url.SendNewSatelliteIDToUser(clientID, newSID), nil)
	if err != nil {
		return err
	}

	return nil
}

func GetNewSatelliteIDByClientPosition(pos int64) string {
	number := (pos - 1) / 100
	return "s" + strconv.Itoa(int(number))
}
