package service

import (
	"github.com/hiro942/elden-server/global"
	"github.com/hiro942/elden-server/global/url"
	"github.com/hiro942/elden-server/mock"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/utils"
	"github.com/hiro942/elden-server/utils/gxios"
	"github.com/pkg/errors"
	"log"
	"time"
)

func PreHandover(userId string) error {
	log.Println("Pre-Handover: Request the user for location.")

	// 请求终端设备位置信息
	resLocationBytes := gxios.POST(url.RequestForUserLocation(userId), "")
	resLocation := utils.JsonUnmarshal[response.Response[any]](resLocationBytes) // 这里返回的位置信息暂时用字符串表示
	if resLocation.Code != 0 {
		return errors.Errorf("message: %s, decription: %s", resLocation.Message, resLocation.Description)
	}

	// 根据res.Data即用户位置信息选出一个合适的交接卫星
	log.Println("Pre-Handover: Choose a new satellite for the user.")
	log.Println("Pre-Handover: Sign a handover message to the new satellite.")

	// 给选择的新卫星发送签名消息
	preHandoverSig := request.PreHandoverToOtherSatellite{
		PreviousSatelliteId: global.MySatelliteId, // 自己的ID
		HashedIMSI:          userId,
		TimeStamp:           time.Now().Unix(),
	}
	preHandoverSigBytes := utils.JsonMarshal(preHandoverSig)
	resSigBytes := gxios.POST(
		url.SignatureToNewSatellite(mock.NewSatelliteId),
		request.MessageWithSig{
			Plain:     preHandoverSigBytes,
			Signature: utils.Sm2Sign(global.PrivateKey, preHandoverSigBytes),
		})
	resSig := utils.JsonUnmarshal[response.Response[any]](resSigBytes)
	if resSig.Code != 0 {
		return errors.Errorf("message: %s, decription: %s", resSig.Message, resSig.Description)
	}

	log.Println("Pre-Handover: Send the new satellite ID to the user")
	// 将新卫星发送给用户设备
	resNewSatelliteBytes := gxios.POST(url.NewSatelliteIdToUser(userId, mock.NewSatelliteId), "")
	resNewSatellite := utils.JsonUnmarshal[response.Response[any]](resNewSatelliteBytes)
	if resNewSatellite.Code != 0 {
		return errors.Errorf("message: %s, decription: %s", resNewSatellite.Message, resNewSatellite.Description)
	}

	log.Println("Pre-Handover: The user has successfully received the new satellite ID.")
	return nil
}
