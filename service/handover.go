package service

import (
	"fmt"
	"github.com/hiro942/elden-server/global"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/utils"
	"github.com/hiro942/elden-server/utils/gxios"
	"github.com/pkg/errors"
	"log"
	"time"
)

func PreHandover(userId string) error {
	log.Println("检测到不能为用户设备提供平滑通信")
	log.Println("Pre-Handover: 向用户请求位置信息")

	url := fmt.Sprintf("http://%s/auth/prehandover/location", global.CurrentSessions[userId].Socket)
	resBytes := gxios.POST(url, "")
	res := utils.JsonUnmarshal[response.Response[any]](resBytes) // 这里返回的位置信息暂时用字符串表示
	if res.Code != 0 {
		return errors.Errorf("message: %s, decription: %s", res.Message, res.Description)
	}

	// todo 根据res.Data即用户位置信息选出一个合适的交接卫星
	log.Println("Pre-Handover: 根据用户位置信息选择一个新卫星")
	log.Println("Pre-Handover: 签名一个Handover消息给新卫星")

	url = fmt.Sprintf("http://%s/auth/prehandover/sig", global.SatelliteSocket[global.MockNewSatelliteId])
	preHandoverToOtherSatellite := request.PreHandoverToOtherSatellite{
		PreviousSatelliteId: global.MySatelliteId, // 自己的ID
		HashedIMSI:          userId,
		TimeStamp:           time.Now().Unix(),
	}
	preHandoverToOtherSatelliteBytes := utils.JsonMarshal(preHandoverToOtherSatellite)
	res2Bytes := gxios.POST(url, request.MessageWithSig{
		Plain:     preHandoverToOtherSatelliteBytes,
		Signature: utils.Sm2Sign(global.PrivateKey, preHandoverToOtherSatelliteBytes),
	})
	res2 := utils.JsonUnmarshal[response.Response[any]](res2Bytes)
	if res2.Code != 0 {
		return errors.Errorf("message: %s, decription: %s", res2.Message, res2.Description)
	}

	log.Println("Pre-Handover: 将新卫星的ID发送给用户设备")
	// 将新卫星发送给用户设备
	url = fmt.Sprintf("http://%s/auth/prehandover/new_satellite?id=%s", global.CurrentSessions[userId].Socket, global.MockNewSatelliteId)
	res3Bytes := gxios.POST(url, "")
	fmt.Println("$##########", res3Bytes)
	res3 := utils.JsonUnmarshal[response.Response[any]](res3Bytes)
	if res3.Code != 0 {
		return errors.Errorf("message: %s, decription: %s", res3.Message, res3.Description)
	}

	log.Println("Pre-Handover: 用户已收到新卫星ID")

	return nil
}
