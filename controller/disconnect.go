package controller

import (
	"github.com/gin-gonic/gin"
	"github.com/hiro942/elden-server/global"
	"github.com/hiro942/elden-server/global/url"
	"github.com/hiro942/elden-server/model"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/utils/gxios"
	"log"
	"time"
)

// @Summary disconnect from the user
// @Router /auth/disconnect [post]

func DisConnect(c *gin.Context) {
	var r request.Disconnect
	err := c.ShouldBindJSON(&r)
	if err != nil {
		log.Panicln("failed to bind request")
	}

	// 在账本中添加用户访问记录
	gxios.POST(url.CreateAccessRecord, model.CreateAccessRecord{
		Id:      r.Id,
		MacAddr: r.MacAddr,
		AccessRecord: model.UserAccessRecord{
			AccessType:          global.CurrentSessions[r.Id].AccessType,
			SatelliteId:         global.MySatelliteId,
			PreviousSatelliteId: global.CurrentSessions[r.Id].PreviousSatelliteId,
			StartAt:             time.Unix(global.CurrentSessions[r.Id].StartAt, 0).Format(global.TimeTemplate),
			EndAt:               time.Now().Format(global.TimeTemplate),
		},
	})

	// 非切换需要更新用户认证态为Uncertified
	if !r.IsHandover {
		gxios.ChangeUserAuthStatus(r.Id, global.AuthStatusCodeUnCertified)
	}

	// 删除该用户会话
	delete(global.CurrentSessions, r.Id)

	response.OK(c)
}
