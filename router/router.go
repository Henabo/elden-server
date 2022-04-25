package router

import (
	"github.com/gin-gonic/gin"
	"github.com/hiro942/elden-server/controller"
	"github.com/hiro942/elden-server/middleware"
)

func Routers() *gin.Engine {
	r := gin.Default()
	r.Use(middleware.Cors())

	authGroup := r.Group("auth")
	{
		authGroup.POST("first/step1", controller.FirstAccessStep1)                     //首次接入请求第一步
		authGroup.POST("first/step2", controller.FirstAccessStep2)                     //首次接入请求第二步
		authGroup.POST("normal", controller.NormalAccess)                              //常规接入请求
		authGroup.POST("prehandover/sig", controller.PreHandoverSigFromOtherSatellite) //预切换时，接收其他卫星的签名消息
		authGroup.POST("handover", controller.Handover)                                // 交接接入请求
		authGroup.POST("disconnect", controller.DisConnect)                            // 断开请求
	}

	return r
}
