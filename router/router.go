package router

import (
	"github.com/gin-gonic/gin"
	"github.com/hiro942/elden-server/controller"
	"github.com/hiro942/elden-server/middleware"
)

func Routers() *gin.Engine {
	r := gin.Default()
	r.Use(middleware.Cors())

	r.Group("auth")
	{
		r.POST("first/step1", controller.FirstAccessStep1)
		r.POST("first/step2", controller.FirstAccessStep2)
		r.POST("normal", controller.NormalAccess)
		r.POST("prehandover", controller.PreHandover)
		r.POST("handover", controller.Handover)
	}

	return r
}
