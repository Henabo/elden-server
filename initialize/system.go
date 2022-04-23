package initialize

import (
	"fmt"
	"github.com/hiro942/elden-server/global"
	"github.com/hiro942/elden-server/router"
	"github.com/hiro942/elden-server/service"
	"github.com/hiro942/elden-server/utils"
)

func SysInit() {
	// 读取公私钥，或
	// 生成公私钥，并将公钥注册上链
	if !utils.FileExist(global.PrivateKeyPath) || !utils.FileExist(global.PublicKeyPath) {
		if err := service.Register(); err != nil {
			panic(fmt.Errorf("register error: %v", err))
		}
	} else {
		utils.ReadKeyPair()
	}

	r := router.Routers()
	r.Run(global.DefaultAuthenticationPort)
}
