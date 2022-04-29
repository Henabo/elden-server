package service

import (
	"github.com/hiro942/elden-server/global"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/utils"
	"github.com/hiro942/elden-server/utils/gxios"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/x509"
	"log"
	"os"
)

func Register() error {
	// 创建加密材料目录
	if err := os.MkdirAll(global.BaseSessionRecordsFilePath, global.DefaultFilePerm); err != nil {
		log.Panicln("failed to make directory:", err)
	}

	// 生成公私钥
	global.PrivateKey, global.PublicKey = utils.GenerateSm2KeyPair()

	// 公私钥转为pem格式
	privateKeyPem := utils.WritePrivateKeyToPem(global.PrivateKey)
	publicKeyPem := utils.WritePublicKeyToPem(global.PublicKey)

	// 公私钥写入文件
	utils.WriteFile(global.PrivateKeyPath, privateKeyPem)
	utils.WriteFile(global.PublicKeyPath, publicKeyPem)

	// HTTP[POST] 添加卫星公钥至区块链
	responseBytes := gxios.POST(
		global.FabricAppBaseUrl+"/node/satellite/register",
		request.SatelliteRegister{
			Id:        global.MySatelliteId,
			PublicKey: x509.WritePublicKeyToHex(global.PublicKey),
		},
	)

	// 解析http响应
	if res := utils.JsonUnmarshal[response.Response[any]](responseBytes); res.Code != 0 {
		return errors.Errorf("message: %s, decription: %s",
			res.Message, res.Description)
	}

	// 注册成功
	return nil
}
