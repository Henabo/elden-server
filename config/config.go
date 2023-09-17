package config

import (
	"github.com/spf13/viper"
	"log"
)

var Conf = new(Config)

type Config struct {
	SatelliteID       string // 卫星 id
	FabricAppHostPath string // fabric-app 地址
	ServiceRangeLeft  int64
	ServiceRangeRight int64
	HttpServerPort    string // http服务器端口
	PrivateKeyPwd     string // 私钥加密密码
}

func LoadConfig() {
	// 指定配置文件路径
	viper.SetConfigName("app")
	viper.SetConfigType("toml")
	viper.AddConfigPath(".")

	// 读取配置
	if err := viper.ReadInConfig(); err != nil {
		log.Panicln(err)
	}

	// 配置绑定
	if err := viper.Unmarshal(Conf); err != nil {
		log.Panicln(err)
	}
}
