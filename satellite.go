package main

import (
	"fmt"
	"github.com/hiro942/elden-server/config"
	"github.com/hiro942/elden-server/constant"
	"github.com/hiro942/elden-server/utils"
	"github.com/tjfoc/gmsm/sm2"
	"log"
	"os"
)

type Satellite struct {
	ID                string
	PublicKey         *sm2.PublicKey
	PrivateKey        *sm2.PrivateKey
	SessionRecordsMap map[string][]SessionRecord

	Cache  *Cache
	Ledger *Ledger
}

type SessionRecord struct {
	ClientID       string `json:"clientID"`
	ClientMacAddr  string `json:"macAddr"`
	SessionKey     string `json:"sessionKey"`
	ExpirationDate int64  `json:"expirationDate"`
}

func NewSatellite(id string, cache *Cache, ledger *Ledger) *Satellite {
	s := &Satellite{
		ID:         id,
		PublicKey:  nil,
		PrivateKey: nil,
		Cache:      cache,
		Ledger:     ledger,
	}
	s.LoadKeyPair()
	s.SessionRecordsMap = make(map[string][]SessionRecord)
	return s
}

func (s *Satellite) LoadKeyPair() {
	// 读取公私钥、或生成公私钥并将公钥注册上链
	if !utils.FileExist(constant.PrivateKeyFilePath) || !utils.FileExist(constant.PublicKeyFilePath) {
		// 生成公私钥
		s.PrivateKey, s.PublicKey = utils.GenerateSm2KeyPair()

		// 公私钥转为pem格式
		privateKeyPem := utils.WritePrivateKeyToPem(s.PrivateKey, []byte(config.Conf.PrivateKeyPwd))
		publicKeyPem := utils.WritePublicKeyToPem(s.PublicKey)

		// HTTP[POST] 添加卫星公钥至区块链
		err := s.Ledger.RegisterSatellite(s.ID, s.PublicKey)
		if err != nil {
			log.Panicln(fmt.Printf("failed to register: %+v", err))
		}

		// 创建加密材料目录
		if err := os.MkdirAll(constant.BaseSessionRecordsFilePath, constant.DefaultFilePerm); err != nil {
			log.Panicln("failed to make directory:", err)
		}

		// 公私钥写入文件
		utils.WriteFile(constant.PrivateKeyFilePath, privateKeyPem)
		utils.WriteFile(constant.PublicKeyFilePath, publicKeyPem)

	} else {
		// 读pem格式私钥和公钥
		privateKeyPem := utils.ReadFile(constant.PrivateKeyFilePath)
		publicKeyPem := utils.ReadFile(constant.PublicKeyFilePath)

		// 公私钥转化
		s.PrivateKey = utils.ReadPrivateKeyFromPem(privateKeyPem, []byte(config.Conf.PrivateKeyPwd))
		s.PublicKey = utils.ReadPublicKeyFromPem(publicKeyPem)
	}
}

func (s *Satellite) WriteNewSessionRecordByClientID(clientID string, newRecord SessionRecord) {
	path := s.GetSessionRecordFilePathByClientID(clientID)
	// 若与该SIM卡没有相关记录，则先创建记录文件
	if !utils.FileExist(path) {
		utils.WriteFile(path, nil)
	}

	// 读出原内容
	records := s.SessionRecordsMap[clientID]

	// 添加新数据
	records = append(records, newRecord)
	recordsBytes := utils.JsonMarshal(records)

	// 写入更新后的内容
	utils.WriteFile(path, recordsBytes)
}

func (s *Satellite) LoadSessionRecordsByClientID(clientID string) {
	path := s.GetSessionRecordFilePathByClientID(clientID)
	// 若与该SIM卡没有相关记录，则先创建记录文件
	if !utils.FileExist(path) {
		utils.WriteFile(path, nil)
	}

	// 读文件
	recordsBytes := utils.ReadFile(path)

	// 若文件本身为空，则不会反序列化成功，直接返回空记录切片即可
	if len(recordsBytes) == 0 {
		s.SessionRecordsMap[clientID] = make([]SessionRecord, 0)
		return
	}

	// 反序列化
	records := utils.JsonUnmarshal[[]SessionRecord](recordsBytes)

	s.SessionRecordsMap[clientID] = records
}

func (s *Satellite) GetSessionRecordFilePathByClientID(clientID string) string {
	return constant.BaseSessionRecordsFilePath + fmt.Sprintf("%s.json", clientID)
}
