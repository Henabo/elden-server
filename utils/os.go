package utils

import (
	"encoding/json"
	"fmt"
	"github.com/hiro942/elden-server/global"
	"github.com/hiro942/elden-server/model"
	"github.com/tjfoc/gmsm/x509"
	"log"
	"os"
)

func FileExist(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}

func ReadKeyPair() {
	// 读pem格式私钥和公钥
	privateKeyPem := ReadFile(global.PrivateKeyPath)
	publicKeyPem := ReadFile(global.PublicKeyPath)

	// 转化私钥
	privateKey, err := x509.ReadPrivateKeyFromPem(privateKeyPem, global.PrivateKeyPwd)
	if err != nil {
		log.Panic(fmt.Printf("failed to convert pem to sm2 private key: %+v", err))
	}

	// 转化公钥
	publicKey, err := x509.ReadPublicKeyFromPem(publicKeyPem)
	if err != nil {
		log.Panic(fmt.Printf("failed to convert pem to sm2 public key: %+v", err))
	}

	global.PrivateKey = privateKey
	global.PublicKey = publicKey
}

func WriteNewSessionRecord(path string, newRecord model.SessionRecord) {
	// 若与该SIM卡没有相关记录，则先创建记录文件
	if !FileExist(path) {
		WriteFile(path, nil)
	}

	// 读出原内容
	records := ReadSessionRecords(path)

	// 添加新数据
	records = append(records, newRecord)
	recordsBytes := JsonMarshal(records)

	// 写入更新后的内容
	WriteFile(path, recordsBytes)
}

func ReadSessionRecords(path string) []model.SessionRecord {
	// 读文件
	recordsBytes := ReadFile(path)

	// 若文件本身为空，则不会反序列化成功，直接返回空记录切片即可
	if len(recordsBytes) == 0 {
		return []model.SessionRecord{}
	}

	// 反序列化
	records := JsonUnmarshal[[]model.SessionRecord](recordsBytes)

	return records
}

func WriteFile(path string, data []byte) {
	err := os.WriteFile(path, data, global.DefaultFilePerm)
	if err != nil {
		log.Panic(fmt.Printf("failed to write file: %+v", err))
	}
}

func ReadFile(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Panic(fmt.Printf("failed to read file: %+v", err))
	}
	return data
}

func JsonMarshal(v any) []byte {
	result, err := json.Marshal(v)
	if err != nil {
		panic("json marshal error")
	}
	return result
}

func JsonUnmarshal[T any](data []byte) T {
	var result T
	err := json.Unmarshal(data, &result)
	if err != nil {
		log.Panic("json unmarshal error: ", err)
	}
	return result

}
