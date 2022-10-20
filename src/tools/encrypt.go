package tools

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// HashBySHA256 使用 SHA256 哈希
func HashBySHA256(sList []string) (res string) {
	s := strings.Join(sList, "")
	hash := sha256.New()
	hash.Write([]byte(s))
	hash.Sum(nil)
	resBytes := hash.Sum(nil)
	res = hex.EncodeToString(resBytes)
	return
}

// HashByMD5 使用 MD5 做哈希
func HashByMD5(strList []string) (h string) {
	r := strings.Join(strList, "")
	hash := md5.New()
	hash.Write([]byte(r))
	return hex.EncodeToString(hash.Sum(nil))
}

// pkcs7Padding 填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	//判断缺少几位长度 最少1 最多 blockSize
	padding := blockSize - len(data)%blockSize
	//补足位数 把切片[]byte{byte(padding)}复制padding个
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// pkcs7UnPadding 填充的反向操作
func pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("加密字符串错误！")
	}
	//获取填充的个数
	unPadding := int(data[length-1])
	return data[:(length - unPadding)], nil
}

// AesEncrypt 加密
func AesEncrypt(data []byte, key []byte) ([]byte, error) {
	defer func() {
		if err := recover(); err != nil {
			ExceptionLog(errors.New("EncryptFail"),
				fmt.Sprintf("Encryption failed： %v", err))
		}
	}()

	//创建加密实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//判断加密快的大小
	blockSize := block.BlockSize()
	//填充
	encryptBytes := pkcs7Padding(data, blockSize)
	//初始化加密数据接收切片
	crypted := make([]byte, len(encryptBytes))
	//使用cbc加密模式
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	//执行加密
	blockMode.CryptBlocks(crypted, encryptBytes)
	return crypted, nil
}

// AesDecrypt 解密
func AesDecrypt(data []byte, key []byte) ([]byte, error) {
	defer func() {
		if err := recover(); err != nil {
			ExceptionLog(errors.New("EncryptFail"),
				fmt.Sprintf("Decryption failed： %v", err))
		}
	}()

	//创建实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//获取块的大小
	blockSize := block.BlockSize()
	//使用cbc
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	//初始化解密数据接收切片
	crypted := make([]byte, len(data))
	//执行解密
	blockMode.CryptBlocks(crypted, data)
	//去除填充
	crypted, err = pkcs7UnPadding(crypted)
	if err != nil {
		return nil, err
	}
	return crypted, nil
}

// DecodeRSAPublicKey 解码 RSA 公钥 pem 文件
func DecodeRSAPublicKey(input []byte) (interface{}, bool) {
	block, _ := pem.Decode(input)
	if block == nil || (block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY") {
		ExceptionLog(errors.New("DecodeRSAPublicKeyFail"),
			"failed to decode PEM block containing public key")
		return nil, false
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		ExceptionLog(errors.New("ParsePKIXPublicKeyFail"),
			"failed to parse PKIX public key")
		return nil, false
	}
	return pub, true
}

// DecodeEcdsaPublicKey 解码 ECDSA 公钥 pem 文件
func DecodeEcdsaPublicKey(input []byte) (interface{}, bool) {
	block, _ := pem.Decode(input)
	if block == nil || (block.Type != "PUBLIC KEY" && block.Type != "ECDSA PUBLIC KEY") {
		ExceptionLog(errors.New("DecodeECDSAPublicKeyFail"),
			"failed to decode PEM block containing public key")
		return nil, false
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		ExceptionLog(errors.New("ParsePKIXPublicKeyFail"),
			"failed to parse PKIX public key")
		return nil, false
	}
	return pub, true
}

// DecodeEcdsaPrivateKey 解码 ECDSA 私钥 pem 文件
func DecodeEcdsaPrivateKey(input []byte) (prvKey *ecdsa.PrivateKey, err error) {
	block, _ := pem.Decode(input)
	if block == nil || block.Type != "ECD PRIVATE KEY" {
		err = errors.New("failed to decode PEM block containing private key")
		return
	}

	prvKey, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		err = errors.New("failed to parse PKCS1 private key")
		return
	}

	return
}

// DecodeRSAPrivateKey 解码 RSA 私钥 pem 文件
func DecodeRSAPrivateKey(input []byte) (*rsa.PrivateKey, bool) {
	block, _ := pem.Decode(input)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		ExceptionLog(errors.New("DecodeRSAPrivateKeyFail"),
			"failed to decode PEM block containing private key")
		return nil, false
	}
	pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		ExceptionLog(errors.New("ParsePKIXPrivateKeyFail"),
			"failed to parse PKCS1 private key")
		return nil, false
	}
	return pk, true
}

// CreateRSAPrivateKeyToFile 生成 RSA 私钥，并写入到文件
func CreateRSAPrivateKeyToFile(filepath string, len int) bool {
	pk, _ := rsa.GenerateKey(rand.Reader, len)
	keyOut, _ := os.Create(filepath)
	defer keyOut.Close()
	err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)})
	if err != nil {
		ExceptionLog(err, fmt.Sprintf("Fail to encode to %s", filepath))
		return false
	}
	return true
}

// CreateEcdsaPrvKeyToFile 生成 ECDSA 私钥，并写入到文件
func CreateEcdsaPrvKeyToFile(filepath string, len int) bool {
	prvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		ExceptionLog(err, fmt.Sprintf("Fail to encode to %s", filepath))
	}

	//pk, _ := rsa.GenerateKey(rand.Reader, len)
	priFile, _ := os.Create(filepath)
	defer priFile.Close()
	prvKeyBytes, err := x509.MarshalECPrivateKey(prvKey)
	if err != nil {
		return false
	}
	prvKeyBlock := pem.Block{
		Type:  "ECD PRIVATE KEY",
		Bytes: prvKeyBytes,
	}
	// 编码私匙,写入文件
	if err := pem.Encode(priFile, &prvKeyBlock); err != nil {
		ExceptionLog(err, fmt.Sprintf("Fail to encode to %s", filepath))
		return false
	}

	return true
}
