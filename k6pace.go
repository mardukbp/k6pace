package k6pace

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"github.com/aead/cmac"
	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/mardukbp/padding"
)

type K6pace struct{}

func New() *K6pace {
	return &K6pace{}
}

// Method names must begin with a capital letter
func (c *K6pace) Cmac(ctx context.Context,
	keyb64 string,
	ssc int,
	data string) string {

	key, _ := base64.StdEncoding.DecodeString(keyb64)
	aesCipher, _ := aes.NewCipher(key)
	blockSize := 8
	ssc_bytes := sscBytes(ssc, blockSize)
	payload := append(ssc_bytes, []byte(data)...)
	signature, _ := cmac.Sum(payload, aesCipher, blockSize)
	return base64.StdEncoding.EncodeToString(signature)
}

func (c *K6pace) Encrypt(ctx context.Context,
	keyb64 string,
	ssc int,
	plaintext string) string {

	blockSize := 16
	key, _ := base64.StdEncoding.DecodeString(keyb64)

	aesCipher, _ := aes.NewCipher(key)
	aesEcb := ecb.NewECBEncrypter(aesCipher)
	iv := make([]byte, blockSize)
	ssc_bytes := sscBytes(ssc, blockSize)
	aesEcb.CryptBlocks(iv, ssc_bytes)
	aesCbc := cipher.NewCBCEncrypter(aesCipher, iv)
	padded := padding.PadIso7816([]byte(plaintext), blockSize)
	encrypted := make([]byte, len(padded))
	aesCbc.CryptBlocks(encrypted, padded)

	return base64.StdEncoding.EncodeToString(encrypted)
}

func (c *K6pace) Decrypt(ctx context.Context,
	keyb64 string,
	ssc int,
	plaintext string) string {

	blockSize := 16
	key, _ := base64.StdEncoding.DecodeString(keyb64)
	data := []byte(plaintext)

	aesCipher, _ := aes.NewCipher(key)
	aesEcb := ecb.NewECBEncrypter(aesCipher)
	iv := make([]byte, blockSize)
	ssc_bytes := sscBytes(ssc, blockSize)
	aesEcb.CryptBlocks(iv, ssc_bytes)
	aesCbc := cipher.NewCBCDecrypter(aesCipher, iv)
	decrypted := make([]byte, len(data))
	aesCbc.CryptBlocks(decrypted, data)
	unpadded, err := padding.UnpadIso7816(decrypted, blockSize)
	if err != nil {
		return err.Error()
	}
	return base64.StdEncoding.EncodeToString(unpadded)
}

func sscBytes(ssc int, blockSize int) []byte {
	bytearr := make([]byte, blockSize)
	binary.BigEndian.PutUint64(bytearr, uint64(ssc))
	return bytearr
}
