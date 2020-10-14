package k6pace

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
    "crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"github.com/aead/cmac"
	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/mardukbp/padding"
    "github.com/valyala/fasthttp"
    "strings"
    "fmt"
)

type K6pace struct{}

type Response struct {
	status int
	body []byte
}

func New() *K6pace {
	return &K6pace{}
}

func (c *K6pace) Post(ctx context.Context, url string, 
                      headers map[string]string, cookie string,
                      body []byte, insecure bool) Response {

	fmt.Println(url)
	fmt.Println(headers)
	
	tlsConfig := &tls.Config {
		InsecureSkipVerify: insecure,
	}
	
	return request("POST", url, headers, cookie, body, tlsConfig)
}

func request(method string, url string, headers map[string]string,
             cookie string, body []byte, 
             tlsConfig *tls.Config) Response {

        req := fasthttp.AcquireRequest()
        defer fasthttp.ReleaseRequest(req)
        resp := fasthttp.AcquireResponse()
        defer fasthttp.ReleaseResponse(resp)

        client := &fasthttp.Client{ TLSConfig: tlsConfig }

		prepareRequest(req, method, url, headers, cookie, body)
        client.Do(req, resp)
        return Response{ resp.StatusCode(), resp.Body() }
}

func prepareRequest(req *fasthttp.Request, method string, url string,
                    headers map[string]string, cookie string,
                    body []byte) {
	
	req.SetRequestURI(url)
	req.Header.DisableNormalizing()
	req.Header.SetContentType("application/json")
	req.Header.SetMethod(method)
	cookie_name, cookie_value := parseCookie(cookie)
	req.Header.SetCookie(cookie_name, cookie_value)
	req.Header.SetContentLength(len(body))

	for key, val := range headers {
		req.Header.Add(key, val)
	}
	req.SetBody(body)
}

func parseCookie(cookie string) (string, string) {
	name_value := strings.Split(cookie, "=")	
	return name_value[0], name_value[1]
}

func (c *K6pace) Sign(ctx context.Context, keyb64 string, 
                      ssc int, data []byte) string {

	key, _ := base64.StdEncoding.DecodeString(keyb64)
	aesCipher, _ := aes.NewCipher(key)
	cmacLength := 8
	ssc_bytes := sscBytes(ssc)
	payload := append(ssc_bytes, data...)
	signature, _ := cmac.Sum(payload, aesCipher, cmacLength)
	return base64.StdEncoding.EncodeToString(signature)
}

func (c *K6pace) Encrypt(ctx context.Context, keyb64 string, 
                         ssc int, plaintext string) []byte {
	
	key, _ := base64.StdEncoding.DecodeString(keyb64)
	aesCipher, _ := aes.NewCipher(key)
	iv := cbcIV(aesCipher, ssc)
	aesCbc := cipher.NewCBCEncrypter(aesCipher, iv)
	padded := padding.PadIso7816([]byte(plaintext), aes.BlockSize)
	encrypted := make([]byte, len(padded))
	aesCbc.CryptBlocks(encrypted, padded)

	return encrypted
}

func (c *K6pace) Decrypt(ctx context.Context, keyb64 string, 
                         ssc int, encrypted []byte) []byte {

	padding.VerifyPadding(encrypted, aes.BlockSize)	
	key, _ := base64.StdEncoding.DecodeString(keyb64)
	aesCipher, _ := aes.NewCipher(key)
	iv := cbcIV(aesCipher, ssc)
	aesCbc := cipher.NewCBCDecrypter(aesCipher, iv)
	decrypted := make([]byte, len(encrypted))
	aesCbc.CryptBlocks(decrypted, encrypted)
	unpadded, err := padding.UnpadIso7816(decrypted, aes.BlockSize)
	if err != nil {
		return []byte(err.Error())
	}
	return unpadded
}

func cbcIV (aesCipher cipher.Block, ssc int) []byte {
	aesEcb := ecb.NewECBEncrypter(aesCipher)
	ssc_bytes := sscBytes(ssc)
	iv := make([]byte, aes.BlockSize)
	aesEcb.CryptBlocks(iv, ssc_bytes)

	return iv
}

func sscBytes(ssc int) []byte {
    bytearr := make([]byte, aes.BlockSize)
	binary.BigEndian.PutUint64(bytearr[8:], uint64(ssc))
	return bytearr
}
