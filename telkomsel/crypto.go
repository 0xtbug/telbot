package telkomsel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"telkomsel-bot/config"
	"time"
)

func evpBytesToKey(password string, keyLen, ivLen int) (key, iv []byte) {
	var hash []byte
	var data []byte
	passBytes := []byte(password)

	res := make([]byte, 0, keyLen+ivLen)
	for len(res) < keyLen+ivLen {
		data = append(data, hash...)
		data = append(data, passBytes...)
		m := md5.Sum(data)
		hash = m[:]
		res = append(res, hash...)
		data = nil
	}
	return res[:keyLen], res[keyLen : keyLen+ivLen]
}

func EncryptPayload(payload string) string {
	_ = hex.EncodeToString([]byte(payload))
	key, iv := evpBytesToKey(config.EncryptionPassword, 16, 16)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	pt := []byte(payload)
	ct := make([]byte, len(pt))
	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(ct, pt)

	return base64.StdEncoding.EncodeToString(ct)
}

func GenerateAuthHeaders(accessToken, idToken string) (string, string) {
	ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	accessAuthMap := map[string]string{
		"accessToken": accessToken,
		"timestamp":   ts,
	}
	bAccess, _ := json.Marshal(accessAuthMap)

	authMap := map[string]string{
		"token":     idToken,
		"timestamp": ts,
	}
	bAuth, _ := json.Marshal(authMap)

	accessAuthEnc := EncryptPayload(string(bAccess))
	authEnc := EncryptPayload(string(bAuth))

	return "Bearer " + accessAuthEnc, "Bearer " + authEnc
}
