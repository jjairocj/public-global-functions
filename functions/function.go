package hashfunctios

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	rand "math/rand"
	"strings"
	"time"

	jsonConfig "github.com/jjairocj/public-global-functions/settings-provider"
)

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))

}

func encodeB64(data []byte) string {
	sEnc := strings.ReplaceAll(base64.StdEncoding.EncodeToString(data), "/", "-")
	return sEnc
}

func decryptB64(data string) []byte {
	uEnc, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(data, "-", "/"))
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return uEnc
}

func encryptAES(data []byte, passphrase string) string {
	block, err := aes.NewCipher([]byte(createHash(passphrase)))
	if err != nil {
		fmt.Println(err)
		return ""
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(crand.Reader, nonce)
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	return encodeB64(ciphertext)
}

func decryptAES(data string, passphrase string) []byte {

	key := []byte(createHash(passphrase))

	dataAES := decryptB64(data)

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	nonceSize := gcm.NonceSize()

	nonce, ciphertext := dataAES[:nonceSize], dataAES[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	return plaintext

}

func generateRandomString(s int) (string, error) {
	b, err := generateRandomBytes(s)

	return base64.StdEncoding.EncodeToString(b)[0:s], err
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

func GeneratePassword(length int) (string, error) {
	rand.Seed(time.Now().UTC().UnixNano())

	return generateRandomString(length)
}

func Encrypt(data []byte) string {
	phassprase, _ := jsonConfig.GetSection("Seg:Phassphrase")
	ciphertext := encryptAES(data, phassprase)
	return string(ciphertext)
}

func Decrypt(data string) string {
	phassprase, _ := jsonConfig.GetSection("Seg:Phassphrase")
	plaintext := decryptAES(data, phassprase)
	return string(plaintext)
}
