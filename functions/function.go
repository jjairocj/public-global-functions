package hashfunctios

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	rand "math/rand"
	"strings"
	"time"

	jsonConfig "github.com/jjairocj/public-global-functions/settings-provider"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

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

	return strings.ReplaceAll(base64.StdEncoding.EncodeToString(b)[0:s], "/", "-"), err
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

func GeneratePhassphrase(lang string, length int, format string) string {
	var m interface{}
	rand.Seed(time.Now().Unix())

	if lang != "Spa" {
		lang = "Eng"
	}
	path, _ := jsonConfig.GetSection("Dictionary:" + lang)

	dat, err := ioutil.ReadFile(path)
	check(err)

	if err := json.Unmarshal([]byte(dat), &m); err != nil {
		log.Fatal(err)
	}

	phrase := ""
	sum := 0
	for i := 1; i <= length; i++ {
		wordsList := m.(map[string]interface{})

		item := wordsList["dictionary"].([]interface{})

		iv := item[rand.Intn(len(item))]

		switch format {

		case "upp":
			phrase += strings.ToUpper(iv.(string)) + " "
		case "pas":
			phrase += strings.Title(strings.ToLower(iv.(string))) + " "
		default:
			phrase += strings.ToLower(iv.(string)) + " "
		}

		sum += i
	}

	return string(phrase)

}
