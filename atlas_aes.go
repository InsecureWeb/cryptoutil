package AtlasInsideAES

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	b64 "encoding/base64"
	"golang.org/x/crypto/pbkdf2"
)

const IterationCount = 65536
const SaltLength = 16
const KeyLength = 16

func setKey(key []byte) (cipher.Block, []byte, error) {
	h := sha1.New()
	h.Write(key)
	salt := h.Sum(nil)
	keyEnc := pbkdf2.Key(key, salt, IterationCount, KeyLength, sha1.New)
	block, err := aes.NewCipher(keyEnc)
	if err != nil {
		return nil, nil, err
	}
	return block, salt[:SaltLength], nil
}

func AESEncrypt(src string, key []byte) (string, error) {
	if len(src) == 0 {
		return "", &InvalidEncryptedDataError{"Invalid crypto"}
	}
	blkEncrypt, ivEncrypt, err := setKey(key)
	if err != nil {
		return "", &InvalidAESKeyError{"Invalid crypto"}
	}
	ecb := cipher.NewCBCEncrypter(blkEncrypt, ivEncrypt)
	content := []byte(src)
	content = PKCS5Padding(content, blkEncrypt.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)
	base64 := b64.StdEncoding.EncodeToString(crypted)
	return base64, nil
}

func AESDecrypt(crypt string, key []byte) (string, error) {
	encryptedData, _ := b64.StdEncoding.DecodeString(crypt)
	if len(crypt) == 0 {
		return "", &InvalidPassphraseError{"Invalid crypto"}
	}
	blk, iv, err := setKey(key)
	if err != nil {
		return "", &InvalidAESKeyError{"Invalid crypto"}
	}
	ecb := cipher.NewCBCDecrypter(blk, iv)
	decrypted := make([]byte, len(encryptedData))
	ecb.CryptBlocks(decrypted, encryptedData)
	return string(PKCS5Trimming(decrypted)), nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}
