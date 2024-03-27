package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
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

func Encrypt(src string, key string) (string, error) {
	if len(src) == 0 {
		return "", &InvalidEncryptedDataError{"Invalid crypto"}
	}
	blkEncrypt, ivEncrypt, err := setKey([]byte(key))
	if err != nil {
		return "", &InvalidAESKeyError{"Invalid crypto"}
	}
	ecb := cipher.NewCBCEncrypter(blkEncrypt, ivEncrypt)
	content := []byte(src)
	content = pkcs5Padding(content, blkEncrypt.BlockSize())
	encrypted := make([]byte, len(content))
	ecb.CryptBlocks(encrypted, content)
	b64 := base64.StdEncoding.EncodeToString(encrypted)
	return b64, nil
}

func Decrypt(crypt string, key string) (string, error) {
	encryptedData, _ := base64.StdEncoding.DecodeString(crypt)
	if len(crypt) == 0 {
		return "", &InvalidPassphraseError{"Invalid crypto"}
	}
	blk, iv, err := setKey([]byte(key))
	if err != nil {
		return "", &InvalidAESKeyError{"Invalid crypto"}
	}
	ecb := cipher.NewCBCDecrypter(blk, iv)
	decrypted := make([]byte, len(encryptedData))
	ecb.CryptBlocks(decrypted, encryptedData)
	return string(pkcs5Trimming(decrypted)), nil
}

func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padded := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padded...)
}

func pkcs5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}
