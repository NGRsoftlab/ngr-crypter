// Copyright 2020 NGR Softlab
//
package crypter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

//////////////////////////////////////////////
// TODO: merge Encrypt/Encrypt2 and Decrypt1&Encrypt2
// TODO: use ngr-logging lib
//////////////////////////////////////////////

func addBase64Padding(value string) string {
	m := len(value) % 4
	if m != 0 {
		value += strings.Repeat("=", 4-m)
	}

	return value
}

func removeBase64Padding(value string) string {
	return strings.Replace(value, "=", "", -1)
}

func Pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

func UnPad(src []byte) ([]byte, error) {
	length := len(src)
	unPadding := int(src[length-1])

	if unPadding > length {
		return nil, errors.New("unpad error. This could happen when incorrect encryption key is used")
	}

	return src[:(length - unPadding)], nil
}

func Encrypt(key []byte, text string) (string, error) {
	if text == "" {
		return "", errors.New("code: 400, message: no password")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	msg := Pad([]byte(text))
	cipherText := make([]byte, aes.BlockSize+len(msg))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(cipherText[aes.BlockSize:], msg)
	finalMsg := removeBase64Padding(base64.URLEncoding.EncodeToString(cipherText))
	return finalMsg, nil
}

func Decrypt(key []byte, text string) (string, error) {
	if text == "" {
		return "", errors.New("code: 400, message: no password")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	decodedMsg, err := base64.URLEncoding.DecodeString(addBase64Padding(text))
	if err != nil {
		return "", err
	}

	if (len(decodedMsg) % aes.BlockSize) != 0 {
		return "", errors.New("blocksize must be multipe of decoded message length")
	}

	iv := decodedMsg[:aes.BlockSize]
	msg := decodedMsg[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(msg, msg)

	unPadMsg, err := UnPad(msg)
	if err != nil {
		return "", err
	}

	return string(unPadMsg), nil
}

///////////////////////////////
////////// LONG KEY ///////////
///////////////////////////////

func Encrypt2(key []byte, message []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	b := message
	b = PKCS5Padding(b, aes.BlockSize)
	encMessage := make([]byte, len(b))
	iv := key[:aes.BlockSize]
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encMessage, b)

	bufF := make([]byte, base64.StdEncoding.EncodedLen(len(encMessage)))
	base64.StdEncoding.Encode(bufF, encMessage)

	return bufF, nil
}

func Decrypt2(key []byte, encMessage []byte) ([]byte, error) {
	decodedBytes := make([]byte, len(encMessage))
	n, err := base64.StdEncoding.Decode(decodedBytes, encMessage)
	if err != nil {
		return []byte(""), errors.New("BAD DECRYPT: " + err.Error())
	}
	bytesToDecrypt := decodedBytes[:n]

	iv := key[:aes.BlockSize]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if (len(bytesToDecrypt) % aes.BlockSize) != 0 {
		return nil, errors.New("encMessage bad length")
	}

	decryptedBytes := make([]byte, len(bytesToDecrypt))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decryptedBytes, bytesToDecrypt)

	return PKCS5UnPadding(decryptedBytes), nil
}

func PKCS5Padding(cipher []byte, blockSize int) []byte {
	padding := blockSize - len(cipher)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(cipher, padText...)
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unPadding := int(src[length-1])

	return src[:(length - unPadding)]
}
