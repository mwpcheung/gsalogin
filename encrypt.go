package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

func unhex(hexStr string) []byte {
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ReplaceAll(hexStr, "\r", "")
	hexStr = strings.ReplaceAll(hexStr, "\n", "")
	hexStr = strings.ReplaceAll(hexStr, "\t", "")
	bytes, _ := hex.DecodeString(hexStr)
	return bytes
}

var (
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize = errors.New("invalid blocksize")

	// ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrInvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")

	// ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")
)

func encrypt(aeskey string, filename string) {
	plaintext, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err.Error())
	}

	key := []byte(aeskey)

	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	plaintext, _ = pkcs7Pad(plaintext, block.BlockSize())
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	bm := cipher.NewCBCEncrypter(block, iv)
	bm.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	//stream := cipher.NewCFBEncrypter(block, iv)
	//stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// create a new file for saving the encrypted data.
	f, err := os.Create(filename + ".aes")
	if err != nil {
		panic(err.Error())
	}
	_, err = io.Copy(f, bytes.NewReader(ciphertext))
	if err != nil {
		panic(err.Error())
	}
}

func decrypt(aesKey string, inputFile string) {
	ciphertext, err := ioutil.ReadFile(inputFile)
	if err != nil {
		panic(err.Error())
	}
	// Key
	key := []byte(aesKey)
	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	bm := cipher.NewCBCDecrypter(block, iv)
	bm.CryptBlocks(ciphertext, ciphertext)
	ciphertext, _ = pkcs7Unpad(ciphertext, aes.BlockSize)
	f, err := os.Create(inputFile + ".ts")
	if err != nil {
		panic(err.Error())
	}
	_, err = io.Copy(f, bytes.NewReader(ciphertext))
	if err != nil {
		panic(err.Error())
	}
}

// pkcs7Pad right-pads the given byte slice with 1 to n bytes, where
// n is the block size. The size of the result is x times n, where x
// is at least 1.
func pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

// pkcs7Unpad validates and unpads data from the given bytes slice.
// The returned value will be 1 to n bytes smaller depending on the
// amount of padding, where n is the block size.
func pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	if len(b)%blocksize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, ErrInvalidPKCS7Padding
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, ErrInvalidPKCS7Padding
		}
	}
	return b[:len(b)-n], nil
}

//DecryptCBC aes_cbc_mode
func DecryptCBC(key, iv, ciphertext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(iv) >= block.BlockSize() {
		iv = iv[:block.BlockSize()]
	} else {
		iv = make([]byte, block.BlockSize())
	}

	plaintext := make([]byte, len(ciphertext))
	bm := cipher.NewCBCDecrypter(block, iv)
	bm.CryptBlocks(plaintext, ciphertext)
	plaintext, _ = pkcs7Unpad(plaintext, block.BlockSize())
	return plaintext
}
