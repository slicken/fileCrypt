package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

var iv = []byte("masterskey16bits")

func printHelp() {
	_, main := filepath.Split(os.Args[0])
	fmt.Printf("Usage: %s [option] PASSWORD /path/filename\n", main)
	fmt.Println()
	fmt.Printf("Options:\n")
	fmt.Printf(" -e,--encrypt\n")
	fmt.Printf(" -d,--decrypt\n")
	fmt.Printf(" -r,--read\n")
	fmt.Println()
}

func main() {
	if len(os.Args) != 4 {
		printHelp()
		return
	}
	var mode, key, file string
	for i, v := range os.Args {
		switch i {
		case 1:
			if v == "-e" || v == "--encrypt" {
				mode = "Encrypt"

			} else if v == "-d" || v == "--decrypt" {
				mode = "Decrypt"

			} else if v == "-r" || v == "--read" {
				mode = "Read"
			} else {
				printHelp()
				return
			}
		case 2:
			key = v
		case 3:
			file = v
			if _, err := os.Stat(file); os.IsNotExist(err) {
				fmt.Printf("%s does not exist. try again\n", file)
				return
			}
		}
	}

	var wBytes []byte
	rBytes, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	if mode == "Encrypt" {
		wBytes, err = encrypt(rBytes, key)
		if err != nil {
			panic(err)
		}
	} else {
		wBytes, err = decrypt(rBytes, key)
		if err != nil {
			panic(err)
		}
	}
	if mode == "Read" {
		fmt.Printf(string(wBytes))

	} else {
		err = ioutil.WriteFile(file, wBytes, 0644)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Successfully %sed %s\n", mode, file)
	}
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	// encode to string
	return []byte(base64.URLEncoding.EncodeToString(ciphertext)), nil
}

func decrypt(data []byte, passphrase string) ([]byte, error) {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// decode string
	msg, err := base64.URLEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := msg[:nonceSize], msg[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
