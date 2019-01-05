package main

import (
	"bytes"
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

	"golang.org/x/crypto/ssh/terminal"
)

var iv = []byte("masterskey16bits")

func printHelp() {
	_, app := filepath.Split(os.Args[0])
	fmt.Printf("Usage: %s [option] /path/filename\n", app)
	fmt.Println()
	fmt.Printf("Option:\n")
	fmt.Printf(" -e,--encrypt\n")
	fmt.Printf(" -d,--decrypt\n")
	fmt.Printf("(no option reads encrypted file)\n")
	fmt.Println()
}

func main() {
	var mode, key, file string

	for _, v := range os.Args {
		switch v {
		case "-e":
			mode = "Encrypt"
		case "--encrypt":
			mode = "Encrypt"
		case "-d":
			mode = "Decrypt"
		case "--dectrypt":
			mode = "Decrypt"
		default:
			file = v
		}
	}

	if file == "" || len(os.Args) == 1 {
		printHelp()
		return
	}
	if _, err := os.Stat(file); os.IsNotExist(err) {
		fmt.Printf("%s does not exist. try again\n", file)
		return
	}

	// -------------------

	var w []byte
	r, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	if mode == "Encrypt" {
		key = SetPassword(3, "*")

		w, err = encrypt(r, key)
		if err != nil {
			panic(err)
		}
	} else {
		key = AskPassword()

		w, err = decrypt(r, key)
		if err != nil {
			fmt.Println("Wrong Password")
			return
		}
	}
	if mode == "" {
		fmt.Printf(string(w))

	} else {
		err = ioutil.WriteFile(file, w, 0644)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Successfully %sed %s\n", mode, file)
	}
}

func md5hash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(md5hash(passphrase)))
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
	key := []byte(md5hash(passphrase))
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

func AskPassword() string {
	fmt.Printf("Enter Password: ")

	pw, _ := maskInput("*")
	return string(pw)
}

func SetPassword(lenght int, mask string) string {
	var pw string

	for {
		fmt.Printf("Enter Password: ")
		password, _ := maskInput(mask)

		if len(password) < lenght {
			fmt.Printf("Password must contain at least %d charecters, try again.\n", lenght)
			continue
		}

		fmt.Printf("Confirm Password: ")
		confirm, _ := maskInput(mask)

		if !bytes.Equal(password, confirm) {
			fmt.Printf("Password did not match, try again.\n")
			continue
		}

		pw = string(password)
		break
	}

	return pw
}

func maskInput(mask string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	state, err := terminal.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	defer terminal.Restore(fd, state)

	// read and manipulate stdin
	var buf []byte
	for {
		var b [1]byte
		n, err := os.Stdin.Read(b[:])
		if err != nil && err != io.EOF {
			return nil, err
		}
		if n == 0 || b[0] == '\n' || b[0] == '\r' {
			break
		}

		buf = append(buf, b[0])
		fmt.Printf(mask)
	}

	fmt.Printf("\r\n")
	return buf, nil
}
