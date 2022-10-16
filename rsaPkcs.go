package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
)

var signature []byte
var privateKey *rsa.PrivateKey

func readFile_(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(f)
}

func createFile_(file string, privateKey []byte) error {
	f, err := os.Create(file)
	if err != nil {
		fmt.Println("Unable to create file:", err)
		os.Exit(1)
		return err
	}
	defer f.Close()
	f.Write(privateKey)
	return nil
}

func createSingn(t []byte) {
	rng := rand.Reader
	hashed := sha256.Sum256(t)
	var err error
	signature, err = rsa.SignPKCS1v15(rng, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return
	}
}

func verifySign(t []byte) {
	hashed := sha256.Sum256(t)
	err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка проверки: %s\n", err)
		return
	} else {
		fmt.Fprintf(os.Stderr, "Прошло проверку\n")
		return
	}
}

func genKey() {
	size := 2048
	nprimes := 2
	var err error
	privateKey, err = rsa.GenerateMultiPrimeKey(rand.Reader, nprimes, size)
	if err != nil {
		fmt.Printf("err: %s", err)
		return
	}
}

func encrypt(t []byte) {
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, &privateKey.PublicKey, t)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}
	createFile_("encrypt.txt", cipherText)
	fmt.Printf("Зашифрованный файл: %x\n", cipherText)
}

func decrypt(t []byte) {
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, t)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return
	}
	createFile_("decrypt.txt", plainText)
	fmt.Printf("расшифрованный файл: %s\n", plainText)

}

func main() {
	genKey()
	k := 0
	for k != 5 {
		fmt.Fprintln(os.Stdout, "Для создания подписи нажмите - 1")
		fmt.Fprintln(os.Stdout, "Для шифрования файла нажмите - 2")
		fmt.Fprintln(os.Stdout, "Для раcшифрования файла нажмите - 3")
		fmt.Fprintln(os.Stdout, "Для проверки подписи - 4")
		fmt.Fprintln(os.Stdout, "Для выхода - 5")
		fmt.Fscan(os.Stdin, &k)
		fmt.Print("\033[H\033[2J")
		switch k {
		case 1:
			t, _ := readFile_("test.txt")
			createSingn(t)
			fmt.Fprintln(os.Stdout, "подпись создана")
		case 2:
			t, _ := readFile_("test.txt")
			encrypt(t)
			fmt.Fprintln(os.Stdout, "Файл зашифрован и записан в encrypt.txt")
		case 3:
			t, err := readFile_("encrypt.txt")
			if err != nil {
				fmt.Fprintln(os.Stdout, "Сначала зашифруйте файл")
			}
			decrypt(t)
			fmt.Fprintln(os.Stdout, "Файл расшифрован и записан в decrypt.txt")
		case 4:
			t, _ := readFile_("test.txt")
			verifySign(t)
		case 5:
			return
		default:
			k = 0

		}
	}

}
