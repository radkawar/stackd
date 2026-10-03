package sts

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1" // XML Encryption OAEP defaults to SHA-1, independently of MGF.
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"errors"

	"github.com/beevik/etree"
)

var errSAMLDecryption = errors.New("SAML assertion decryption failed")

// decryptSAMLAssertion uses only keys supplied by the selected IAM provider.
// Encryption is never authentication: the caller must verify a signature over
// this plaintext assertion. AWS also verifies an optional response signature.
func decryptSAMLAssertion(encrypted *etree.Element, keys []SAMLDecryptionKey) (*etree.Element, error) {
	data, err := samlOne(encrypted, samlEncryptionNS, "EncryptedData")
	if err != nil || samlCount(encrypted, samlEncryptionNS, "EncryptedData") != 1 {
		return nil, errSAMLDecryption
	}
	if kind := data.SelectAttrValue("Type", ""); kind != "" && kind != samlEncryptionNS+"Element" {
		return nil, errSAMLDecryption
	}
	method, err := samlOne(data, samlEncryptionNS, "EncryptionMethod")
	if err != nil {
		return nil, errSAMLDecryption
	}
	algorithm := method.SelectAttrValue("Algorithm", "")
	keyBytes, gcm := 0, false
	switch algorithm {
	case samlEncryptionNS + "aes128-cbc":
		keyBytes = 16
	case samlEncryptionNS + "aes256-cbc":
		keyBytes = 32
	case samlEncryption11NS + "aes128-gcm":
		keyBytes, gcm = 16, true
	case samlEncryption11NS + "aes256-gcm":
		keyBytes, gcm = 32, true
	default:
		return nil, errSAMLDecryption
	}
	encryptedKey, err := samlEncryptedKey(encrypted, data)
	if err != nil {
		return nil, errSAMLDecryption
	}
	keyMethod, err := samlOne(encryptedKey, samlEncryptionNS, "EncryptionMethod")
	if err != nil {
		return nil, errSAMLDecryption
	}
	options, err := samlOAEPOptions(keyMethod)
	if err != nil {
		return nil, errSAMLDecryption
	}
	wrappedKey, err := samlCipherValue(encryptedKey)
	if err != nil {
		return nil, errSAMLDecryption
	}
	ciphertext, err := samlCipherValue(data)
	if err != nil {
		return nil, errSAMLDecryption
	}
	for i := len(keys) - 1; i >= 0; i-- {
		parsed, err := x509.ParsePKCS8PrivateKey(keys[i].PKCS8DER)
		if err != nil {
			continue
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok || len(wrappedKey) != key.Size() {
			continue
		}
		secret, err := key.Decrypt(rand.Reader, wrappedKey, options)
		if err != nil || len(secret) != keyBytes {
			continue
		}
		plaintext, err := samlAESDecrypt(secret, ciphertext, gcm)
		clear(secret)
		if err != nil {
			continue
		}
		assertion, err := parseSAMLXML(plaintext)
		clear(plaintext)
		if err == nil && assertion.NamespaceURI() == samlAssertionNS && assertion.Tag == "Assertion" && samlCount(assertion, samlAssertionNS, "Assertion") == 1 {
			return assertion, nil
		}
	}
	return nil, errSAMLDecryption
}

func samlEncryptedKey(encrypted, data *etree.Element) (*etree.Element, error) {
	if samlCount(encrypted, samlEncryptionNS, "EncryptedKey") != 1 {
		return nil, errSAMLDecryption
	}
	keyInfos := samlChildren(data, samlSignatureNS, "KeyInfo")
	if len(keyInfos) > 1 {
		return nil, errSAMLDecryption
	}
	if len(keyInfos) == 1 {
		nested := samlChildren(keyInfos[0], samlEncryptionNS, "EncryptedKey")
		if len(nested) == 1 {
			return nested[0], nil
		}
	}
	key, err := samlOne(encrypted, samlEncryptionNS, "EncryptedKey")
	if err != nil {
		return nil, err
	}
	// A sibling EncryptedKey must explicitly bind the encrypted data; neither
	// external RetrievalMethod URLs nor unrelated reference targets are allowed.
	refs, err := samlOne(key, samlEncryptionNS, "ReferenceList")
	if err != nil || len(refs.ChildElements()) != 1 {
		return nil, errSAMLDecryption
	}
	ref, err := samlOne(refs, samlEncryptionNS, "DataReference")
	id := data.SelectAttrValue("Id", "")
	if err != nil || id == "" || ref.SelectAttrValue("URI", "") != "#"+id {
		return nil, errSAMLDecryption
	}
	if len(keyInfos) == 1 {
		retrieval, err := samlOne(keyInfos[0], samlSignatureNS, "RetrievalMethod")
		if err != nil || key.SelectAttrValue("Id", "") == "" || retrieval.SelectAttrValue("URI", "") != "#"+key.SelectAttrValue("Id", "") {
			return nil, errSAMLDecryption
		}
	}
	return key, nil
}

func samlCipherValue(element *etree.Element) ([]byte, error) {
	data, err := samlOne(element, samlEncryptionNS, "CipherData")
	if err != nil || len(data.ChildElements()) != 1 {
		return nil, errSAMLDecryption
	}
	value, err := samlOne(data, samlEncryptionNS, "CipherValue")
	if err != nil {
		return nil, errSAMLDecryption
	}
	text, err := samlText(value)
	if err != nil {
		return nil, errSAMLDecryption
	}
	decoded, err := samlBase64(text)
	if err != nil || len(decoded) == 0 || len(decoded) > samlMaxXML {
		return nil, errSAMLDecryption
	}
	return decoded, nil
}

func samlOAEPOptions(method *etree.Element) (*rsa.OAEPOptions, error) {
	algorithm := method.SelectAttrValue("Algorithm", "")
	if algorithm != samlEncryptionNS+"rsa-oaep-mgf1p" && algorithm != samlEncryption11NS+"rsa-oaep" {
		return nil, errSAMLDecryption
	}
	options := &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA1}
	seen := make(map[string]bool)
	for _, child := range method.ChildElements() {
		name := child.NamespaceURI() + child.Tag
		if seen[name] {
			return nil, errSAMLDecryption
		}
		seen[name] = true
		switch {
		case child.NamespaceURI() == samlSignatureNS && child.Tag == "DigestMethod":
			options.Hash = samlDigest(child.SelectAttrValue("Algorithm", ""))
		case child.NamespaceURI() == samlEncryption11NS && child.Tag == "MGF":
			if algorithm != samlEncryption11NS+"rsa-oaep" {
				return nil, errSAMLDecryption
			}
			switch child.SelectAttrValue("Algorithm", "") {
			case samlEncryption11NS + "mgf1sha1":
				options.MGFHash = crypto.SHA1
			case samlEncryption11NS + "mgf1sha256":
				options.MGFHash = crypto.SHA256
			case samlEncryption11NS + "mgf1sha384":
				options.MGFHash = crypto.SHA384
			case samlEncryption11NS + "mgf1sha512":
				options.MGFHash = crypto.SHA512
			default:
				return nil, errSAMLDecryption
			}
		case child.NamespaceURI() == samlEncryptionNS && child.Tag == "OAEPparams":
			text, err := samlText(child)
			if err != nil {
				return nil, errSAMLDecryption
			}
			options.Label, err = samlBase64(text)
			if err != nil {
				return nil, errSAMLDecryption
			}
		default:
			return nil, errSAMLDecryption
		}
	}
	if options.Hash == 0 || !options.Hash.Available() {
		return nil, errSAMLDecryption
	}
	return options, nil
}

func samlDigest(algorithm string) crypto.Hash {
	switch algorithm {
	case samlSignatureNS + "sha1":
		return crypto.SHA1
	case samlEncryptionNS + "sha256":
		return crypto.SHA256
	case "http://www.w3.org/2001/04/xmldsig-more#sha384":
		return crypto.SHA384
	case samlEncryptionNS + "sha512":
		return crypto.SHA512
	default:
		return 0
	}
}

func samlAESDecrypt(key, ciphertext []byte, gcm bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errSAMLDecryption
	}
	if gcm {
		aead, err := cipher.NewGCM(block)
		if err != nil || len(ciphertext) < aead.NonceSize()+aead.Overhead() {
			return nil, errSAMLDecryption
		}
		plaintext, err := aead.Open(nil, ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():], nil)
		if err != nil {
			return nil, errSAMLDecryption
		}
		return plaintext, nil
	}
	if len(ciphertext) < 2*aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errSAMLDecryption
	}
	plaintext := make([]byte, len(ciphertext)-aes.BlockSize)
	cipher.NewCBCDecrypter(block, ciphertext[:aes.BlockSize]).CryptBlocks(plaintext, ciphertext[aes.BlockSize:])
	padding := int(plaintext[len(plaintext)-1])
	if padding < 1 || padding > aes.BlockSize || padding > len(plaintext) {
		clear(plaintext)
		return nil, errSAMLDecryption
	}
	// XML Encryption padding permits arbitrary preceding padding bytes; only
	// its final byte encodes the number of bytes to remove.
	return plaintext[:len(plaintext)-padding], nil
}
