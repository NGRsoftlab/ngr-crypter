// Copyright 2020 NGR Softlab
//
package crypter

import (
	"encoding/hex"
	"testing"
)

/////////////////////////////////////////////////
func TestEncrypt(t *testing.T) {
	//t.Parallel()
	text := "test sentence"
	key := "KKKKKKKKKKKKKKKK" //16

	res1, err := Encrypt([]byte(key), text)
	if err != nil {
		t.Fatal("Bad TestEncrypt1: ", err)
	}

	t.Log(res1, len(res1))

	res2, err := Decrypt([]byte(key), res1)
	if err != nil {
		t.Fatal("Bad TestEncrypt1: ", err)
	}

	t.Log(text, res2)

	if res2 != text {
		t.Fatal("non equal")
	}
}

/////////////////////////////////////////////////
func TestEncrypt_2(t *testing.T) {
	//t.Parallel()
	Etext := "bad sentence (not encrypted)"
	key := "KKKKKKKKKKKKKKKK" //16

	_, err := Decrypt([]byte(key), Etext)
	if err == nil {
		t.Fatal("Bad TestEncrypt1: ", err)
	}
}

/////////////////////////////////////////////////
func TestEncrypt2(t *testing.T) {
	//t.Parallel()
	text := "test sentence"
	key, err := hex.DecodeString("4444444444444444444444444444444444444444444444444444444444444444")
	if err != nil {
		t.Fatal("Bad key: ", err)
	}

	res1, err := Encrypt2(key, []byte(text))
	if err != nil {
		t.Fatal("Bad TestEncrypt1: ", err)
	}

	t.Log(string(res1), len(res1))

	res2, err := Decrypt2(key, res1)
	if err != nil {
		t.Fatal("Bad TestEncrypt1: ", err)
	}

	t.Log(text, string(res2))

	if string(res2) != text {
		t.Fatal("non equal")
	}
}

func TestEncrypt2_2(t *testing.T) {
	//t.Parallel()
	Etext := "abababababababab"
	key, err := hex.DecodeString("4444444444444444444444444444444444444444444444444444444444444444")
	if err != nil {
		t.Fatal("Bad key: ", err)
	}

	res2, err := Decrypt2(key, []byte(Etext))
	//must be bad. no panic.
	if err == nil {
		t.Fatal("Bad TestEncrypt1: ", err)
	}

	t.Log(res2)
}
