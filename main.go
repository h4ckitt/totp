package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

func main() {
	key := "12345678901234567890"
	//interval := 30
	// HOTP
	fmt.Println(calculateOTP(key, 0))

	// TOTP
	fmt.Println(calculateOTP(key, getTimeStep(30)))

	for range time.Tick(30 * time.Second) {
		fmt.Println(calculateOTP(key, getTimeStep(30)))
	}
}

func calculateOTP(key string, counter uint64) uint32 {
	valueBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(valueBytes, counter)

	h := hmac.New(sha1.New, []byte(key))
	h.Write(valueBytes)

	hash := h.Sum(nil)
	offset := hash[len(hash)-1] & 0xf
	hash[offset] = hash[offset] & 0x7f // mask the MSB to a zero to convert it to an unsigned int
	data := binary.BigEndian.Uint32(hash[offset : offset+4])
	return data % uint32(math.Pow(10, 6))
}

func getTimeStep(interval int64) uint64 {
	return uint64(time.Now().Unix() / interval)
}
