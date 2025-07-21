package secure

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/scrypt"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func GenerateSecureRandomString(length int) (string, error) {
	for {
		result, err := generateRandomString(length)
		if err != nil {
			return "", err
		}
		if !IsWeakPassword(result) {
			return result, nil
		}
	}
}

// 实际的随机字符串生成逻辑（原函数拆解出来）
func generateRandomString(length int) (string, error) {
	result := make([]byte, length)
	max := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		result[i] = charset[n.Int64()]
	}
	return string(result), nil
}

func secureSeed() int64 {
	var seed int64
	err := binary.Read(rand.Reader, binary.BigEndian, &seed)
	if err != nil {
		// 回退到时间种子
		return time.Now().UnixNano()
	}
	return seed
}

// IsWeakPassword 判断一个密码是否太弱
func IsWeakPassword(password string) bool {
	if len(password) < 8 {
		return true
	}

	lowerPassword := strings.ToLower(password)

	// 常见弱密码列表（可扩展）
	weakList := []string{
		"123456", "password", "12345678", "qwerty", "abc123", "111111", "123123",
	}

	for _, weak := range weakList {
		if lowerPassword == weak {
			return true
		}
	}

	var hasLetter, hasDigit bool
	for _, c := range password {
		if unicode.IsLetter(c) {
			hasLetter = true
		}
		if unicode.IsDigit(c) {
			hasDigit = true
		}
	}

	// 如果缺少字母或数字，认为太弱
	if !hasLetter || !hasDigit {
		return true
	}

	return false
}

func DerivePSK(password string) ([]byte, error) {
	salt := []byte("gonc-psk-salt")
	key, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32) // 输出 256bit PSK
	if err != nil {
		return nil, err
	}
	return key, nil
}
