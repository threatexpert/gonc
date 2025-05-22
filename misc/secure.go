package misc

import (
	"crypto/rand"
	"math/big"
	"strings"
	"unicode"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func GenerateSecureRandomString(length int) (string, error) {
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
