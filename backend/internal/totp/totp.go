// Package totp 实现 RFC 6238（TOTP，SHA-1 / 6 位 / 30 秒），用于危险操作的二次确认。
// 只依赖标准库：密钥是 base32（无填充），二维码内容由调用方拼 otpauth:// URI。
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	Period = 30
	Digits = 6
	// 允许前后一个时间窗，容忍客户端时钟偏差。
	DefaultWindow = 1
)

var (
	ErrBadSecret = errors.New("totp: 密钥格式不正确")
	ErrBadCode   = errors.New("totp: 验证码不正确")
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret 生成 20 字节（160 bit）随机密钥，base32 编码。
func GenerateSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b32.EncodeToString(buf), nil
}

func normalizeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	s = strings.TrimRight(s, "=")
	key, err := b32.DecodeString(s)
	if err != nil || len(key) < 10 {
		return nil, ErrBadSecret
	}
	return key, nil
}

// Step 返回某个时刻对应的时间步。
func Step(t time.Time) int64 { return t.Unix() / Period }

// Code 计算某个时间步的 6 位验证码。
func Code(secret string, step int64) (string, error) {
	key, err := normalizeSecret(secret)
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%0*d", Digits, bin%1_000_000), nil
}

// Verify 校验验证码，返回命中的时间步。调用方必须记录该步，拒绝重复使用（防重放）。
func Verify(secret, code string, now time.Time, window int) (int64, error) {
	code = strings.TrimSpace(code)
	if len(code) != Digits {
		return 0, ErrBadCode
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return 0, ErrBadCode
		}
	}
	if window < 0 {
		window = 0
	}
	current := Step(now)
	for d := -window; d <= window; d++ {
		candidate, err := Code(secret, current+int64(d))
		if err != nil {
			return 0, err
		}
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			return current + int64(d), nil
		}
	}
	return 0, ErrBadCode
}

// ProvisioningURI 生成 authenticator 应用可识别的 otpauth:// URI。
func ProvisioningURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", strings.TrimRight(strings.ToUpper(secret), "="))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(Digits))
	q.Set("period", strconv.Itoa(Period))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
