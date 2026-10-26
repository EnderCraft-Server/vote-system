// Package protocol 实现前台(PHP)与后台(Go)之间的 TCP 帧格式。
// 帧布局见 docs/PROTOCOL.md，任何改动都必须同步那边。
package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

const (
	RequestMagic  = "VOTE"
	ResponseMagic = "VOTR"
	Version       = 1

	// MaxFrameBytes 是单帧上限，与 docs/PROTOCOL.md 一致。
	MaxFrameBytes = 1 << 20
	// MaxBodyBytes 是 JSON body 上限。
	MaxBodyBytes = 256 << 10

	headerLen = 53 // magic(4)+ver(1)+flags(1)+reserved(2)+ts(8)+id(16)+nonce(16)+methodLen(1)+bodyLen(4) 的固定部分之前
	macLen    = 32
)

// 协议层错误：出现这些错误说明对端不是可信的调用方，服务端应当直接断开。
var (
	ErrFrameTooLarge = errors.New("帧超过上限")
	ErrShortFrame    = errors.New("帧长度不足")
	ErrBadMagic      = errors.New("magic 不正确")
	ErrBadVersion    = errors.New("协议版本不支持")
	ErrBadFlags      = errors.New("保留字段非 0")
	ErrBadMAC        = errors.New("HMAC 校验失败")
	ErrStale         = errors.New("时间戳超出允许偏移")
	ErrBadMethod     = errors.New("方法名非法")
	ErrBadBody       = errors.New("body 非法")
)

type Request struct {
	Method    string
	Body      []byte
	Timestamp int64
	RequestID [16]byte
	Nonce     [16]byte
}

type Response struct {
	Status    byte
	Body      []byte
	RequestID [16]byte
	Timestamp int64
}

const (
	StatusOK    byte = 0
	StatusError byte = 1
)

func randomID() [16]byte {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand 失败说明系统已经不可信，这里 panic 比继续用弱随机好。
		panic("crypto/rand 不可用：" + err.Error())
	}
	return b
}

func sign(secret, payload []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(payload)
	return m.Sum(nil)
}

// EncodeRequest 生成一帧请求的 payload（不含 4 字节长度前缀）。
func EncodeRequest(secret []byte, method string, body []byte) ([]byte, error) {
	if len(method) == 0 || len(method) > 63 || !validMethod(method) {
		return nil, ErrBadMethod
	}
	if len(body) > MaxBodyBytes {
		return nil, ErrBadBody
	}
	buf := make([]byte, 0, headerLen+len(method)+len(body)+macLen)
	buf = append(buf, RequestMagic...)
	buf = append(buf, Version, 0, 0, 0)
	buf = binary.BigEndian.AppendUint64(buf, uint64(time.Now().Unix()))
	id := randomID()
	buf = append(buf, id[:]...)
	nonce := randomID()
	buf = append(buf, nonce[:]...)
	buf = append(buf, byte(len(method)))
	buf = append(buf, method...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(body)))
	buf = append(buf, body...)
	return append(buf, sign(secret, buf)...), nil
}

// DecodeRequest 校验并解析请求 payload。now 用于时间戳检查，skew 是允许偏移。
func DecodeRequest(secret, payload []byte, now time.Time, skew time.Duration) (*Request, error) {
	if len(payload) < 4+1+1+2+8+16+16+1+4+macLen {
		return nil, ErrShortFrame
	}
	// 先验签，再信任任何字段。
	if subtle.ConstantTimeCompare(sign(secret, payload[:len(payload)-macLen]), payload[len(payload)-macLen:]) != 1 {
		return nil, ErrBadMAC
	}
	if string(payload[0:4]) != RequestMagic {
		return nil, ErrBadMagic
	}
	if payload[4] != Version {
		return nil, ErrBadVersion
	}
	if payload[5] != 0 || payload[6] != 0 || payload[7] != 0 {
		return nil, ErrBadFlags
	}
	ts := int64(binary.BigEndian.Uint64(payload[8:16]))
	if d := now.Sub(time.Unix(ts, 0)); d > skew || d < -skew {
		return nil, ErrStale
	}
	var id, nonce [16]byte
	copy(id[:], payload[16:32])
	copy(nonce[:], payload[32:48])
	mlen := int(payload[48])
	if mlen == 0 || mlen > 63 {
		return nil, ErrBadMethod
	}
	off := 49
	if len(payload) < off+mlen+4+macLen {
		return nil, ErrShortFrame
	}
	method := string(payload[off : off+mlen])
	if !validMethod(method) {
		return nil, ErrBadMethod
	}
	off += mlen
	blen := int(binary.BigEndian.Uint32(payload[off : off+4]))
	off += 4
	if blen < 0 || blen > MaxBodyBytes {
		return nil, ErrBadBody
	}
	if len(payload) != off+blen+macLen {
		return nil, ErrShortFrame
	}
	return &Request{
		Method:    method,
		Body:      payload[off : off+blen],
		Timestamp: ts,
		RequestID: id,
		Nonce:     nonce,
	}, nil
}

func validMethod(m string) bool {
	for i := 0; i < len(m); i++ {
		c := m[i]
		ok := c == '.' || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// EncodeResponse 生成响应 payload。
func EncodeResponse(secret []byte, id [16]byte, status byte, body []byte) []byte {
	if len(body) > MaxBodyBytes {
		body = []byte(`{"code":"internal","message":"响应体过大"}`)
		status = StatusError
	}
	buf := make([]byte, 0, 36+len(body)+macLen)
	buf = append(buf, ResponseMagic...)
	buf = append(buf, Version, status, 0, 0)
	buf = binary.BigEndian.AppendUint64(buf, uint64(time.Now().Unix()))
	buf = append(buf, id[:]...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(body)))
	buf = append(buf, body...)
	return append(buf, sign(secret, buf)...)
}

// DecodeResponse 校验并解析响应 payload（前台侧使用）。
func DecodeResponse(secret, payload []byte, now time.Time, skew time.Duration) (*Response, error) {
	if len(payload) < 36+macLen {
		return nil, ErrShortFrame
	}
	if subtle.ConstantTimeCompare(sign(secret, payload[:len(payload)-macLen]), payload[len(payload)-macLen:]) != 1 {
		return nil, ErrBadMAC
	}
	if string(payload[0:4]) != ResponseMagic {
		return nil, ErrBadMagic
	}
	if payload[4] != Version {
		return nil, ErrBadVersion
	}
	status := payload[5]
	if status != StatusOK && status != StatusError {
		return nil, ErrBadFlags
	}
	ts := int64(binary.BigEndian.Uint64(payload[8:16]))
	if d := now.Sub(time.Unix(ts, 0)); d > skew || d < -skew {
		return nil, ErrStale
	}
	var id [16]byte
	copy(id[:], payload[16:32])
	blen := int(binary.BigEndian.Uint32(payload[32:36]))
	if blen < 0 || blen > MaxBodyBytes {
		return nil, ErrBadBody
	}
	if len(payload) != 36+blen+macLen {
		return nil, ErrShortFrame
	}
	return &Response{Status: status, Body: payload[36 : 36+blen], RequestID: id, Timestamp: ts}, nil
}

// ReadFrame 读出 4 字节长度前缀 + payload，并强制上限。
func ReadFrame(r io.Reader, max int) ([]byte, error) {
	if max <= 0 || max > MaxFrameBytes {
		max = MaxFrameBytes
	}
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n < 0 || n > max || n < macLen {
		return nil, ErrFrameTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// WriteFrame 写出 4 字节长度前缀 + payload。
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrameBytes {
		return ErrFrameTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// NonceCache 记录最近出现过的 nonce，防止同一帧被重放。
type NonceCache struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[[16]byte]time.Time
}

func NewNonceCache(ttl time.Duration) *NonceCache {
	return &NonceCache{ttl: ttl, seen: make(map[[16]byte]time.Time)}
}

// Seen 记录 nonce；返回 true 表示这是重放。
func (c *NonceCache) Seen(nonce [16]byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.seen[nonce]; ok && now.Before(exp) {
		return true
	}
	c.seen[nonce] = now.Add(c.ttl)
	if len(c.seen) > 100000 {
		for k, exp := range c.seen {
			if now.After(exp) {
				delete(c.seen, k)
			}
		}
	}
	return false
}

// ProtocolError 用于给日志提供可读的原因。
func ProtocolError(err error) string {
	switch {
	case errors.Is(err, ErrBadMAC):
		return "bad_mac"
	case errors.Is(err, ErrStale):
		return "stale_timestamp"
	case errors.Is(err, ErrBadMagic):
		return "bad_magic"
	case errors.Is(err, ErrBadVersion):
		return "bad_version"
	case errors.Is(err, ErrBadFlags):
		return "bad_flags"
	case errors.Is(err, ErrBadMethod):
		return "bad_method"
	case errors.Is(err, ErrBadBody):
		return "bad_body"
	case errors.Is(err, ErrShortFrame):
		return "short_frame"
	case errors.Is(err, ErrFrameTooLarge):
		return "frame_too_large"
	case errors.Is(err, io.EOF):
		return "eof"
	default:
		return strings.ToLower(fmt.Sprintf("%v", err))
	}
}
