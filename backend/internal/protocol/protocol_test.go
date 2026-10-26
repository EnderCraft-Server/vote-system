package protocol

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func TestRequestRoundTrip(t *testing.T) {
	body := []byte(`{"ip":"1.2.3.4"}`)
	payload, err := EncodeRequest(testSecret, "captcha.create", body)
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}
	req, err := DecodeRequest(testSecret, payload, time.Now(), 60*time.Second)
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	if req.Method != "captcha.create" {
		t.Fatalf("method = %q", req.Method)
	}
	if !bytes.Equal(req.Body, body) {
		t.Fatalf("body = %q", req.Body)
	}
	if req.RequestID == ([16]byte{}) || req.Nonce == ([16]byte{}) {
		t.Fatal("request id / nonce 未填充")
	}
}

func TestRequestRejectsTamperedBody(t *testing.T) {
	payload, err := EncodeRequest(testSecret, "poll.list", []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	payload[len(payload)/2] ^= 0xFF
	if _, err := DecodeRequest(testSecret, payload, time.Now(), 60*time.Second); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("期望 ErrBadMAC，得到 %v", err)
	}
}

func TestRequestRejectsWrongSecret(t *testing.T) {
	payload, _ := EncodeRequest(testSecret, "poll.list", []byte(`{}`))
	if _, err := DecodeRequest([]byte("ffffffffffffffffffffffffffffffff"), payload, time.Now(), time.Minute); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("期望 ErrBadMAC，得到 %v", err)
	}
}

func TestRequestRejectsStaleTimestamp(t *testing.T) {
	payload, _ := EncodeRequest(testSecret, "poll.list", []byte(`{}`))
	if _, err := DecodeRequest(testSecret, payload, time.Now().Add(5*time.Minute), time.Minute); !errors.Is(err, ErrStale) {
		t.Fatalf("期望 ErrStale，得到 %v", err)
	}
}

func TestRequestRejectsBadMethodName(t *testing.T) {
	if _, err := EncodeRequest(testSecret, "bad method", nil); !errors.Is(err, ErrBadMethod) {
		t.Fatalf("期望 ErrBadMethod，得到 %v", err)
	}
}

func TestResponseRoundTrip(t *testing.T) {
	id := [16]byte{1, 2, 3}
	payload := EncodeResponse(testSecret, id, StatusOK, []byte(`{"pong":true}`))
	resp, err := DecodeResponse(testSecret, payload, time.Now(), time.Minute)
	if err != nil {
		t.Fatalf("DecodeResponse: %v", err)
	}
	if resp.Status != StatusOK || resp.RequestID != id {
		t.Fatalf("响应字段不对：%+v", resp)
	}
	payload[10] ^= 0x01
	if _, err := DecodeResponse(testSecret, payload, time.Now(), time.Minute); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("期望 ErrBadMAC，得到 %v", err)
	}
}

func TestFrameRoundTripAndLimit(t *testing.T) {
	// 合法帧至少要包含 32 字节 MAC，这里用 64 字节 body 做往返
	body := bytes.Repeat([]byte("a"), 64)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, body); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("got %q", got)
	}

	big := make([]byte, 2048)
	var buf2 bytes.Buffer
	_ = WriteFrame(&buf2, big)
	if _, err := ReadFrame(&buf2, 1024); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("期望 ErrFrameTooLarge，得到 %v", err)
	}
}

func TestNonceCache(t *testing.T) {
	c := NewNonceCache(time.Minute)
	n := [16]byte{9}
	now := time.Now()
	if c.Seen(n, now) {
		t.Fatal("首次不应判为重放")
	}
	if !c.Seen(n, now.Add(time.Second)) {
		t.Fatal("第二次应判为重放")
	}
	if c.Seen(n, now.Add(2*time.Minute)) {
		t.Fatal("过期后应允许")
	}
}
