package totp

import (
	"testing"
	"time"
)

// RFC 6238 附录 B 的 SHA-1 测试向量（密钥为 ASCII "12345678901234567890"）。
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestRFCVector(t *testing.T) {
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, c := range cases {
		got, err := Code(rfcSecret, Step(time.Unix(c.unix, 0)))
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Fatalf("T=%d 期望 %s，得到 %s", c.unix, c.want, got)
		}
	}
}

func TestVerifyWindowAndReplayData(t *testing.T) {
	now := time.Unix(1234567890, 0)
	code, _ := Code(rfcSecret, Step(now))
	step, err := Verify(rfcSecret, code, now, 1)
	if err != nil {
		t.Fatalf("正确码应通过：%v", err)
	}
	if step != Step(now) {
		t.Fatalf("时间步不对：%d", step)
	}
	// 上一个窗口的码也应通过（时钟偏差）
	prev, _ := Code(rfcSecret, Step(now)-1)
	if _, err := Verify(rfcSecret, prev, now, 1); err != nil {
		t.Fatalf("前一个窗口应被接受：%v", err)
	}
	// 超出窗口应失败
	old, _ := Code(rfcSecret, Step(now)-5)
	if _, err := Verify(rfcSecret, old, now, 1); err == nil {
		t.Fatal("超出窗口不应通过")
	}
	// 格式错误
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "12345a"} {
		if _, err := Verify(rfcSecret, bad, now, 1); err == nil {
			t.Fatalf("%q 不应通过", bad)
		}
	}
}

func TestSecretAndURI(t *testing.T) {
	s, err := GenerateSecret()
	if err != nil || len(s) < 32 {
		t.Fatalf("密钥生成异常：%q %v", s, err)
	}
	if _, err := Code(s, 1); err != nil {
		t.Fatalf("生成的密钥无法计算：%v", err)
	}
	uri := ProvisioningURI("Vote Super Admin Access", "admin", s)
	for _, want := range []string{"otpauth://totp/", "Vote%20Super%20Admin%20Access", "issuer=Vote+Super+Admin+Access", "digits=6", "period=30", "secret="} {
		if !contains(uri, want) {
			t.Fatalf("URI 缺少 %q：%s", want, uri)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
