<?php
declare(strict_types=1);

namespace App;

/**
 * 无状态 CSRF 令牌：base64url(时间戳 . HMAC(secret, 时间戳|IP|用途))。
 * 不依赖 Cookie/Session，所以不存在"偷 Cookie 就能提交"的问题；令牌与 IP、投票绑定且会过期。
 */
final class Csrf
{
    public static function issue(string $purpose): string
    {
        $ts = (string)time();
        $ip = ClientIp::resolve();
        $mac = hash_hmac('sha256', $ts . '|' . $ip . '|' . $purpose, self::secret(), true);
        return rtrim(strtr(base64_encode($ts . '.' . $mac), '+/', '-_'), '=');
    }

    public static function verify(?string $token, string $purpose): bool
    {
        if (!is_string($token) || $token === '') {
            return false;
        }
        $raw = base64_decode(strtr($token, '-_', '+/'), true);
        if ($raw === false || !str_contains($raw, '.')) {
            return false;
        }
        [$ts, $mac] = explode('.', $raw, 2);
        if (!ctype_digit($ts)) {
            return false;
        }
        $ttl = (int)Bootstrap::cfg('security.csrf_ttl', 1800);
        if (abs(time() - (int)$ts) > $ttl) {
            return false;
        }
        $expected = hash_hmac('sha256', $ts . '|' . ClientIp::resolve() . '|' . $purpose, self::secret(), true);
        return hash_equals($expected, $mac);
    }

    private static function secret(): string
    {
        static $cached = null;
        if ($cached !== null) {
            return $cached;
        }
        $secret = (string)Bootstrap::cfg('security.csrf_secret', '');
        $weak = strlen($secret) < 32 || str_contains($secret, 'CHANGE_ME');
        if (!$weak) {
            return $cached = $secret;
        }
        // 绝不能退回"可复算的常量"——那等于没有 CSRF 保护。
        // 退而求其次：本进程随机生成，重启即失效，并明确告警。
        $cached = bin2hex(random_bytes(32));
        error_log('vote: security.csrf_secret 未配置或仍是 CHANGE_ME，已改用本进程随机密钥（重启后所有表单令牌失效）');
        return $cached;
    }
}
