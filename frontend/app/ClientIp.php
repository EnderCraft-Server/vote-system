<?php
declare(strict_types=1);

namespace App;

/** 取访客 IP：只有来自可信代理时才采信转发头，其余一律用 REMOTE_ADDR。 */
final class ClientIp
{
    public static function resolve(): string
    {
        $remote = (string)($_SERVER['REMOTE_ADDR'] ?? '');
        $header = (string)Bootstrap::cfg('security.client_ip_header', '');
        $trusted = (array)Bootstrap::cfg('security.trusted_proxies', []);

        if ($header === '' || !self::inRanges($remote, $trusted)) {
            return self::normalize($remote);
        }

        $key = 'HTTP_' . strtoupper(str_replace('-', '_', $header));
        $raw = (string)($_SERVER[$key] ?? '');
        if ($raw === '') {
            return self::normalize($remote);
        }
        // 多个值时取第一个（最靠近客户端），并再校验一次格式
        $first = trim(explode(',', $raw)[0]);
        return self::normalize($first);
    }

    private static function normalize(string $ip): string
    {
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return '0.0.0.0';
        }
        return $ip;
    }

    /** @param string[] $ranges */
    private static function inRanges(string $ip, array $ranges): bool
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return false;
        }
        foreach ($ranges as $cidr) {
            if (!str_contains((string)$cidr, '/')) {
                if (@inet_pton((string)$cidr) === $bin) {
                    return true;
                }
                continue;
            }
            [$net, $bits] = explode('/', (string)$cidr, 2);
            $netBin = @inet_pton($net);
            if ($netBin === false || strlen($netBin) !== strlen($bin)) {
                continue;
            }
            $bits = (int)$bits;
            $bytes = intdiv($bits, 8);
            if (substr($bin, 0, $bytes) !== substr($netBin, 0, $bytes)) {
                continue;
            }
            $rest = $bits % 8;
            if ($rest === 0) {
                return true;
            }
            $mask = 0xFF << (8 - $rest) & 0xFF;
            if ((ord($bin[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask)) {
                return true;
            }
        }
        return false;
    }
}
