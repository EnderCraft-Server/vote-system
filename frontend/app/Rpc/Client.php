<?php
declare(strict_types=1);

namespace App\Rpc;

use App\Bootstrap;

/**
 * 按 docs/PROTOCOL.md 实现的 TCP 客户端。
 * 每一帧都做 HMAC-SHA256 校验；响应验签失败一律当"后台异常"处理，绝不解析其中的数据。
 */
final class Client
{
    private const MAGIC_REQ = 'VOTE';
    private const MAGIC_RES = 'VOTR';
    private const VERSION = 1;
    private const MAX_FRAME = 1048576;
    private const CLOCK_SKEW = 60;

    private string $host;
    private int $port;
    private float $timeout;
    private string $secret;

    public function __construct(?array $config = null)
    {
        $cfg = $config ?? (array)Bootstrap::cfg('backend', []);
        $this->host = (string)($cfg['host'] ?? '127.0.0.1');
        $this->port = (int)($cfg['port'] ?? 7788);
        $this->timeout = (float)($cfg['timeout'] ?? 3.0);
        $this->secret = (string)($cfg['rpc_secret'] ?? '');
        if (strlen($this->secret) < 32) {
            throw new \RuntimeException('backend.rpc_secret 未配置或过短（至少 32 字节）');
        }
    }

    /**
     * @return array<string,mixed>
     * @throws RpcException
     */
    public function call(string $method, array $body = []): array
    {
        $requestId = random_bytes(16);
        $payload = $this->encodeRequest($method, $body, $requestId);

        $address = sprintf('tcp://%s:%d', $this->host, $this->port);
        $errno = 0;
        $errstr = '';
        $sock = @stream_socket_client($address, $errno, $errstr, $this->timeout);
        if ($sock === false) {
            throw RpcException::transport(sprintf('连接后台失败 %s: %s (%d)', $address, $errstr, $errno));
        }
        try {
            stream_set_timeout($sock, (int)$this->timeout);
            $this->writeAll($sock, pack('N', strlen($payload)) . $payload);
            $frame = $this->readFrame($sock);
        } finally {
            fclose($sock);
        }
        return $this->decodeResponse($frame, $requestId);
    }

    private function encodeRequest(string $method, array $body, string $requestId): string
    {
        if ($method === '' || strlen($method) > 63) {
            throw new \InvalidArgumentException('方法名非法');
        }
        $json = json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new \InvalidArgumentException('请求体无法编码');
        }
        $header = self::MAGIC_REQ . chr(self::VERSION) . chr(0) . pack('n', 0) . pack('J', time())
            . $requestId . random_bytes(16) . chr(strlen($method));
        $payload = $header . $method . pack('N', strlen($json)) . $json;
        return $payload . hash_hmac('sha256', $payload, $this->secret, true);
    }

    /** @return array<string,mixed> */
    private function decodeResponse(string $frame, string $requestId): array
    {
        if (strlen($frame) < 36 + 32) {
            throw RpcException::transport('响应帧过短');
        }
        $signature = substr($frame, -32);
        $payload = substr($frame, 0, -32);
        $expected = hash_hmac('sha256', $payload, $this->secret, true);
        if (!hash_equals($expected, $signature)) {
            throw RpcException::transport('响应签名校验失败');
        }
        if (substr($payload, 0, 4) !== self::MAGIC_RES) {
            throw RpcException::transport('响应 magic 不正确');
        }
        if (ord($payload[4]) !== self::VERSION) {
            throw RpcException::transport('协议版本不匹配');
        }
        $status = ord($payload[5]);
        $ts = unpack('J', substr($payload, 8, 8))[1];
        if (abs(time() - $ts) > self::CLOCK_SKEW) {
            throw RpcException::transport('响应时间戳超出允许范围');
        }
        if (substr($payload, 16, 16) !== $requestId) {
            throw RpcException::transport('响应与请求不匹配');
        }
        $bodyLen = unpack('N', substr($payload, 32, 4))[1];
        if ($bodyLen < 0 || $bodyLen > 262144 || strlen($payload) !== 36 + $bodyLen) {
            throw RpcException::transport('响应体长度非法');
        }
        $data = json_decode(substr($payload, 36, $bodyLen), true);
        if (!is_array($data)) {
            throw RpcException::transport('响应不是合法 JSON');
        }
        if ($status === 1) {
            $code = (string)($data['code'] ?? 'internal');
            $message = (string)($data['message'] ?? '');
            throw new RpcException($code, $message);
        }
        return $data;
    }

    private function writeAll($sock, string $bytes): void
    {
        $written = 0;
        $total = strlen($bytes);
        while ($written < $total) {
            $n = @fwrite($sock, substr($bytes, $written));
            if ($n === false || $n === 0) {
                throw RpcException::transport('写入后台失败');
            }
            $written += $n;
        }
    }

    private function readFrame($sock): string
    {
        $header = $this->readExact($sock, 4);
        $len = unpack('N', $header)[1];
        if ($len < 32 || $len > self::MAX_FRAME) {
            throw RpcException::transport('响应帧长度非法');
        }
        return $this->readExact($sock, $len);
    }

    private function readExact($sock, int $length): string
    {
        $buf = '';
        while (strlen($buf) < $length) {
            $chunk = @fread($sock, $length - strlen($buf));
            if ($chunk === false || $chunk === '') {
                $meta = stream_get_meta_data($sock);
                if (!empty($meta['timed_out'])) {
                    throw RpcException::transport('读取后台响应超时');
                }
                throw RpcException::transport('后台连接提前关闭');
            }
            $buf .= $chunk;
        }
        return $buf;
    }
}
