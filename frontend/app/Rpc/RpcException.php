<?php
declare(strict_types=1);

namespace App\Rpc;

/** 调用后台失败：code 与 docs/PROTOCOL.md 的错误表一致。 */
final class RpcException extends \RuntimeException
{
    public function __construct(
        public readonly string $rpcCode,
        string $detail = '',
        public readonly bool $transport = false,
    ) {
        parent::__construct($detail === '' ? $rpcCode : $detail);
    }

    public static function transport(string $detail): self
    {
        return new self('transport', $detail, true);
    }

    /** 只把"能让用户看懂"的错误码透出去。 */
    public function userMessageKey(): string
    {
        $known = [
            'poll_not_found', 'poll_closed', 'already_voted', 'captcha_invalid', 'captcha_expired',
            'ip_blocked', 'rate_limited', 'invalid_argument', 'results_hidden',
        ];
        return in_array($this->rpcCode, $known, true) ? 'err.' . $this->rpcCode : 'err.internal';
    }
}
