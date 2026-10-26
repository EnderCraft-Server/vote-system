<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Log;
use App\Rpc\Client;
use App\Rpc\RpcException;

final class CaptchaController
{
    public function image(string $id): void
    {
        if (!preg_match('/^[a-f0-9]{16,64}$/', $id)) {
            http_response_code(404);
            header('Content-Type: image/png');
            return;
        }
        try {
            $data = (new Client())->call('captcha.image', ['id' => $id]);
        } catch (RpcException $e) {
            Log::warn('captcha.image 失败：' . $e->getMessage());
            http_response_code(410);
            header('Content-Type: text/plain; charset=utf-8');
            echo 'captcha expired';
            return;
        }
        $png = base64_decode((string)($data['png'] ?? ''), true);
        if ($png === false || $png === '') {
            http_response_code(500);
            return;
        }
        header('Content-Type: image/png');
        header('Content-Length: ' . strlen($png));
        header('Cache-Control: no-store, max-age=0');
        header('X-Content-Type-Options: nosniff');
        echo $png;
    }
}
