<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Log;
use App\Rpc\Client;
use App\Rpc\RpcException;
use App\View;

final class HomeController
{
    public function index(): void
    {
        $polls = [];
        $error = null;
        try {
            $data = (new Client())->call('poll.list');
            $polls = is_array($data['polls'] ?? null) ? $data['polls'] : [];
        } catch (RpcException $e) {
            Log::error('poll.list 失败：' . $e->getMessage());
            $error = $e;
        }

        View::render('home', [
            'polls' => $polls,
            'error' => $error,
            'title' => '投票',
        ], $error === null ? 200 : 503);
    }
}
