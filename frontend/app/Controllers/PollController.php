<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Bootstrap;
use App\ClientIp;
use App\Csrf;
use App\Log;
use App\Rpc\Client;
use App\Rpc\RpcException;
use App\View;

final class PollController
{
    public function show(string $slug): void
    {
        $ip = ClientIp::resolve();
        try {
            $detail = (new Client())->call('poll.get', ['slug' => $slug, 'ip' => $ip]);
        } catch (RpcException $e) {
            $this->renderFailure($e);
            return;
        }

        $poll = is_array($detail['poll'] ?? null) ? $detail['poll'] : [];
        $questions = is_array($detail['questions'] ?? null) ? $detail['questions'] : [];
        $captcha = null;
        $captchaError = null;
        if (!empty($poll['can_vote']) && (bool)Bootstrap::cfg('captcha.enabled', true)) {
            try {
                $captcha = (new Client())->call('captcha.create', ['ip' => $ip]);
            } catch (RpcException $e) {
                Log::warn('captcha.create 失败：' . $e->getMessage());
                $captchaError = $e;
            }
        }

        View::render('poll', [
            'title' => (string)($poll['title'] ?? '投票'),
            'poll' => $poll,
            'questions' => $questions,
            'captcha' => $captcha,
            'captchaError' => $captchaError,
            'csrf' => Csrf::issue('vote:' . $slug),
            'errors' => [],
            'old' => [],
        ]);
    }

    public function submit(string $slug): void
    {
        $ip = ClientIp::resolve();
        $client = new Client();

        try {
            $detail = $client->call('poll.get', ['slug' => $slug, 'ip' => $ip]);
        } catch (RpcException $e) {
            $this->renderFailure($e);
            return;
        }
        $poll = is_array($detail['poll'] ?? null) ? $detail['poll'] : [];
        $questions = is_array($detail['questions'] ?? null) ? $detail['questions'] : [];

        $old = [
            'answers' => $this->collectAnswers($questions),
            'captcha_answer' => is_string($_POST['captcha_answer'] ?? null) ? trim((string)$_POST['captcha_answer']) : '',
            'captcha_id' => is_string($_POST['captcha_id'] ?? null) ? (string)$_POST['captcha_id'] : '',
        ];

        if (!Csrf::verify(is_string($_POST['csrf'] ?? null) ? (string)$_POST['csrf'] : null, 'vote:' . $slug)) {
            $this->rerender($slug, $poll, $questions, 'err.csrf', [], 400);
            return;
        }
        if (empty($poll['can_vote'])) {
            $this->rerender($slug, $poll, $questions, 'err.poll_closed', $old, 403);
            return;
        }

        $payload = [
            'slug' => $slug,
            'ip' => $ip,
            'ua' => substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 512),
            'captcha' => [
                'id' => $old['captcha_id'],
                'answer' => $old['captcha_answer'],
            ],
            'answers' => $this->toPayload($questions, $old['answers']),
        ];

        try {
            $result = $client->call('vote.submit', $payload);
        } catch (RpcException $e) {
            if ($e->transport) {
                Log::error('vote.submit 传输失败：' . $e->getMessage());
                $this->rerender($slug, $poll, $questions, 'err.internal', $old, 503);
                return;
            }
            Log::warn('vote.submit 被拒绝：' . $e->rpcCode . ' ' . $e->getMessage());
            $status = match ($e->rpcCode) {
                'already_voted' => 409,
                'poll_closed', 'ip_blocked' => 403,
                'rate_limited' => 429,
                default => 400,
            };
            $this->rerender($slug, $poll, $questions, $e->userMessageKey(), $old, $status);
            return;
        }

        Log::write('info', 'vote ok slug=' . $slug . ' ip=' . $ip . ' receipt=' . (string)($result['receipt'] ?? ''));
        View::redirect(url('/p/' . rawurlencode($slug) . '/result?voted=1'));
    }

    public function result(string $slug): void
    {
        $ip = ClientIp::resolve();
        try {
            $data = (new Client())->call('poll.results', ['slug' => $slug, 'ip' => $ip]);
        } catch (RpcException $e) {
            if ($e->rpcCode === 'results_hidden') {
                View::render('result_locked', ['title' => '结果暂未公开'], 200);
                return;
            }
            $this->renderFailure($e);
            return;
        }
        $poll = is_array($data['poll'] ?? null) ? $data['poll'] : [];
        View::render('result', [
            'title' => (string)($poll['title'] ?? '结果'),
            'poll' => $poll,
            'result' => $data,
            'justVoted' => isset($_GET['voted']),
        ]);
    }

    /** @param array<int,array<string,mixed>> $questions @return array<int,array<string,mixed>> */
    private function collectAnswers(array $questions): array
    {
        $answers = [];
        foreach ($questions as $q) {
            $id = (int)($q['id'] ?? 0);
            $type = (string)($q['type'] ?? '');
            if ($id <= 0) {
                continue;
            }
            switch ($type) {
                case 'single':
                    $value = $_POST['q' . $id] ?? null;
                    $answers[$id] = ['choices' => is_string($value) && ctype_digit($value) ? [(int)$value] : []];
                    break;
                case 'multiple':
                    $values = $_POST['q' . $id] ?? [];
                    $clean = [];
                    if (is_array($values)) {
                        foreach (array_slice($values, 0, 32) as $v) {
                            if (is_string($v) && ctype_digit($v)) {
                                $clean[] = (int)$v;
                            }
                        }
                    }
                    $answers[$id] = ['choices' => array_values(array_unique($clean))];
                    break;
                case 'text':
                    $value = $_POST['q' . $id] ?? '';
                    $answers[$id] = ['text' => is_string($value) ? trim($value) : ''];
                    break;
                case 'rank':
                    $values = $_POST['q' . $id . '_rank'] ?? [];
                    $clean = [];
                    if (is_array($values)) {
                        foreach (array_slice($values, 0, 64) as $v) {
                            if (is_string($v) && ctype_digit($v)) {
                                $clean[] = (int)$v;
                            }
                        }
                    }
                    $answers[$id] = ['ranking' => $clean];
                    break;
            }
        }
        return $answers;
    }

    /** @param array<int,array<string,mixed>> $answers */
    private function toPayload(array $questions, array $answers): array
    {
        $items = [];
        foreach ($questions as $q) {
            $id = (int)($q['id'] ?? 0);
            if (!isset($answers[$id])) {
                continue;
            }
            $item = ['question_id' => $id];
            $type = (string)($q['type'] ?? '');
            if ($type === 'text') {
                $item['text'] = (string)($answers[$id]['text'] ?? '');
                if ($item['text'] === '') {
                    continue;
                }
            } elseif ($type === 'rank') {
                $item['ranking'] = $answers[$id]['ranking'] ?? [];
                if ($item['ranking'] === []) {
                    continue;
                }
            } else {
                $item['choices'] = $answers[$id]['choices'] ?? [];
                if ($item['choices'] === []) {
                    continue;
                }
            }
            $items[] = $item;
        }
        return $items;
    }

    /** @param array<string,mixed> $poll @param array<int,array<string,mixed>> $questions @param array<string,mixed> $old */
    private function rerender(string $slug, array $poll, array $questions, string $errorKey, array $old, int $status): void
    {
        $captcha = null;
        try {
            $captcha = (new Client())->call('captcha.create', ['ip' => ClientIp::resolve()]);
        } catch (RpcException $e) {
            Log::warn('重新生成验证码失败：' . $e->getMessage());
        }
        View::render('poll', [
            'title' => (string)($poll['title'] ?? '投票'),
            'poll' => $poll,
            'questions' => $questions,
            'captcha' => $captcha,
            'captchaError' => $captcha === null ? new RpcException('captcha_invalid') : null,
            'csrf' => Csrf::issue('vote:' . $slug),
            'errors' => [$errorKey],
            'old' => $old,
        ], $status);
    }

    private function renderFailure(RpcException $e): void
    {
        if ($e->transport) {
            Log::error('后台不可用：' . $e->getMessage());
            View::render('error', ['title' => '服务暂时不可用', 'code' => 503, 'messageKey' => 'err.backend_down'], 503);
            return;
        }
        if ($e->rpcCode === 'poll_not_found') {
            View::render('error', ['title' => '投票不存在', 'code' => 404, 'messageKey' => 'err.poll_not_found'], 404);
            return;
        }
        Log::warn('poll 接口失败：' . $e->rpcCode . ' ' . $e->getMessage());
        View::render('error', ['title' => '无法打开投票', 'code' => 400, 'messageKey' => $e->userMessageKey()], 400);
    }
}
