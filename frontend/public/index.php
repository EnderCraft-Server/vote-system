<?php
declare(strict_types=1);

require __DIR__ . '/../app/bootstrap.php';

\App\Bootstrap::init(dirname(__DIR__));

use App\Bootstrap;
use App\Controllers\CaptchaController;
use App\Controllers\HomeController;
use App\Controllers\PollController;
use App\Log;
use App\Router;
use App\View;

// ---- 安全响应头：前台不需要任何外部资源，也不许被 iframe 嵌入 ----
header('Content-Type: text/html; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
header('Permissions-Policy: geolocation=(), microphone=(), camera=(), interest-cohort=()');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

// ---- 路径解析（支持部署在子目录） ----
$uri = (string)($_SERVER['REQUEST_URI'] ?? '/');
$path = parse_url($uri, PHP_URL_PATH);
$path = is_string($path) ? rawurldecode($path) : '/';
$base = rtrim((string)Bootstrap::cfg('site.base_url', ''), '/');
if ($base !== '' && str_starts_with($path, parse_url($base, PHP_URL_PATH) ?: $base)) {
    $path = substr($path, strlen(parse_url($base, PHP_URL_PATH) ?: $base)) ?: '/';
}
$path = '/' . trim($path, '/');
if ($path === '/index.php') {
    $path = '/';
}

$router = new Router();
$router->get('/', [HomeController::class, 'index']);
$router->get('/p/{slug}', [PollController::class, 'show']);
$router->post('/p/{slug}/submit', [PollController::class, 'submit']);
$router->get('/p/{slug}/result', [PollController::class, 'result']);
$router->get('/captcha/{id}.png', [CaptchaController::class, 'image']);

$method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
// HEAD 与 GET 同语义
if ($method === 'HEAD') {
    $method = 'GET';
}

$matched = $router->match($method, $path);
if ($matched === null) {
    View::render('error', ['title' => '页面不存在', 'code' => 404, 'messageKey' => 'err.not_found'], 404);
    exit;
}

[$handler, $args] = $matched;
$controller = new $handler[0]();
$action = $handler[1];

try {
    $args === [] ? $controller->$action() : $controller->$action(...array_values($args));
} catch (Throwable $e) {
    Log::error('未捕获异常：' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
    View::render('error', ['title' => '服务暂时不可用', 'code' => 500, 'messageKey' => 'err.internal'], 500);
}
