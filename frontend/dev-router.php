<?php
declare(strict_types=1);

/**
 * 仅用于本地开发：php -S 127.0.0.1:8080 -t public dev-router.php
 * 生产环境用 nginx/apache 的 rewrite 规则把不存在的路径交给 public/index.php。
 */

$path = parse_url((string)($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
$path = is_string($path) ? $path : '/';
$file = __DIR__ . '/public' . $path;

if ($path !== '/' && is_file($file) && !str_ends_with($file, '.php')) {
    return false; // 交给内置服务器直接输出静态文件
}

require __DIR__ . '/public/index.php';
