<?php
declare(strict_types=1);

namespace App;

/**
 * 前台启动：加载配置、注册自动加载、按环境设置错误处理。
 * 生产环境绝不把 PHP 报错或后台 message 打到页面上。
 */

final class Bootstrap
{
    public static array $config = [];
    public static string $basePath = '';
    public static bool $debug = false;

    public static function init(string $basePath): void
    {
        self::$basePath = rtrim($basePath, '/\\');
        require self::$basePath . '/app/helpers.php';

        spl_autoload_register(static function (string $class): void {
            if (!str_starts_with($class, 'App\\')) {
                return;
            }
            $path = self::$basePath . '/app/' . str_replace('\\', '/', substr($class, 4)) . '.php';
            if (is_file($path)) {
                require $path;
            }
        });

        $configPath = self::$basePath . '/config/config.php';
        if (!is_file($configPath)) {
            $configPath = self::$basePath . '/config/config.example.php';
            if (!is_file($configPath)) {
                http_response_code(500);
                echo '配置文件缺失：请把 config/config.example.php 复制为 config/config.php';
                exit;
            }
        }
        $config = require $configPath;
        self::$config = is_array($config) ? $config : [];
        self::$debug = (bool)(self::$config['debug'] ?? false) || (self::$config['env'] ?? 'production') === 'development';

        ini_set('display_errors', self::$debug ? '1' : '0');
        ini_set('display_startup_errors', self::$debug ? '1' : '0');
        ini_set('log_errors', '1');
        error_reporting(E_ALL);

        date_default_timezone_set('Asia/Shanghai');

        set_error_handler(static function (int $severity, string $message, string $file = '', int $line = 0): bool {
            if (!(error_reporting() & $severity)) {
                return false;
            }
            throw new \ErrorException($message, 0, $severity, $file, $line);
        });

        register_shutdown_function(static function (): void {
            $err = error_get_last();
            if ($err === null || !in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
                return;
            }
            Log::error('fatal: ' . $err['message'] . ' @ ' . $err['file'] . ':' . $err['line']);
            if (!self::$debug && !headers_sent()) {
                http_response_code(500);
                header('Content-Type: text/html; charset=utf-8');
                echo '<!doctype html><meta charset="utf-8"><title>服务暂时不可用</title>'
                    . '<p style="font:16px/1.7 system-ui;padding:48px;max-width:640px;margin:0 auto">服务暂时不可用，请稍后再试。</p>';
            }
        });

        I18n::init(self::$config);
    }

    public static function cfg(string $path, mixed $default = null): mixed
    {
        $node = self::$config;
        foreach (explode('.', $path) as $key) {
            if (!is_array($node) || !array_key_exists($key, $node)) {
                return $default;
            }
            $node = $node[$key];
        }
        return $node;
    }
}
