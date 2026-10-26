<?php
declare(strict_types=1);

namespace App;

/** 只写文件日志；页面永远不展示内部错误细节。 */
final class Log
{
    public static function write(string $level, string $message): void
    {
        $path = (string)Bootstrap::cfg('log.path', Bootstrap::$basePath . '/storage/logs/app.log');
        $dir = dirname($path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0775, true);
        }
        $line = sprintf("[%s] %s %s\n", date('c'), strtoupper($level), str_replace("\n", ' ', $message));
        @file_put_contents($path, $line, FILE_APPEND | LOCK_EX);
    }

    public static function error(string $message): void
    {
        self::write('error', $message);
    }

    public static function warn(string $message): void
    {
        self::write('warn', $message);
    }
}
