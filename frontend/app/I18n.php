<?php
declare(strict_types=1);

namespace App;

/** 极简 i18n：中文为主，英文作为可选项；缺词条时回退中文，再回退 key 本身。 */
final class I18n
{
    private static string $locale = 'zh-CN';
    private static array $dict = [];

    public static function init(array $config): void
    {
        $default = (string)($config['site']['default_locale'] ?? 'zh-CN');
        $locale = $default;
        $requested = $_GET['lang'] ?? null;
        if (is_string($requested) && in_array($requested, ['zh-CN', 'en'], true)) {
            $locale = $requested;
        } elseif ($requested === null && $default !== 'en') {
            $accept = strtolower((string)($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''));
            if (str_starts_with($accept, 'en')) {
                $locale = 'en';
            }
        }
        self::$locale = $locale;
        $zh = require Bootstrap::$basePath . '/app/lang/zh.php';
        $en = require Bootstrap::$basePath . '/app/lang/en.php';
        self::$dict = $locale === 'en' ? $en : $zh;
        self::$dict += $zh; // 英文缺词条时退回中文
    }

    public static function locale(): string
    {
        return self::$locale;
    }

    public static function t(string $key, array $params = []): string
    {
        $text = self::$dict[$key] ?? $key;
        foreach ($params as $name => $value) {
            $text = str_replace('{' . $name . '}', (string)$value, $text);
        }
        return $text;
    }
}
