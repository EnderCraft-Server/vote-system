<?php
declare(strict_types=1);

/** 转义输出：所有进模板的变量都走这里。 */
function e(mixed $value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** 站内链接（带 base_url，便于部署在子目录）。 */
function url(string $path = '/'): string
{
    $base = rtrim((string)\App\Bootstrap::cfg('site.base_url', ''), '/');
    return $base . '/' . ltrim($path, '/');
}

/** 静态资源链接：带版本串，避免缓存过期。 */
function asset(string $path): string
{
    $file = \App\Bootstrap::$basePath . '/public/' . ltrim($path, '/');
    $version = is_file($file) ? (string)filemtime($file) : '1';
    return url($path) . '?v=' . $version;
}

/** 文案：找不到 key 时原样返回，避免页面上出现空白。 */
function t(string $key, array $params = []): string
{
    return \App\I18n::t($key, $params);
}

/** UTF-8 字符数：mbstring 不是必需的扩展，缺了就用正则兜底。 */
function text_len(string $value): int
{
    if (function_exists('mb_strlen')) {
        return mb_strlen($value, 'UTF-8');
    }
    $count = preg_match_all('/./us', $value);
    return $count === false ? strlen($value) : (int)$count;
}
