<?php
declare(strict_types=1);

namespace App;

final class View
{
    public static string $title = '';
    public static string $description = '';

    /**
     * 渲染视图并套用 layout。$data 里的变量在模板中直接可用。
     * @param array<string,mixed> $data
     */
    public static function render(string $template, array $data = [], int $status = 200): void
    {
        http_response_code($status);
        $data['locale'] = I18n::locale();
        $data['title'] = $data['title'] ?? self::$title;
        extract($data, EXTR_SKIP);

        ob_start();
        require Bootstrap::$basePath . '/views/' . $template . '.php';
        $content = (string)ob_get_clean();

        require Bootstrap::$basePath . '/views/layout.php';
    }

    public static function redirect(string $path, int $status = 303): never
    {
        header('Location: ' . $path, true, $status);
        exit;
    }
}
