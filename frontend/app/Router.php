<?php
declare(strict_types=1);

namespace App;

/** 极简路由：只支持固定路径与 {name} 占位符。 */
final class Router
{
    /** @var array<int, array{method:string, regex:string, params:array<int,string>, handler:array{0:class-string,1:string}}> */
    private array $routes = [];

    public function get(string $pattern, array $handler): void
    {
        $this->add('GET', $pattern, $handler);
    }

    public function post(string $pattern, array $handler): void
    {
        $this->add('POST', $pattern, $handler);
    }

    private function add(string $method, string $pattern, array $handler): void
    {
        $params = [];
        $regex = preg_replace_callback('/\\{([a-zA-Z_][a-zA-Z0-9_]*)\\}/', static function (array $m) use (&$params): string {
            $params[] = $m[1];
            return '([A-Za-z0-9_\\.-]+)';
        }, $pattern);
        $this->routes[] = [
            'method' => $method,
            'regex' => '#^' . $regex . '$#',
            'params' => $params,
            'handler' => $handler,
        ];
    }

    /** @return array{0: array{0:class-string,1:string}, 1: array<string,string>}|null */
    public function match(string $method, string $path): ?array
    {
        foreach ($this->routes as $route) {
            if ($route['method'] !== $method) {
                continue;
            }
            if (preg_match($route['regex'], $path, $m) === 1) {
                $args = [];
                foreach ($route['params'] as $i => $name) {
                    $args[$name] = $m[$i + 1];
                }
                return [$route['handler'], $args];
            }
        }
        return null;
    }
}
