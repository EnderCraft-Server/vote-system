<?php
/**
 * Vote 前台配置样例
 * 复制为 config.php 后修改；config.php 已在 .gitignore 中，不会进仓库。
 */
return [
    // production: 关闭错误显示、使用通用错误页；development: 显示调用栈与后台 message
    'env'   => 'production',
    'debug' => false,

    'site' => [
        'name'           => '投票系统',
        'name_en'        => 'Vote',
        'tagline'        => '匿名投票 · 一个网络一票',
        'default_locale' => 'zh-CN',   // zh-CN | en
        'support_email'  => '',
    ],

    'backend' => [
        'host'       => '127.0.0.1',
        'port'       => 7788,
        'timeout'    => 3.0,           // 单次 RPC 超时（秒）
        // 必须与 backend/config/config.yaml 的 security.rpc_secret 完全一致
        'rpc_secret' => 'CHANGE_ME_64_HEX_CHARACTERS',
    ],

    'security' => [
        // 用于签发 CSRF 令牌；每个部署独立生成，不要与 rpc_secret 复用
        'csrf_secret' => 'CHANGE_ME_ANOTHER_64_HEX',
        'csrf_ttl'    => 1800,
        // 反向代理/CDN 的网段；只有来自这些地址的请求才会采信 client_ip_header
        'trusted_proxies'  => [],
        'client_ip_header' => '',      // 例如 'CF-Connecting-IP' 或 'X-Forwarded-For'
    ],

    'captcha' => [
        'enabled' => true,
        'length'  => 6,
    ],

    'log' => [
        'path' => __DIR__ . '/../storage/logs/app.log',
    ],
];
