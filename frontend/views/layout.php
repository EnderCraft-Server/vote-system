<?php
/** @var string $content */
/** @var string $title */
/** @var string $locale */
$siteName = (string)\App\Bootstrap::cfg('site.name', '投票系统');
$otherLocale = $locale === 'en' ? 'zh-CN' : 'en';
?>
<!doctype html>
<html lang="<?= e($locale) ?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= e($title !== '' ? $title . ' · ' . $siteName : $siteName) ?></title>
<meta name="description" content="<?= e($siteName . ' · ' . t('site.tagline')) ?>">
<meta name="color-scheme" content="light dark">
<link rel="icon" href="<?= e(url('/favicon.svg')) ?>" type="image/svg+xml">
<link rel="stylesheet" href="<?= e(asset('assets/app.css')) ?>">
</head>
<body>
<a class="skip-link" href="#main"><?= e(t('skip.link')) ?></a>

<header class="topbar">
  <div class="topbar-inner">
    <a class="brand" href="<?= e(url('/')) ?>">
      <span class="brand-name"><?= e($siteName) ?></span>
      <span class="brand-en" aria-hidden="true">VOTE</span>
    </a>
    <nav class="nav" aria-label="<?= e(t('nav.label')) ?>">
      <a href="<?= e(url('/')) ?>"><?= e(t('nav.votes')) ?></a>
      <a class="lang" href="?lang=<?= e($otherLocale) ?>" hreflang="<?= e($otherLocale) ?>"><?= e(t('nav.lang_switch')) ?></a>
    </nav>
  </div>
</header>

<main id="main">
<?= $content ?>
</main>

<footer class="foot">
  <div class="foot-inner">
    <p><?= e(t('foot.note')) ?></p>
    <p class="foot-meta"><?= e(t('foot.privacy')) ?></p>
  </div>
</footer>

<script src="<?= e(asset('assets/app.js')) ?>" defer></script>
</body>
</html>
