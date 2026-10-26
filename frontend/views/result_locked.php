<?php /** @var string $title */ ?>
<div class="wrap">
  <article class="ballot ballot-narrow">
    <header class="ballot-head">
      <p class="eyebrow"><?= e(t('result.eyebrow')) ?></p>
      <h1><?= e($title) ?></h1>
      <p class="lede"><?= e(t('result.locked_body')) ?></p>
    </header>
    <p class="back"><a class="btn" href="<?= e(url('/')) ?>"><?= e(t('result.back')) ?></a></p>
  </article>
</div>
