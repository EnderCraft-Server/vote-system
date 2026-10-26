<?php
/** @var int $code */
/** @var string $messageKey */
?>
<div class="wrap">
  <article class="ballot ballot-narrow">
    <header class="ballot-head">
      <p class="eyebrow"><?= e((string)$code) ?></p>
      <h1><?= e($title) ?></h1>
      <p class="lede"><?= e(t($messageKey)) ?></p>
    </header>
    <p class="back"><a class="btn" href="<?= e(url('/')) ?>"><?= e(t('err.back_home')) ?></a></p>
  </article>
</div>
