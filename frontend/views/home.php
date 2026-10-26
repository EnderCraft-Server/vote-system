<?php
/** @var array<int,array<string,mixed>> $polls */
/** @var \App\Rpc\RpcException|null $error */
$statusText = static function (string $status): string {
    return match ($status) {
        'open' => t('home.status_open'),
        'closed' => t('home.status_closed'),
        default => t('home.status_draft'),
    };
};
?>
<div class="wrap">
  <header class="intro">
    <p class="eyebrow"><?= e(t('site.tagline')) ?></p>
    <h1><?= e(t('home.title')) ?></h1>
    <p class="lede"><?= e(t('home.lead')) ?></p>
  </header>

  <?php if ($error !== null): ?>
    <p class="notice notice-warn"><?= e(t('err.backend_down')) ?></p>
  <?php elseif ($polls === []): ?>
    <div class="empty">
      <p class="empty-title"><?= e(t('home.empty')) ?></p>
      <p class="muted"><?= e(t('home.empty_hint')) ?></p>
    </div>
  <?php else: ?>
    <ol class="poll-list">
      <?php foreach ($polls as $poll): ?>
        <?php
          $slug = (string)($poll['slug'] ?? '');
          $status = (string)($poll['status'] ?? 'draft');
          $canVote = !empty($poll['can_vote']);
          $endsAt = $poll['ends_at'] ?? null;
        ?>
        <li class="poll-item">
          <a class="poll-link" href="<?= e(url('/p/' . rawurlencode($slug))) ?>">
            <span class="poll-head">
              <span class="poll-title"><?= e((string)($poll['title'] ?? '')) ?></span>
              <?php if ($canVote): ?>
                <span class="stamp stamp-open"><?= e($statusText($status)) ?></span>
              <?php else: ?>
                <span class="stamp"><?= e($statusText($status)) ?></span>
              <?php endif; ?>
            </span>
            <?php if ((string)($poll['summary'] ?? '') !== ''): ?>
              <span class="poll-summary"><?= e((string)$poll['summary']) ?></span>
            <?php endif; ?>
            <span class="poll-meta">
              <span><?= e(t('home.votes', ['n' => (int)($poll['vote_count'] ?? 0)])) ?></span>
              <span aria-hidden="true">·</span>
              <span><?= e(t('home.questions', ['n' => (int)($poll['question_count'] ?? 0)])) ?></span>
              <?php if (is_string($endsAt) && $endsAt !== ''): ?>
                <span aria-hidden="true">·</span>
                <span><?= e(t('home.deadline', ['time' => date('Y-m-d H:i', strtotime($endsAt))])) ?></span>
              <?php endif; ?>
            </span>
          </a>
        </li>
      <?php endforeach; ?>
    </ol>
  <?php endif; ?>
</div>
