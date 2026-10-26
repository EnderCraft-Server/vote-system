<?php
/** @var array<string,mixed> $poll */
/** @var array<string,mixed> $result */
/** @var bool $justVoted */
$total = (int)($result['total_votes'] ?? 0);
$questions = is_array($result['questions'] ?? null) ? $result['questions'] : [];
$slug = (string)($poll['slug'] ?? '');
?>
<div class="wrap">
  <article class="ballot">
    <header class="ballot-head">
      <p class="eyebrow"><?= e(t('result.eyebrow')) ?></p>
      <h1><?= e((string)($poll['title'] ?? '')) ?></h1>
      <?php if ((string)($poll['summary'] ?? '') !== ''): ?>
        <p class="lede"><?= e((string)$poll['summary']) ?></p>
      <?php endif; ?>
      <ul class="meta">
        <li><?= e(t('result.total', ['n' => $total])) ?></li>
      </ul>
      <?php if ($justVoted): ?>
        <p class="thanks"><?= e(t('result.just_voted')) ?></p>
      <?php endif; ?>
    </header>

    <?php if ($total === 0): ?>
      <div class="empty">
        <p class="empty-title"><?= e(t('result.none')) ?></p>
      </div>
    <?php endif; ?>

    <?php foreach ($questions as $index => $q): ?>
      <?php
        $type = (string)($q['type'] ?? '');
        $options = is_array($q['options'] ?? null) ? $q['options'] : [];
        $responses = (int)($q['total_responses'] ?? 0);
      ?>
      <section class="q result-q">
        <h2 class="q-title">
          <span class="q-no" aria-hidden="true"><?= (int)$index + 1 ?></span>
          <span class="q-text"><?= e((string)($q['title'] ?? '')) ?></span>
        </h2>
        <p class="q-note"><?= e(t('result.responses', ['n' => $responses])) ?></p>

        <?php if ($type === 'text'): ?>
          <p class="q-note"><?= e(t('result.text_only')) ?></p>
        <?php elseif ($type === 'rank'): ?>
          <table class="rank-table">
            <thead>
              <tr>
                <th scope="col"><?= e(t('result.option')) ?></th>
                <th scope="col" class="num"><?= e(t('result.rank_avg')) ?></th>
                <th scope="col" class="num"><?= e(t('result.rank_first')) ?></th>
              </tr>
            </thead>
            <tbody>
            <?php foreach ($options as $opt): ?>
              <tr>
                <td><?= e((string)($opt['label'] ?? '')) ?></td>
                <td class="num"><?= e(number_format((float)($opt['avg_rank'] ?? 0), 2)) ?></td>
                <td class="num"><?= (int)($opt['first_place'] ?? 0) ?></td>
              </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        <?php else: ?>
          <ul class="bars">
            <?php foreach ($options as $opt): ?>
              <?php
                $count = (int)($opt['count'] ?? 0);
                $percent = (int)round((float)($opt['percent'] ?? 0));
                $percent = max(0, min(100, $percent));
              ?>
              <li class="bar-row">
                <div class="bar-head">
                  <span class="bar-label"><?= e((string)($opt['label'] ?? '')) ?></span>
                  <span class="bar-value"><span class="num"><?= $count ?></span> · <?= $percent ?>%</span>
                </div>
                <div class="bar" role="img" aria-label="<?= e(t('result.bar_alt', ['label' => (string)($opt['label'] ?? ''), 'p' => $percent])) ?>">
                  <span class="bar-fill pct-<?= $percent ?>"></span>
                </div>
              </li>
            <?php endforeach; ?>
          </ul>
        <?php endif; ?>
      </section>
    <?php endforeach; ?>

    <p class="back"><a class="btn-quiet" href="<?= e(url('/')) ?>"><?= e(t('result.back')) ?></a></p>
  </article>
</div>
