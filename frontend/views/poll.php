<?php
/** @var array<string,mixed> $poll */
/** @var array<int,array<string,mixed>> $questions */
/** @var array<string,mixed>|null $captcha */
/** @var array<string,mixed>|null $pow */
/** @var \App\Rpc\RpcException|null $captchaError */
/** @var string $csrf */
/** @var string[] $errors */
/** @var array<string,mixed> $old */
$slug = (string)($poll['slug'] ?? '');
$answers = is_array($old['answers'] ?? null) ? $old['answers'] : [];
$endsAt = $poll['ends_at'] ?? null;
$hasVoted = !empty($poll['has_voted']);
$canVote = !empty($poll['can_vote']);
$resultsVisible = !empty($poll['results_visible']);
?>
<div class="wrap">
  <article class="ballot">
    <header class="ballot-head">
      <p class="eyebrow"><?= e(t('poll.eyebrow')) ?></p>
      <h1><?= e((string)($poll['title'] ?? '')) ?></h1>
      <?php if ((string)($poll['summary'] ?? '') !== ''): ?>
        <p class="lede"><?= e((string)$poll['summary']) ?></p>
      <?php endif; ?>
      <ul class="meta">
        <li><?= e(t('poll.questions_count', ['n' => count($questions)])) ?></li>
        <?php if (is_string($endsAt) && $endsAt !== ''): ?>
          <li><?= e(t('poll.deadline', ['time' => date('Y-m-d H:i', strtotime($endsAt))])) ?></li>
        <?php else: ?>
          <li><?= e(t('poll.no_deadline')) ?></li>
        <?php endif; ?>
      </ul>
    </header>

    <?php if ($errors !== []): ?>
      <div class="notice notice-error" role="alert" tabindex="-1" id="form-error">
        <p class="notice-title"><?= e(t('poll.error_title')) ?></p>
        <ul>
          <?php foreach (array_unique($errors) as $key): ?>
            <li><?= e(t($key)) ?></li>
          <?php endforeach; ?>
        </ul>
      </div>
    <?php endif; ?>

    <?php if ($hasVoted): ?>
      <div class="state">
        <p class="state-stamp" aria-hidden="true"><?= e(t('poll.voted_stamp')) ?></p>
        <p class="state-text"><?= e(t('poll.voted_body')) ?></p>
        <?php if ($resultsVisible): ?>
          <a class="btn" href="<?= e(url('/p/' . rawurlencode($slug) . '/result')) ?>"><?= e(t('poll.view_result')) ?></a>
        <?php endif; ?>
      </div>
    <?php elseif (!$canVote): ?>
      <div class="state">
        <p class="state-title"><?= e(t('poll.closed_title')) ?></p>
        <p class="state-text"><?= e(t('poll.closed_body')) ?></p>
        <?php if ($resultsVisible): ?>
          <a class="btn" href="<?= e(url('/p/' . rawurlencode($slug) . '/result')) ?>"><?= e(t('poll.view_result')) ?></a>
        <?php endif; ?>
      </div>
    <?php else: ?>
      <form class="vote-form" method="post" action="<?= e(url('/p/' . rawurlencode($slug) . '/submit')) ?>" novalidate>
        <input type="hidden" name="csrf" value="<?= e($csrf) ?>">

        <?php foreach ($questions as $index => $q): ?>
          <?php
            $qid = (int)($q['id'] ?? 0);
            $type = (string)($q['type'] ?? '');
            $options = is_array($q['options'] ?? null) ? $q['options'] : [];
            $selected = $answers[$qid]['choices'] ?? [];
            $textValue = (string)($answers[$qid]['text'] ?? '');
            $ranking = $answers[$qid]['ranking'] ?? [];
            $required = !empty($q['required']);
          ?>
          <section class="q" id="q-<?= $qid ?>">
            <h2 class="q-title">
              <span class="q-no" aria-hidden="true"><?= (int)$index + 1 ?></span>
              <span class="q-text"><?= e((string)($q['title'] ?? '')) ?><?php if ($required): ?><span class="q-req" aria-hidden="true">*</span><?php endif; ?></span>
              <?php if ($required): ?><span class="sr-only">（<?= e(t('poll.required')) ?>）</span><?php endif; ?>
            </h2>
            <?php if ((string)($q['hint'] ?? '') !== ''): ?>
              <p class="q-hint"><?= e((string)$q['hint']) ?></p>
            <?php endif; ?>

            <?php if ($type === 'single'): ?>
              <div class="opts">
                <?php foreach ($options as $opt): ?>
                  <?php $oid = (int)($opt['id'] ?? 0); ?>
                  <label class="opt">
                    <input type="radio" name="q<?= $qid ?>" value="<?= $oid ?>" <?= in_array($oid, $selected, true) ? 'checked' : '' ?>>
                    <span class="opt-label"><?= e((string)($opt['label'] ?? '')) ?></span>
                  </label>
                <?php endforeach; ?>
              </div>
            <?php elseif ($type === 'multiple'): ?>
              <?php
                $min = (int)($q['min_choices'] ?? 0);
                $max = (int)($q['max_choices'] ?? 0);
                $hintParts = [];
                if ($min > 0) { $hintParts[] = t('poll.at_least', ['n' => $min]); }
                if ($max > 0) { $hintParts[] = t('poll.at_most', ['n' => $max]); }
              ?>
              <?php if ($hintParts !== []): ?>
                <p class="q-note"><?= e(implode(' · ', $hintParts)) ?></p>
              <?php endif; ?>
              <div class="opts">
                <?php foreach ($options as $opt): ?>
                  <?php $oid = (int)($opt['id'] ?? 0); ?>
                  <label class="opt">
                    <input type="checkbox" name="q<?= $qid ?>[]" value="<?= $oid ?>" <?= in_array($oid, $selected, true) ? 'checked' : '' ?>>
                    <span class="opt-label"><?= e((string)($opt['label'] ?? '')) ?></span>
                  </label>
                <?php endforeach; ?>
              </div>
            <?php elseif ($type === 'text'): ?>
              <?php $maxLen = (int)($q['max_length'] ?? 300); ?>
              <textarea class="text-answer" name="q<?= $qid ?>" rows="4" maxlength="<?= $maxLen ?>"
                        data-counter="count-<?= $qid ?>"
                        placeholder="<?= e(t('poll.text_placeholder')) ?>"><?= e($textValue) ?></textarea>
              <p class="q-note" id="count-<?= $qid ?>"><?= e(t('poll.char_count', ['n' => text_len($textValue), 'max' => $maxLen])) ?></p>
            <?php elseif ($type === 'rank'): ?>
              <p class="q-note"><?= e(t('poll.rank_hint')) ?></p>
              <?php
                // $labels 是完整映射，$rest 只当"还没排过"的集合。
                // 以前直接在 $byId 上 unset，重填一次所有已排序条目的名称就没了。
                $labels = [];
                foreach ($options as $opt) { $labels[(int)$opt['id']] = (string)$opt['label']; }
                $rest = $labels;
                $ordered = [];
                foreach ($ranking as $oid) {
                    if (isset($rest[$oid])) { $ordered[] = $oid; unset($rest[$oid]); }
                }
                foreach ($rest as $oid => $label) { $ordered[] = $oid; }
              ?>
              <ol class="rank" data-rank>
                <?php foreach ($ordered as $pos => $oid): ?>
                  <li class="rank-item" data-id="<?= (int)$oid ?>">
                    <span class="rank-pos" aria-hidden="true"><?= $pos + 1 ?></span>
                    <span class="rank-label"><?= e($labels[$oid] ?? '') ?></span>
                    <span class="rank-actions">
                      <button type="button" class="btn-icon" data-move="-1" aria-label="<?= e(t('poll.rank_up')) ?>">↑</button>
                      <button type="button" class="btn-icon" data-move="1" aria-label="<?= e(t('poll.rank_down')) ?>">↓</button>
                    </span>
                    <input type="hidden" name="q<?= $qid ?>_rank[]" value="<?= (int)$oid ?>">
                  </li>
                <?php endforeach; ?>
              </ol>
              <p class="sr-only" aria-live="polite" data-rank-live></p>
            <?php endif; ?>
          </section>
        <?php endforeach; ?>

        <?php if ($pow !== null): ?>
          <section class="pow"
         data-pow="<?= e(json_encode($pow, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?>"
         data-pow-worker="<?= e(asset('assets/pow-worker.js')) ?>">
            <h2 class="captcha-title"><?= e(t('pow.title')) ?></h2>
            <p class="q-note pow-status" data-pow-status aria-live="polite"><?= e(t('pow.pending')) ?></p>
            <p class="q-note"><?= e(t('pow.hint')) ?></p>
            <input type="hidden" name="pow_solution" value="">
          </section>
        <?php endif; ?>

        <section class="captcha" aria-labelledby="captcha-label">
          <h2 class="captcha-title" id="captcha-label"><?= e(t('poll.captcha')) ?></h2>
          <?php if ($captcha !== null): ?>
            <div class="captcha-row">
              <img class="captcha-img" src="<?= e(url('/captcha/' . rawurlencode((string)$captcha['id']) . '.png')) ?>"
                   width="320" height="100" alt="<?= e(t('poll.captcha_alt')) ?>">
              <a class="btn-quiet" href="<?= e(url('/p/' . rawurlencode($slug))) ?>"><?= e(t('poll.captcha_refresh')) ?></a>
            </div>
            <input type="hidden" name="captcha_id" value="<?= e((string)$captcha['id']) ?>">
            <label class="field">
              <span class="field-label"><?= e(t('poll.captcha_answer')) ?></span>
              <input class="captcha-answer" name="captcha_answer" inputmode="numeric" autocomplete="off"
                     pattern="[0-9]*" maxlength="8" required
                     value="<?= e((string)($old['captcha_answer'] ?? '')) ?>">
            </label>
            <p class="q-note"><?= e(t('poll.captcha_hint')) ?></p>
          <?php else: ?>
            <p class="notice notice-error"><?= e(t('poll.captcha_failed')) ?></p>
          <?php endif; ?>
        </section>

        <noscript>
          <p class="notice notice-error">本投票需要 JavaScript 完成人机校验（工作量证明）。请开启 JavaScript 后刷新页面，或换一个较新的浏览器。</p>
        </noscript>

        <div class="actionbar">
          <div class="actionbar-inner">
            <p class="actionbar-note"><?= e(t('poll.submit_note')) ?></p>
            <button class="btn btn-primary" type="submit" <?= $pow !== null ? 'disabled' : '' ?>><?= e(t('poll.submit')) ?></button>
          </div>
        </div>
      </form>
    <?php endif; ?>
  </article>
</div>
