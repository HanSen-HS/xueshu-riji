(function () {
  const PHASES = { work: 25 * 60, short_break: 5 * 60, long_break: 15 * 60 };
  const KEY = 'acadlog_pomodoro';
  let _tick = null;

  function load() {
    try { return JSON.parse(localStorage.getItem(KEY)); } catch { return null; }
  }
  function save(s) { localStorage.setItem(KEY, JSON.stringify(s)); }
  function fresh() {
    return { running: false, phase: 'work', count: 0, remaining: PHASES.work, startedAt: null };
  }

  function getRem(s) {
    if (!s.running || !s.startedAt) return s.remaining;
    return Math.max(0, s.remaining - (Date.now() - s.startedAt) / 1000);
  }

  function fmt(sec) {
    sec = Math.ceil(sec);
    return String(Math.floor(sec / 60)).padStart(2, '0') + ':' + String(sec % 60).padStart(2, '0');
  }

  function phaseInfo(s) {
    if (s.phase === 'work')        return { label: `🍅 第 ${s.count + 1} 个番茄 · 25min`, col: '#e53935' };
    if (s.phase === 'short_break') return { label: '☕ 短休息 · 5min',  col: '#00897B' };
    return                                { label: '🌿 长休息 · 15min', col: '#3949AB' };
  }

  function bell() {
    try {
      const ctx = new AudioContext();
      [880, 660, 880].forEach((f, i) => {
        const o = ctx.createOscillator(), g = ctx.createGain();
        o.connect(g); g.connect(ctx.destination);
        o.frequency.value = f;
        g.gain.setValueAtTime(0.18, ctx.currentTime + i * 0.32);
        g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + i * 0.32 + 0.28);
        o.start(ctx.currentTime + i * 0.32);
        o.stop(ctx.currentTime + i * 0.32 + 0.3);
      });
    } catch {}
  }

  function advance(s) {
    bell();
    if (s.phase === 'work') {
      s.count += 1;
      s.phase = s.count % 4 === 0 ? 'long_break' : 'short_break';
    } else {
      s.phase = 'work';
    }
    s.remaining = PHASES[s.phase];
    s.running = false;
    s.startedAt = null;
    return s;
  }

  function startTick() {
    if (_tick) return;
    _tick = setInterval(() => {
      let s = load() || fresh();
      if (!s.running) { clearInterval(_tick); _tick = null; render(); return; }
      if (getRem(s) <= 0) {
        s = advance(s);
        save(s);
        clearInterval(_tick); _tick = null;
      }
      render();
    }, 500);
  }

  /* ── Public API ─────────────────────────────────────────────── */
  window.__pomodoroAutoStart = function () {
    const s = load();
    if (!s || !s.running) window.__pomodoroStart();
  };

  window.__pomodoroStart = function () {
    let s = load() || fresh();
    if (s.running) return;
    s.running = true;
    s.startedAt = Date.now();
    save(s);
    startTick();
    render();
  };

  window.__pomodoroPause = function () {
    let s = load() || fresh();
    if (s.running) {
      s.remaining = getRem(s);
      s.running = false;
      s.startedAt = null;
      clearInterval(_tick); _tick = null;
    } else {
      s.running = true;
      s.startedAt = Date.now();
      startTick();
    }
    save(s);
    render();
  };

  window.__pomodoroReset = function () {
    save(fresh());
    clearInterval(_tick); _tick = null;
    render();
  };

  /* ── Render ─────────────────────────────────────────────────── */
  function render() {
    const w = document.getElementById('pomodoroWidget');
    if (!w) return;
    const s = load() || fresh();
    const rem = getRem(s);
    const info = phaseInfo(s);

    w.querySelector('.pomo-time').textContent = fmt(rem);
    w.querySelector('.pomo-time').style.color = info.col;
    w.querySelector('.pomo-label').textContent = info.label;
    w.querySelector('.pomo-dot').style.background = s.running ? info.col : '#bdbdbd';
    w.querySelector('.pomo-pause').textContent = s.running ? '⏸' : '▶';

    // progress ring
    const circle = w.querySelector('.pomo-ring-fill');
    if (circle) {
      const total = PHASES[s.phase];
      const pct = rem / total;
      const r = 20, circ = 2 * Math.PI * r;
      circle.style.strokeDashoffset = circ * (1 - pct);
      circle.style.stroke = info.col;
    }
  }

  /* ── Init ───────────────────────────────────────────────────── */
  document.addEventListener('DOMContentLoaded', () => {
    render();
    const s = load();
    if (s && s.running) startTick();
    if (typeof Notification !== 'undefined' && Notification.permission === 'default') {
      Notification.requestPermission();
    }
  });
})();
