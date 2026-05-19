(function () {
  const SUPPORTED = ['zh', 'en', 'ja'];
  const LABELS = { zh: '中文', en: 'EN', ja: '日本語' };
  let cache = {};
  let sortedEntries = [];

  /* ── 语言检测 ────────────────────────────────────────────── */
  function detectLang() {
    const stored = localStorage.getItem('acadlog_lang');
    if (stored && SUPPORTED.includes(stored)) return stored;
    const nav = (navigator.language || navigator.userLanguage || 'zh').toLowerCase();
    if (nav.startsWith('zh')) return 'zh';
    if (nav.startsWith('ja')) return 'ja';
    if (nav.startsWith('en')) return 'en';
    return 'zh';
  }

  /* ── 翻译 DOM ─────────────────────────────────────────────── */
  function translateDOM(dict) {
    // 按 key 长度倒序排列，避免短 key 先替换导致误匹配
    sortedEntries = Object.entries(dict).sort((a, b) => b[0].length - a[0].length);

    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode(node) {
          const p = node.parentElement;
          if (!p) return NodeFilter.FILTER_REJECT;
          const t = p.tagName.toLowerCase();
          if (['script', 'style', 'noscript'].includes(t)) return NodeFilter.FILTER_REJECT;
          // 跳过语言切换按钮自身
          if (p.closest('#langSwitcher')) return NodeFilter.FILTER_REJECT;
          return NodeFilter.FILTER_ACCEPT;
        }
      }
    );

    const toUpdate = [];
    let node;
    while ((node = walker.nextNode())) {
      let text = node.textContent;
      let changed = false;
      for (const [key, val] of sortedEntries) {
        if (text.includes(key)) {
          text = text.split(key).join(val);
          changed = true;
        }
      }
      if (changed) toUpdate.push([node, text]);
    }
    toUpdate.forEach(([n, t]) => { n.textContent = t; });

    // 处理 placeholder
    document.querySelectorAll('[placeholder]').forEach(el => {
      const ph = el.getAttribute('placeholder');
      for (const [key, val] of sortedEntries) {
        if (ph && ph.includes(key)) {
          el.setAttribute('placeholder', ph.split(key).join(val));
          break;
        }
      }
    });

    // 处理 title 属性（如 tooltip）
    document.querySelectorAll('[title]').forEach(el => {
      const ti = el.getAttribute('title');
      for (const [key, val] of sortedEntries) {
        if (ti && ti.includes(key)) {
          el.setAttribute('title', ti.split(key).join(val));
          break;
        }
      }
    });
  }

  /* ── 应用语言 ─────────────────────────────────────────────── */
  async function applyLang(lang, reload) {
    document.documentElement.setAttribute('lang',
      lang === 'zh' ? 'zh-CN' : lang === 'ja' ? 'ja' : 'en');
    updateSwitcherUI(lang);

    if (lang === 'zh') {
      if (reload) location.reload();
      return;
    }
    if (!cache[lang]) {
      try {
        const r = await fetch(`/static/i18n/${lang}.json?v=1`);
        cache[lang] = await r.json();
      } catch (e) { console.warn('i18n load failed', e); return; }
    }
    translateDOM(cache[lang]);
    document.body.dataset.i18nLang = lang;
  }

  /* ── 语言切换器 UI ────────────────────────────────────────── */
  function buildSwitcher() {
    const wrap = document.getElementById('langSwitcher');
    if (!wrap) return;
    const cur = detectLang();
    wrap.innerHTML = SUPPORTED.map(l =>
      `<button class="lang-btn${l === cur ? ' lang-active' : ''}" onclick="window.__setLang('${l}')">${LABELS[l]}</button>`
    ).join('');
  }

  function updateSwitcherUI(lang) {
    document.querySelectorAll('.lang-btn').forEach(btn => {
      btn.classList.toggle('lang-active', btn.textContent === LABELS[lang]);
    });
  }

  /* ── 公开接口 ─────────────────────────────────────────────── */
  window.__setLang = function (lang) {
    if (!SUPPORTED.includes(lang)) return;
    const prev = localStorage.getItem('acadlog_lang') || 'zh';
    localStorage.setItem('acadlog_lang', lang);
    // 切换到中文需要刷新（已翻译的 DOM 无法复原）
    applyLang(lang, lang === 'zh' && prev !== 'zh');
  };

  /* ── 初始化 ───────────────────────────────────────────────── */
  const initLang = detectLang();
  if (initLang !== 'zh') {
    // 尽早隐藏 body 以减少闪烁，翻译完立即显示
    document.documentElement.style.visibility = 'hidden';
    document.addEventListener('DOMContentLoaded', () => {
      buildSwitcher();
      applyLang(initLang, false).then(() => {
        document.documentElement.style.visibility = '';
      });
    });
  } else {
    document.addEventListener('DOMContentLoaded', buildSwitcher);
  }
})();
