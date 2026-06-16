/* ── Copy buttons ─────────────────────────────────────────── */
document.querySelectorAll('.copy-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const pre = btn.closest('.code-block').querySelector('pre');
    const text = pre.innerText;
    navigator.clipboard.writeText(text).then(() => {
      btn.textContent = 'Copied!';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.textContent = 'Copy';
        btn.classList.remove('copied');
      }, 1800);
    }).catch(() => {
      // fallback for older browsers
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      btn.textContent = 'Copied!';
      setTimeout(() => btn.textContent = 'Copy', 1800);
    });
  });
});

/* ── KQL syntax highlighting ──────────────────────────────── */
function highlightKQL(codeEl) {
  let html = codeEl.textContent
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  // Line comments first (before keyword pass touches them)
  html = html.replace(/(\/\/[^\n]*)/g, '<span class="kql-comment">$1</span>');

  // String literals
  html = html.replace(/("(?:[^"\\]|\\.)*")/g, '<span class="kql-string">$1</span>');

  // Keywords (only outside already-wrapped spans)
  const kw = [
    'where','project','summarize','extend','join','on','let','by',
    'count','ago','bin','order','sort','top','limit','mv-expand',
    'parse','evaluate','distinct','union','in','has','has_any',
    'has_cs','contains','startswith','endswith','matches',
    'and','or','not','if','iff','between','kind','inner','outer',
    'left','right','dcount','make_set','make_list','tostring',
    'todynamic','isnotempty','isempty','array_length','iif',
    'tolower','toupper','split','trim','strcat','format_datetime',
    'datetime','timespan','now','ago','range','print',
  ];
  const kwPattern = new RegExp(`(?<!<[^>]*)\\b(${kw.join('|')})\\b(?![^<]*>)`, 'g');
  html = html.replace(kwPattern, '<span class="kql-keyword">$1</span>');

  // Table names (capitalized identifiers at start of line or after |)
  html = html.replace(/((?:^|\|\s*)([A-Z][A-Za-z]+))/gm, (m, full, name) => {
    return full.replace(name, `<span class="kql-table">${name}</span>`);
  });

  codeEl.innerHTML = html;
}

document.querySelectorAll('.code-block[data-lang="kql"] code').forEach(highlightKQL);

/* ── Sidebar active section (IntersectionObserver) ───────── */
const tocLinks = document.querySelectorAll('.toc-list a[href^="#"]');
const sections = document.querySelectorAll('.attack-section[id]');

if (sections.length && tocLinks.length) {
  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        tocLinks.forEach(link => {
          link.classList.remove('active');
          if (link.getAttribute('href') === '#' + entry.target.id) {
            link.classList.add('active');
          }
        });
      }
    });
  }, {
    rootMargin: `-${60 + 20}px 0px -55% 0px`,
    threshold: 0,
  });

  sections.forEach(s => observer.observe(s));
}

/* ── Search (index page) ──────────────────────────────────── */
const searchInput = document.getElementById('attack-search');
if (searchInput) {
  const wrappers = document.querySelectorAll('[data-searchable]');

  searchInput.addEventListener('input', () => {
    const q = searchInput.value.toLowerCase().trim();
    wrappers.forEach(el => {
      const text = (el.dataset.searchable || el.textContent).toLowerCase();
      el.style.display = (!q || text.includes(q)) ? '' : 'none';
    });
  });
}

/* ── Filter chips (index page) ───────────────────────────── */
document.querySelectorAll('.chip[data-filter]').forEach(chip => {
  chip.addEventListener('click', () => {
    document.querySelectorAll('.chip[data-filter]').forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
    const filter = chip.dataset.filter;
    document.querySelectorAll('[data-categories]').forEach(el => {
      const cats = el.dataset.categories || '';
      el.style.display = (filter === 'all' || cats.includes(filter)) ? '' : 'none';
    });
    // re-run search if there's a query active
    if (searchInput && searchInput.value.trim()) {
      searchInput.dispatchEvent(new Event('input'));
    }
  });
});
