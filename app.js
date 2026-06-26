/* ==============================================
   인쇄소 가이드 — app.js
   (서버 불필요 / 순수 클라이언트사이드)
   ============================================== */

'use strict';

// ─────────────────────────────────────────────
// 보안 유틸리티
// ─────────────────────────────────────────────

/**
 * HTML 특수문자 이스케이프 (XSS 방지)
 * innerHTML에 삽입하는 모든 외부 문자열에 적용
 */
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#39;');
}

/**
 * CSS 인라인 속성 값 살균 (style= 주입 방지)
 * background-color 등에 사용하는 값만 허용:
 *   #RRGGBB / #RGB / rgb(...) / rgba(...) / 알려진 색상명
 * 그 외는 빈 문자열 반환
 */
const SAFE_CSS_COLOR = /^(#[0-9A-Fa-f]{3,8}|rgb\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*\)|rgba\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*[\d.]+\s*\)|[a-zA-Z]{2,30})$/;

function safeCssColor(value) {
  if (!value) return '#f0f0f0';
  const clean = String(value).trim();
  return SAFE_CSS_COLOR.test(clean) ? clean : '#f0f0f0';
}

/**
 * URL 유효성 검증 (href injection 방지)
 * http:// 또는 https:// 로 시작하는 URL만 허용
 * javascript:, data:, vbscript: 등 차단
 */
function safeUrl(url) {
  if (!url) return '';
  const str = String(url).trim();
  try {
    const parsed = new URL(str);
    if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
      return str;
    }
  } catch (_) { /* 파싱 실패 = 잘못된 URL */ }
  return '';
}

/**
 * 이모지 아이콘 필드 살균
 * 이모지(Unicode 범위)와 공백만 허용하고 HTML 태그 등은 제거
 * 소스가 신뢰된 JSON이라도 방어적으로 처리
 */
function safeIcon(value) {
  if (!value) return '';
  // HTML 태그가 있으면 escapeHtml 처리 후 반환
  const str = String(value);
  if (/<|>|&|"/.test(str)) return escapeHtml(str);
  return str;
}

/**
 * 필터 그룹 화이트리스트 검증 (prototype pollution 방지)
 * state.filters[group] = value 패턴에서 group이 임의 키가 되는 것을 차단
 */
const ALLOWED_FILTER_GROUPS = new Set(['printType', 'productType', 'feature']);

function isAllowedFilterGroup(group) {
  return ALLOWED_FILTER_GROUPS.has(group);
}

/**
 * 탭 ID 화이트리스트 검증 (DOM 조작 방지)
 * switchTab('__proto__') 등 비정상 입력 차단
 */
const ALLOWED_TABS = new Set(['curated', 'printers', 'guide', 'guide-post', 'instructions']);

function isAllowedTab(tab) {
  return ALLOWED_TABS.has(tab);
}

/**
 * index.json / printers 데이터 필드 검증
 * 예상되는 타입이 아닌 값은 안전한 기본값으로 대체
 */
function sanitizeArticleMeta(raw) {
  return {
    id:       typeof raw.id       === 'string' ? raw.id.replace(/[^a-zA-Z0-9\-_]/g, '').slice(0, 80) : '',
    category: typeof raw.category === 'string' ? raw.category.slice(0, 50)  : '',
    date:     typeof raw.date     === 'string' ? raw.date.slice(0, 30)      : '',
    icon:     typeof raw.icon     === 'string' ? raw.icon.slice(0, 20)      : '',
    bgColor:  safeCssColor(raw.bgColor),
    title:    typeof raw.title    === 'string' ? raw.title.slice(0, 200)    : '',
    excerpt:  typeof raw.excerpt  === 'string' ? raw.excerpt.slice(0, 500)  : '',
    summary:  typeof raw.summary  === 'string' ? raw.summary.slice(0, 300)  : '',
  };
}

function sanitizePrinter(raw) {
  return {
    name:     typeof raw.name     === 'string' ? raw.name.slice(0, 100)     : '',
    website:  safeUrl(raw.website),
    sns:      safeUrl(raw.sns),
    location: typeof raw.location === 'string' ? raw.location.slice(0, 100) : '',
    tags:     Array.isArray(raw.tags)
                ? raw.tags
                    .filter(t => typeof t === 'string')
                    .map(t => {
                      // normalize spacing and known variants (e.g. '옵셋인쇄' -> '옵셋 인쇄')
                      const normalized = t.trim().replace(/\s+/g, ' ').replace(/옵셋\s*인쇄/g, '옵셋 인쇄');
                      return normalized.slice(0, 50);
                    })
                    .slice(0, 20)
                : [],
  };
}

// ─────────────────────────────────────────────
// 큐레이션 카테고리 정의
// 새 항목 추가 시 이 배열만 수정하세요
// ─────────────────────────────────────────────
const CURATED_CATEGORIES = [
  { id: 'sticker',   icon: '🏷️', title: '스티커 제작',    desc: '다양한 소재·형태의 스티커 인쇄',     filterTags: ['스티커'] },
  { id: 'booklet',   icon: '📚', title: '책자·단행본',    desc: '무선·중철 제본 책자 인쇄',           filterTags: ['책자'] },
  { id: 'small-qty', icon: '🔢', title: '소량 인쇄',      desc: '1부~100부, 소량 인쇄도 OK!',     filterTags: ['디지털 인쇄'] },
  { id: 'biz-card',  icon: '💳', title: '명함 인쇄',      desc: '빠르고 저렴한 명함 제작',            filterTags: ['명함'] },
  { id: 'poster',    icon: '🖼️', title: '포스터 인쇄',    desc: '대형 포스터·배너 인쇄',              filterTags: ['포스터'] },
  { id: 'leaflet',   icon: '📄', title: '리플렛·브로셔',  desc: '홍보물, 팸플릿, 리플렛 인쇄',        filterTags: ['리플렛'] },
  { id: 'calendar',  icon: '📅', title: '달력 제작',    desc: '새해를 준비하는 달력 제작',                 filterTags: ['달력'] },
  { id: 'goods',     icon: '🎁', title: '굿즈 제작',      desc: '각종 굿즈 제작이 필요할 때',       filterTags: ['굿즈'] },
  { id: 'fast-delivery',   icon: '⚡', title: '빠른 출고',      desc: '빠른 출고 옵션이 있는 곳',      filterTags: ['빠른 출고'] },
  { id: 'foil-finishing', icon: '✨', title: '박 후가공',   desc: '금박·은박 등 박 후가공 특화 인쇄',    filterTags: ['박 후가공'] },
  { id: 'hardcover', icon: '📘', title: '양장 제본',      desc: '하드커버·고급 양장 제본 책자 제작',    filterTags: ['양장 제본'] },
  { id: 'riso',      icon: '🎨', title: '리소 인쇄',      desc: '독특한 질감의 리소그래프 인쇄',      filterTags: ['리소 인쇄'] },
  { id: 'estimate',  icon: '🧾', title: '간편 견적',      desc: '온라인에서 바로 견적 확인 가능',     filterTags: ['간편 견적'] },
  { id: 'bulk',      icon: '📦', title: '대량 인쇄',      desc: '1,000부 이상 대량 인쇄 가능',        filterTags: ['옵셋 인쇄'] },
  { id: '24hours',   icon: '⏰', title: '24시간 인쇄',      desc: '24시간 운영하는 인쇄소',        filterTags: ['24시간'] }
];

// ─────────────────────────────────────────────
// 가이드 아티클 데이터
// 아티클 추가·수정은 data/guides/ 폴더의 .md 파일을 편집하세요
// 목록 메타데이터(제목·날짜·발췌문 등)는 data/guides/index.json을 편집하세요
// ─────────────────────────────────────────────
let GUIDE_ARTICLES = [];

// ── marked.js 커스텀 렌더러 설정 ──────────────
function buildMarkedRenderer() {
  const renderer = new marked.Renderer();

  // blockquote → highlight-box
  // > 인용문 블록을 highlight-box div로 변환
  // 내부 **[color] 텍스트** 패턴 → info-tag span
  renderer.blockquote = function(token) {
    let rawText = '';
    if (token && token.tokens) {
      token.tokens.forEach(t => {
        if (t.type === 'paragraph' && t.tokens) {
          t.tokens.forEach(inner => { rawText += inner.raw || inner.text || ''; });
          rawText += '\n';
        } else {
          rawText += t.raw || t.text || '';
        }
      });
    } else {
      rawText = (typeof token === 'string') ? token : (token.text || token.raw || '');
    }

    // **[cyan] 텍스트** 패턴 → <span class="info-tag {color}">텍스트</span>
    // color는 알려진 클래스명만 허용 (XSS 방지)
    const ALLOWED_TAG_COLORS = new Set(['cyan', 'magenta', 'yellow', 'black']);
    const tagPattern = /\*\*\[(\w+)\]\s*([^*]+)\*\*/g;
    const processed  = rawText.replace(tagPattern, (_, color, text) => {
      const safeColor = ALLOWED_TAG_COLORS.has(color) ? color : 'black';
      return `<span class="info-tag ${safeColor}">${escapeHtml(text.trim())}</span>`;
    });

    const lines     = processed.split('\n').map(l => l.trim()).filter(Boolean);
    const tagLines  = lines.filter(l => l.startsWith('<span class="info-tag'));
    const textLines = lines.filter(l => !l.startsWith('<span class="info-tag'));

    let inner = '';
    if (textLines.length) inner += '<p>' + textLines.map(escapeHtml).join('<br>') + '</p>';
    if (tagLines.length)  inner += '<div class="tag-row">' + tagLines.join('') + '</div>';

    return `<div class="highlight-box">${inner}</div>\n`;
  };

  // listitem: - [x] 항목 → guide-checklist 스타일, 💡 항목 → 팁 스타일
  renderer.listitem = function(token) {
    const isTask = token && token.task;
    let body = '';
    if (token && token.tokens) {
      token.tokens.forEach(t => {
        if (t.type === 'text' && t.tokens) {
          t.tokens.forEach(inner => { body += inner.raw || inner.text || ''; });
        } else if (t.type === 'paragraph') {
          body += marked.parseInline(t.text);
        } else {
          body += marked.parseInline(t.raw || t.text || '');
        }
      });
    } else {
      body = (typeof token === 'string') ? token : (token.text || '');
    }

    if (isTask) {
      return `<li><i class="fas fa-check-circle"></i> <div>${body}</div></li>\n`;
    }
    if (/^💡/.test(body)) {
      const content = body.replace(/^💡\s*/, '');
      return `<li><i class="fas fa-lightbulb"></i> <div>${content}</div></li>\n`;
    }
    return `<li>${body}</li>\n`;
  };

  // list: task 항목 포함 여부 → guide-checklist 클래스
  renderer.list = function(token) {
    const isChecklist = token && token.items &&
      token.items.some(item => item.task);
    const cls = isChecklist ? ' class="guide-checklist"' : '';
    let body = '';
    if (token && token.items) {
      token.items.forEach(item => { body += renderer.listitem(item); });
    }
    return `<ul${cls}>${body}</ul>\n`;
  };

  return renderer;
}

// MD → HTML 변환: marked.js 파싱 후 DOMPurify로 살균
function parseMd(mdText) {
  if (typeof marked === 'undefined') return `<pre>${escapeHtml(mdText)}</pre>`;
  const renderer = buildMarkedRenderer();
  const rawHtml  = marked.parse(mdText, { renderer, breaks: true });

  // DOMPurify가 로드되어 있으면 살균, 없으면 경고 후 반환
  if (typeof DOMPurify !== 'undefined') {
    return DOMPurify.sanitize(rawHtml, {
      ALLOWED_TAGS: [
        'h1','h2','h3','h4','h5','h6',
        'p','br','hr','strong','em','del','code','pre',
        'ul','ol','li',
        'a','img',
        'div','span',
        'blockquote',
        'i',   // Font Awesome 아이콘
      ],
      ALLOWED_ATTR: ['class','href','src','alt','target','rel','style'],
      ALLOW_DATA_ATTR: false,
      FORCE_BODY: false,
      // href는 http/https만 허용
      ALLOWED_URI_REGEXP: /^(https?:\/\/|\/|#)/i,
    });
  }

  console.warn('[보안] DOMPurify가 로드되지 않았습니다. MD 콘텐츠가 살균되지 않았습니다.');
  return rawHtml;
}

// index.json 로드 → 각 .md 파일 fetch → GUIDE_ARTICLES 완성
async function loadGuides() {
  try {
    const idxRes = await fetch('data/guides/index.json');
    if (!idxRes.ok) throw new Error('index.json 로드 실패: ' + idxRes.status);

    // Content-Type 검증
    const ct = idxRes.headers.get('content-type') || '';
    if (!ct.includes('json') && !ct.includes('text')) {
      throw new Error('index.json: 예상치 않은 Content-Type: ' + ct);
    }

    const rawIndex = await idxRes.json();

    // 배열인지 확인
    if (!Array.isArray(rawIndex)) throw new Error('index.json이 배열 형식이 아닙니다.');

    // 각 항목 유효성 검증 및 살균
    const indexData = rawIndex
      .map(sanitizeArticleMeta)
      .filter(m => m.id.length > 0);  // id가 빈 항목 제거

    const articles = await Promise.all(
      indexData.map(async (meta) => {
        // id는 이미 sanitizeArticleMeta에서 [a-zA-Z0-9\-_] 만 남겼으므로 안전
        try {
          const mdRes = await fetch(`data/guides/${meta.id}.md`);
          if (!mdRes.ok) throw new Error(`${meta.id}.md 로드 실패`);
          const mdText = await mdRes.text();
          return { ...meta, content: parseMd(mdText) };
        } catch (e) {
          console.warn(`[가이드] ${meta.id}.md 로드 실패:`, e);
          return { ...meta, content: '<p>본문을 불러올 수 없습니다.</p>' };
        }
      })
    );

    GUIDE_ARTICLES = articles;
  } catch (e) {
    console.error('[인쇄소 가이드] 가이드 데이터 로드 오류:', e);
    GUIDE_ARTICLES = [];
  }
}

// ─────────────────────────────────────────────
// 앱 상태
// ─────────────────────────────────────────────
const state = {
  printers: [],
  filters: {
    printType:   'all',
    productType: 'all',
    feature:     'all',
  },
  printerSearch: '',
  printerSort:   'default',
  currentTab:    'curated',
  currentGuideId: null,
};

// ─────────────────────────────────────────────
// AdSense 초기화
// meta[name="adsense-client"]에 퍼블리셔 ID 1회 입력
// 각 광고 영역은 data-ad-slot 값만 바꾸면 됨
// ─────────────────────────────────────────────
function getAdSenseClient() {
  const meta = document.querySelector('meta[name="adsense-client"]');
  return meta ? (meta.getAttribute('content') || '').trim() : '';
}

function isPlaceholderAdValue(value) {
  return !value || /X{4,}|SLOT_ID|YOUR_|TEST/i.test(value);
}

function loadAdSenseScript(client) {
  return new Promise((resolve, reject) => {
    if (window.adsbygoogle) {
      resolve();
      return;
    }

    const existing = document.querySelector('script[data-adsense-loader="true"]');
    if (existing) {
      existing.addEventListener('load', () => resolve(), { once: true });
      existing.addEventListener('error', () => reject(new Error('AdSense 스크립트 로드 실패')), { once: true });
      return;
    }

    const script = document.createElement('script');
    script.async = true;
    script.src = `https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=${encodeURIComponent(client)}`;
    script.crossOrigin = 'anonymous';
    script.dataset.adsenseLoader = 'true';
    script.addEventListener('load', () => resolve(), { once: true });
    script.addEventListener('error', () => reject(new Error('AdSense 스크립트 로드 실패')), { once: true });
    document.head.appendChild(script);
  });
}

async function initAdSenseSlots() {
  const client = getAdSenseClient();
  const slots = Array.from(document.querySelectorAll('.adsense-slot'));

  if (!slots.length) return;
  if (isPlaceholderAdValue(client)) {
    console.info('[AdSense] meta[name="adsense-client"] 값이 아직 placeholder 상태입니다.');
    return;
  }

  const validSlots = slots.filter(slot => !isPlaceholderAdValue(slot.dataset.adSlot));
  if (!validSlots.length) {
    console.info('[AdSense] 아직 data-ad-slot 값이 입력되지 않았습니다.');
    return;
  }

  try {
    await loadAdSenseScript(client);

    validSlots.forEach(slot => {
      if (slot.dataset.adsenseReady === 'true') return;

      slot.innerHTML = `
        <ins class="adsbygoogle"
             style="display:block"
             data-ad-client="${escapeHtml(client)}"
             data-ad-slot="${escapeHtml(slot.dataset.adSlot)}"
             data-ad-format="auto"
             data-full-width-responsive="true"></ins>
      `;

      (adsbygoogle = window.adsbygoogle || []).push({});
      slot.dataset.adsenseReady = 'true';
    });
  } catch (err) {
    console.warn('[AdSense] 초기화 실패:', err);
  }
}

// ─────────────────────────────────────────────
// 초기화
// ─────────────────────────────────────────────
async function init() {
  if (typeof PRINTERS_DATA !== 'undefined') {
    // 프린터 데이터도 살균 처리
    const rawPrinters = PRINTERS_DATA.printers;
    state.printers = Array.isArray(rawPrinters)
      ? rawPrinters.map(sanitizePrinter)
      : [];
  }

  await loadGuides();
  await initAdSenseSlots();

  setupTabs();
  setupMobileMenu();
  setupHeroSearch();
  setupPrinterSearch();
  setupFilters();
  setupSort();
  setupModal();

  renderCuratedGrid();
  renderStats();
  renderFeaturedPrinters();
  renderPrinters();
  renderGuideList();
}

// ─────────────────────────────────────────────
// 탭 전환
// ─────────────────────────────────────────────
function setupTabs() {
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;
      // 탭 ID 화이트리스트 검증
      if (isAllowedTab(tab)) switchTab(tab);
    });
  });
}

function switchTab(tab) {
  if (!isAllowedTab(tab)) return;
  state.currentTab = tab;

  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  const panel = document.getElementById('tab-' + tab);
  if (panel) panel.classList.add('active');

  document.querySelectorAll('.nav-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === tab);
  });

  document.getElementById('mobileNav').classList.remove('open');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ─────────────────────────────────────────────
// 모바일 메뉴
// ─────────────────────────────────────────────
function setupMobileMenu() {
  const btn = document.getElementById('mobileMenuBtn');
  const nav = document.getElementById('mobileNav');
  btn.addEventListener('click', () => nav.classList.toggle('open'));
  document.addEventListener('click', (e) => {
    if (!btn.contains(e.target) && !nav.contains(e.target)) nav.classList.remove('open');
  });
}

// ─────────────────────────────────────────────
// 히어로 검색
// ─────────────────────────────────────────────
function setupHeroSearch() {
  const input = document.getElementById('heroSearchInput');
  const btn   = document.getElementById('heroSearchBtn');

  const doSearch = () => {
    const q = input.value.trim();
    if (!q) return;
    state.printerSearch = q;
    document.getElementById('printerSearchInput').value = q;
    document.getElementById('printerClearBtn').style.display = 'flex';
    switchTab('printers');
    setTimeout(() => renderPrinters(), 80);
  };

  btn.addEventListener('click', doSearch);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') doSearch(); });
}

// ─────────────────────────────────────────────
// 인쇄소 검색
// ─────────────────────────────────────────────
function setupPrinterSearch() {
  const input    = document.getElementById('printerSearchInput');
  const clearBtn = document.getElementById('printerClearBtn');

  input.addEventListener('input', () => {
    state.printerSearch = input.value.trim();
    clearBtn.style.display = state.printerSearch ? 'flex' : 'none';
    renderPrinters();
  });

  clearBtn.addEventListener('click', () => {
    input.value = '';
    state.printerSearch = '';
    clearBtn.style.display = 'none';
    renderPrinters();
    input.focus();
  });
}

// ─────────────────────────────────────────────
// 필터
// ─────────────────────────────────────────────
function setupFilters() {
  document.querySelectorAll('.filter-tag').forEach(tag => {
    tag.addEventListener('click', () => {
      const group = tag.dataset.group;
      const value = tag.dataset.value;

      // 필터 그룹 화이트리스트 검증 (prototype pollution 방지)
      if (!isAllowedFilterGroup(group)) return;

      state.filters[group] = value;
      document.querySelectorAll(`[data-group="${escapeHtml(group)}"]`).forEach(t => {
        t.classList.toggle('active', t.dataset.value === value);
      });
      renderPrinters();
    });
  });

  document.getElementById('resetFiltersBtn').addEventListener('click', resetFilters);
}

function resetFilters() {
  state.filters = { printType: 'all', productType: 'all', feature: 'all' };
  state.printerSearch = '';
  document.getElementById('printerSearchInput').value = '';
  document.getElementById('printerClearBtn').style.display = 'none';
  document.getElementById('printerSortSelect').value = 'default';
  state.printerSort = 'default';

  document.querySelectorAll('.filter-tag').forEach(t => {
    t.classList.toggle('active', t.dataset.value === 'all');
  });
  renderPrinters();
}

// ─────────────────────────────────────────────
// 정렬
// ─────────────────────────────────────────────
const ALLOWED_SORT_VALUES = new Set(['default', 'name', 'featured']);

function setupSort() {
  document.getElementById('printerSortSelect').addEventListener('change', (e) => {
    const val = e.target.value;
    // 정렬 값 화이트리스트 검증
    if (ALLOWED_SORT_VALUES.has(val)) {
      state.printerSort = val;
      renderPrinters();
    }
  });
}

// ─────────────────────────────────────────────
// 인쇄소 필터링 + 정렬
// ─────────────────────────────────────────────
function getFilteredPrinters() {
  let list = [...state.printers];

  if (state.printerSearch) {
    const q = state.printerSearch.toLowerCase();
    list = list.filter(p =>
      p.name.toLowerCase().includes(q) ||
      (p.location && p.location.toLowerCase().includes(q)) ||
      (p.tags && p.tags.some(t => t.toLowerCase().includes(q)))
    );
  }

  if (state.filters.printType !== 'all')
    list = list.filter(p => p.tags && p.tags.includes(state.filters.printType));
  if (state.filters.productType !== 'all')
    list = list.filter(p => p.tags && p.tags.includes(state.filters.productType));
  if (state.filters.feature !== 'all')
    list = list.filter(p => p.tags && p.tags.includes(state.filters.feature));

  if (state.printerSort === 'name') {
    list.sort((a, b) => a.name.localeCompare(b.name, 'ko'));
  } else if (state.printerSort === 'featured') {
    list.sort((a, b) => (b.name.includes('⭐') ? 1 : 0) - (a.name.includes('⭐') ? 1 : 0));
  }

  return list;
}

// ─────────────────────────────────────────────
// 큐레이션 그리드
// ─────────────────────────────────────────────
function renderCuratedGrid() {
  const grid = document.getElementById('curatedGrid');
  grid.innerHTML = '';

  CURATED_CATEGORIES.forEach(cat => {
    const count = state.printers.filter(p =>
      cat.filterTags.some(tag => p.tags && p.tags.includes(tag))
    ).length;

    const card = document.createElement('div');
    card.className = 'curated-card';
    card.setAttribute('role', 'button');
    card.setAttribute('tabindex', '0');
    // CURATED_CATEGORIES는 코드 내 상수이므로 escapeHtml 없이 textContent 사용
    card.innerHTML = `
      <div class="curated-card-icon">${safeIcon(cat.icon)}</div>
      <div class="curated-card-title">${escapeHtml(cat.title)}</div>
      <div class="curated-card-desc">${escapeHtml(cat.desc)}</div>
      <div class="curated-card-count">${escapeHtml(String(count))}곳</div>
    `;

    const goFilter = () => {
      const tag = cat.filterTags[0];
      resetFilters();

      const featureTags  = ['소량 인쇄', '대량 인쇄', '빠른 출고', '박 후가공', '양장 제본', '간편 견적'];
      const productTags  = ['책자', '리플렛', '명함', '포스터', '스티커', '달력', '굿즈', '카드 및 엽서'];
      const printTags    = ['디지털 인쇄', '옵셋 인쇄', '리소 인쇄'];

      if (featureTags.includes(tag)) {
        state.filters.feature = tag;
        document.querySelectorAll('[data-group="feature"]').forEach(t => t.classList.toggle('active', t.dataset.value === tag));
      } else if (productTags.includes(tag)) {
        state.filters.productType = tag;
        document.querySelectorAll('[data-group="productType"]').forEach(t => t.classList.toggle('active', t.dataset.value === tag));
      } else if (printTags.includes(tag)) {
        state.filters.printType = tag;
        document.querySelectorAll('[data-group="printType"]').forEach(t => t.classList.toggle('active', t.dataset.value === tag));
      }

      switchTab('printers');
      setTimeout(() => renderPrinters(), 50);
    };

    card.addEventListener('click', goFilter);
    card.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') goFilter(); });
    grid.appendChild(card);
  });
}

// ─────────────────────────────────────────────
// 통계
// ─────────────────────────────────────────────
function renderStats() {
  const featured = state.printers.filter(p => p.name.includes('⭐')).length;
  const regions  = new Set(state.printers.map(p => {
    if (!p.location) return '기타';
    const m = p.location.match(/(서울|경기|인천|부산|대구|대전|광주|울산|세종|강원|충북|충남|전북|전남|경북|경남|제주)/);
    return m ? m[1] : '기타';
  })).size;

  animateCount('statTotalPrinters', state.printers.length);
  animateCount('statFeatured', featured);
  animateCount('statRegions', regions);
  // 가이드 수를 동적으로 표시
  animateCount('statGuides', GUIDE_ARTICLES.length);

  // 가이드 목록 헤더의 텍스트도 업데이트
  const guideCountEl = document.getElementById('guideResultCount');
  if (guideCountEl) guideCountEl.textContent = `${GUIDE_ARTICLES.length}개 아티클`;
}

function animateCount(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  let current = 0;
  const step = Math.ceil(target / 30);
  const timer = setInterval(() => {
    current = Math.min(current + step, target);
    el.textContent = current;
    if (current >= target) clearInterval(timer);
  }, 38);
}

// ─────────────────────────────────────────────
// 추천 인쇄소
// ─────────────────────────────────────────────
function renderFeaturedPrinters() {
  const grid = document.getElementById('featuredGrid');
  grid.innerHTML = '';
  state.printers.filter(p => p.name.includes('⭐')).forEach(p => grid.appendChild(createPrinterCard(p)));
}

// ─────────────────────────────────────────────
// 인쇄소 목록
// ─────────────────────────────────────────────
function renderPrinters() {
  const grid    = document.getElementById('printerGrid');
  const countEl = document.getElementById('printerResultCount');
  const emptyEl = document.getElementById('printerEmptyState');
  const list    = getFilteredPrinters();

  grid.innerHTML = '';
  countEl.textContent = `전체 ${list.length}개`;
  emptyEl.style.display = list.length === 0 ? 'block' : 'none';
  list.forEach(p => grid.appendChild(createPrinterCard(p)));
}

// ─────────────────────────────────────────────
// 인쇄소 카드
// ─────────────────────────────────────────────
function createPrinterCard(printer) {
  const card = document.createElement('article');
  card.className = 'printer-card';

  const isFeatured = printer.name.includes('⭐');
  const cleanName  = printer.name.replace(/⭐️|⭐/g, '').trim();

  const tagsHTML = (printer.tags || []).slice(0, 7).map(t => {
    return `<span class="tag">${escapeHtml(t)}</span>`;
  }).join('');

  card.innerHTML = `
    <div class="printer-card-name">${isFeatured ? '⭐ ' : ''}${escapeHtml(cleanName)}</div>
    <div class="printer-card-location"><i class="fas fa-map-marker-alt"></i>${escapeHtml(printer.location || '지역 정보 없음')}</div>
    <div class="printer-card-tags">${tagsHTML}</div>
    <div class="printer-card-actions">${buildCardActions(printer)}</div>
  `;

  card.addEventListener('click', e => {
    if (e.target.closest('a')) return;
    openPrinterModal(printer);
  });

  return card;
}

function buildCardActions(p) {
  let html = '';
  // safeUrl()로 이미 검증된 값만 사용 (javascript: 등 차단)
  const website = safeUrl(p.website);
  const sns     = safeUrl(p.sns);
  if (website) html += `<a href="${escapeHtml(website)}" target="_blank" rel="noopener noreferrer" class="card-link-btn" onclick="event.stopPropagation()"><i class="fas fa-globe"></i> 홈페이지</a>`;
  if (sns)     html += `<a href="${escapeHtml(sns)}"     target="_blank" rel="noopener noreferrer" class="card-link-btn sns" onclick="event.stopPropagation()"><i class="fab fa-instagram"></i> SNS</a>`;
  return html;
}

// ─────────────────────────────────────────────
// 인쇄소 모달
// ─────────────────────────────────────────────
function openPrinterModal(printer) {
  const modal     = document.getElementById('printerModal');
  const cleanName = printer.name.replace(/⭐️|⭐/g, '').trim();
  const isFeat    = printer.name.includes('⭐');

  // textContent 사용 → XSS 불가
  document.getElementById('modalPrinterName').textContent     = (isFeat ? '⭐ ' : '') + cleanName;
  document.getElementById('modalPrinterLocation').textContent = '📍 ' + (printer.location || '지역 정보 없음');

  document.getElementById('modalPrinterTags').innerHTML =
    (printer.tags || []).map(t => `<span class="tag">${escapeHtml(t)}</span>`).join('');

  const actEl = document.getElementById('modalPrinterActions');
  actEl.innerHTML = '';

  const website = safeUrl(printer.website);
  const sns     = safeUrl(printer.sns);

  if (website) {
    const a = document.createElement('a');
    a.href = website;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.className = 'primary-link';
    // innerHTML 대신 DOM API 사용
    const icon = document.createElement('i');
    icon.className = 'fas fa-globe';
    a.appendChild(icon);
    a.appendChild(document.createTextNode(' 홈페이지 방문'));
    actEl.appendChild(a);
  }
  if (sns) {
    const a = document.createElement('a');
    a.href = sns;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    const icon = document.createElement('i');
    icon.className = 'fab fa-instagram';
    a.appendChild(icon);
    a.appendChild(document.createTextNode(' SNS 보기'));
    actEl.appendChild(a);
  }

  modal.style.display = 'flex';
  document.body.style.overflow = 'hidden';
}

function setupModal() {
  const modal = document.getElementById('printerModal');
  document.getElementById('modalClose').addEventListener('click', closeModal);
  modal.addEventListener('click', e => { if (e.target === modal) closeModal(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
}

function closeModal() {
  document.getElementById('printerModal').style.display = 'none';
  document.body.style.overflow = '';
}

// ─────────────────────────────────────────────
// 가이드 목록 렌더링
// ─────────────────────────────────────────────
function renderGuideList() {
  const list = document.getElementById('guideList');
  list.innerHTML = '';

  GUIDE_ARTICLES.forEach((article, idx) => {
    const card = document.createElement('div');
    card.className = 'guide-preview-card';
    card.setAttribute('role', 'button');
    card.setAttribute('tabindex', '0');
    card.setAttribute('aria-label', escapeHtml(article.title) + ' 읽기');

    // bgColor는 safeCssColor()로 sanitizeArticleMeta에서 이미 검증됨
    card.innerHTML = `
      <div class="guide-preview-num">${escapeHtml(String(idx + 1).padStart(2, '0'))}</div>
      <div class="guide-preview-thumb">
        <div class="guide-preview-thumb-inner" style="background:${article.bgColor};">
          ${safeIcon(article.icon)}
        </div>
      </div>
      <div class="guide-preview-body">
        <div class="guide-preview-meta">
          <span class="guide-preview-category">${escapeHtml(article.category)}</span>
          <span>${escapeHtml(article.date)}</span>
        </div>
        <div class="guide-preview-title">${escapeHtml(article.title)}</div>
        <div class="guide-preview-excerpt">${escapeHtml(article.excerpt)}</div>
        <div class="guide-preview-summary">
          <i class="fas fa-bolt"></i> ${escapeHtml(article.summary)}
        </div>
      </div>
      <i class="fas fa-chevron-right guide-preview-arrow"></i>
    `;

    const openPost = () => openGuidePost(article.id);
    card.addEventListener('click', openPost);
    card.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') openPost(); });

    list.appendChild(card);
  });
}

// ─────────────────────────────────────────────
// 가이드 세부 게시글 렌더링
// ─────────────────────────────────────────────
function openGuidePost(articleId) {
  // articleId 화이트리스트 검증: GUIDE_ARTICLES에 실제로 있는 id만 허용
  const idx = GUIDE_ARTICLES.findIndex(a => a.id === articleId);
  if (idx === -1) return;
  const article = GUIDE_ARTICLES[idx];
  state.currentGuideId = article.id; // 검증된 id 사용

  const postEl = document.getElementById('guidePostContent');

  const catColors = ['cyan', 'magenta', 'yellow', 'black', 'cyan', 'magenta'];
  const catCls    = catColors[idx % catColors.length];

  // bgColor: sanitizeArticleMeta에서 safeCssColor()로 이미 검증됨
  // article.content: parseMd()를 통해 DOMPurify로 살균됨
  // 나머지 텍스트: escapeHtml() 적용
  postEl.innerHTML = `
    <div class="guide-post-header">
      <div class="guide-post-category-row">
        <span class="guide-post-category info-tag ${catCls}">${escapeHtml(article.category)}</span>
        <span class="guide-post-date">${escapeHtml(article.date)}</span>
      </div>
      <h1 class="guide-post-title" id="guide-post-heading">${escapeHtml(article.title)}</h1>
    </div>

    <div class="guide-post-summary-box">
      <div class="guide-post-summary-label"><i class="fas fa-bolt"></i> 1초 요약</div>
      <div class="guide-post-summary-text">${escapeHtml(article.summary)}</div>
    </div>

    <div class="guide-post-hero-img" style="background:${article.bgColor};">
      ${safeIcon(article.icon)}
    </div>

    <div class="guide-post-content">
      ${article.content}
    </div>
  `;

  // 이전글 / 다음글
  const navEl = document.getElementById('guidePostNavBottom');
  const prev  = idx > 0                           ? GUIDE_ARTICLES[idx - 1] : null;
  const next  = idx < GUIDE_ARTICLES.length - 1   ? GUIDE_ARTICLES[idx + 1] : null;

  navEl.innerHTML = '';

  if (prev) {
    const btn = document.createElement('button');
    btn.className = 'guide-nav-link';
    btn.innerHTML = `
      <span class="guide-nav-label"><i class="fas fa-arrow-left"></i> 이전글</span>
      <span class="guide-nav-title">${escapeHtml(prev.title)}</span>
    `;
    btn.addEventListener('click', () => openGuidePost(prev.id));
    navEl.appendChild(btn);
  } else {
    navEl.appendChild(Object.assign(document.createElement('div'), { className: 'guide-nav-empty' }));
  }

  if (next) {
    const btn = document.createElement('button');
    btn.className = 'guide-nav-link next';
    btn.innerHTML = `
      <span class="guide-nav-label" style="justify-content:flex-end;">다음글 <i class="fas fa-arrow-right"></i></span>
      <span class="guide-nav-title">${escapeHtml(next.title)}</span>
    `;
    btn.addEventListener('click', () => openGuidePost(next.id));
    navEl.appendChild(btn);
  } else {
    navEl.appendChild(Object.assign(document.createElement('div'), { className: 'guide-nav-empty' }));
  }

  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.getElementById('tab-guide-post').classList.add('active');
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === 'guide'));

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// 뒤로가기 (가이드 목록으로)
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('guideBackBtn').addEventListener('click', () => {
    switchTab('guide');
  });
});

// ─────────────────────────────────────────────
// 로고 클릭
// ─────────────────────────────────────────────
document.getElementById('logo-home-link').addEventListener('click', e => {
  e.preventDefault();
  switchTab('curated');
  window.scrollTo({ top: 0, behavior: 'smooth' });
});

// ─────────────────────────────────────────────
// 앱 시작
// ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', init);
