/**
 * 界面语言（中文 / English）。
 *
 * 文案的真源是**中文原文**：源码里写 tr`中文…`，英文表在 i18n-en-*.js。
 * key = 标签模板的各段用 \u0000 连起来（带插值的整句也能翻）；
 * 静态页面的文案用 data-i18n / data-i18n-html / data-i18n-title 标，key 就是属性值。
 *
 * 语言怎么定：先看用户手动选过的那次（localStorage），没有就跟随浏览器偏好
 * （zh 开头 → 中文，其余 → 英文）。右上角的菜单可以覆盖，覆盖结果会记住。
 *
 * 这个模块在 Node 里也能 import（跑测试用）：没有 document/navigator 时默认中文、不碰 DOM，
 * 所以中文输出与改造前逐字一致。
 */

import { EN_SHELL } from './i18n-en-shell.js';
import { EN_UI } from './i18n-en-ui.js';

const SEP = '\u0000';
const STORE_KEY = 'pmca-lang';
const EVENT = 'pmca-i18n-change';

const DICT = Object.assign({}, EN_SHELL, EN_UI);

let lang = detectLang();

function detectLang() {
  const saved = readSaved();
  if (saved) return saved;
  const nav = typeof navigator === 'undefined' ? null : navigator;
  const list = nav ? [].concat(nav.languages || [], nav.language || []) : [];
  for (const l of list) {
    if (typeof l !== 'string') continue;
    if (/^zh\b/i.test(l)) return 'zh';
    if (/^en\b/i.test(l)) return 'en';
  }
  return list.length ? 'en' : 'zh'; // 浏览器里的别的语种 → 英文；Node（没 navigator）→ 中文
}

function readSaved() {
  try {
    const v = typeof localStorage === 'undefined' ? null : localStorage.getItem(STORE_KEY);
    return v === 'zh' || v === 'en' ? v : null;
  } catch (e) {
    return null; // 隐私模式 / 禁用存储：当没选过
  }
}

function save(v) {
  try {
    if (typeof localStorage !== 'undefined') localStorage.setItem(STORE_KEY, v);
  } catch (e) {
    /* 存不了就算了，只影响下次是否记住 */
  }
}

export function getLang() {
  return lang;
}

export function setLang(next) {
  if (next !== 'zh' && next !== 'en') return;
  const changed = next !== lang;
  lang = next;
  save(next);
  if (typeof document !== 'undefined') {
    document.documentElement.setAttribute('lang', next === 'zh' ? 'zh-CN' : 'en');
    applyDom();
  }
  if (changed && typeof window !== 'undefined') {
    // 用事件广播：打包版（app.min.js）与源码版同时在场时，各自有一份模块副本，
    // 靠这条事件把它们语言对齐，不然切换后一半文案不会变。
    window.dispatchEvent(new CustomEvent(EVENT, { detail: { lang: next } }));
  }
}

/** 订阅语言变化（各模块副本都靠它跟上）。 */
export function onLangChange(cb) {
  if (typeof window === 'undefined') return;
  window.addEventListener(EVENT, (e) => {
    lang = e.detail.lang;
    applyDom();
    cb(lang);
  });
}

/**
 * 翻译标签模板：tr`已选择 apk：${file.name}（${n} 个条目）`。
 * 英文表里没有这条就原样返回中文 —— 漏翻只会「还是中文」，不会报错。
 * 也支持 tr('整句') 这种不用插值的写法。
 */
export function tr(strings, ...values) {
  if (typeof strings === 'string') {
    const hit = lang === 'en' ? DICT[strings] : undefined;
    return hit !== undefined ? hit : strings;
  }
  const parts = strings;
  if (lang === 'en') {
    const hit = DICT[parts.join(SEP)];
    if (hit !== undefined) return fill(hit.split(SEP), values);
  }
  return fill(parts, values);
}

function fill(parts, values) {
  let out = '';
  for (let i = 0; i < parts.length; i++) {
    out += parts[i];
    if (i < values.length) out += show(values[i]);
  }
  return out;
}

function show(v) {
  if (v == null) return '?';
  if (v instanceof Error) return v.message;
  return String(v);
}

/** 静态文案：把带 data-i18n* 的元素换成当前语言，中文原文第一次见到时留档。 */
const originals = new Map();

export function applyDom(root) {
  if (typeof document === 'undefined') return;
  const scope = root || document;
  if (!scope.querySelectorAll) return;
  const nodes = scope.querySelectorAll('[data-i18n],[data-i18n-html],[data-i18n-title]');
  for (const el of nodes) {
    applyOne(el, 'data-i18n', (v) => (el.textContent = v), () => el.textContent);
    applyOne(el, 'data-i18n-html', (v) => (el.innerHTML = v), () => el.innerHTML);
    applyOne(el, 'data-i18n-title', (v) => el.setAttribute('title', v), () => el.getAttribute('title'));
  }
}

function applyOne(el, attr, set, get) {
  const key = el.getAttribute(attr);
  if (!key) return;
  let cache = originals.get(el);
  if (!cache) originals.set(el, (cache = {}));
  if (!(attr in cache)) cache[attr] = get();
  const text = lang === 'en' && DICT[key] !== undefined ? DICT[key] : cache[attr];
  if (text != null) set(text);
}

/** 页面启动时调用：先换静态文案，再接右上角的语言菜单。重复调用无副作用。 */
let booted = false;

export function boot() {
  if (typeof document === 'undefined') return;
  document.documentElement.setAttribute('lang', lang === 'zh' ? 'zh-CN' : 'en');
  applyDom();
  if (booted) return;
  booted = true;
  const sel = document.getElementById('lang-select');
  if (sel) {
    sel.value = lang;
    sel.addEventListener('change', () => setLang(sel.value));
  }
  onLangChange(() => {
    const s = document.getElementById('lang-select');
    if (s) s.value = getLang();
  });
}
