const sourceText = new WeakMap();
const sourceAttributes = new WeakMap();
const excluded = 'script,style,textarea,pre,code,.markdown-preview,[data-i18n-ignore]';
// The first screen waits this long for a language file. The manifest is optional, so it gets
// a small part of that. Older browsers have no AbortSignal.timeout and wait as they always did.
const PACK_LIMIT_MS = 25000, MANIFEST_LIMIT_MS = 5000;
const within = ms => globalThis.AbortSignal?.timeout?.(ms);
// The failure page must still read correctly when the pack is what failed. Korean is the source.
const withoutPack = {en: {
  '화면을 불러오지 못했습니다.': 'Could not load this page.',
  '다시 시도': 'Retry',
  '서버에 연결할 수 없습니다. 연결을 확인하세요.': 'Cannot reach the server. Check the connection.',
  '서버가 응답하지 않습니다. 잠시 후 다시 시도하세요.': 'The server is not answering. Try again in a moment.',
  '서버 응답을 확인할 수 없습니다. 잠시 후 다시 시도하세요.': 'Could not read the server response. Try again in a moment.',
  '요청에 실패했습니다 ({n}).': 'Request failed ({n}).',
  '서비스 업데이트 중입니다. 완료 후 다시 시도하세요.': 'Service update in progress. Try again when it finishes.',
  '로컬 접속 링크를 확인할 수 없습니다. Start.cmd를 다시 실행하세요.': 'The local access link is invalid. Run Start.cmd again.',
}};

function storedLanguage() {
  try {
    const saved = localStorage.getItem('ctf-language');
    if (saved && /^[a-z]{2,3}(?:-[A-Z]{2})?$/.test(saved)) return saved;
  } catch { /* Local storage can be disabled. */ }
  return navigator.language?.toLowerCase().startsWith('ko') ? 'ko' : 'en';
}

class Localizer {
  constructor() {
    this.locale = storedLanguage();
    this.wanted = this.locale;
    this.messages = {};
    this.languages = [{code:'en',name:'English'},{code:'ko',name:'한국어'}];
    this.observer = null;
    this.loaded = false;
    this.starting = null;
  }

  async load(locale, signal = within(PACK_LIMIT_MS)) {
    const response = await fetch(new URL(`./${locale}.json`, import.meta.url), {cache: 'force-cache', signal});
    if (!response.ok) throw new Error(`Language pack unavailable: ${locale}`);
    const pack = await response.json();
    if (pack.locale !== locale || typeof pack.messages !== 'object') throw new Error('Invalid language pack');
    return pack.messages;
  }

  // Boot runs again on Retry. There is one page observer however often it runs, and a pack
  // that did not arrive is fetched again.
  init() {
    if (this.loaded) return Promise.resolve();
    this.starting ??= this.start().finally(() => { this.starting = null; });
    return this.starting;
  }

  async start() {
    const deadline = within(PACK_LIMIT_MS);
    try {
      const response = await fetch(new URL('./manifest.json', import.meta.url), {cache:'force-cache', signal: within(MANIFEST_LIMIT_MS)});
      const manifest = await response.json();
      if (response.ok && Array.isArray(manifest.languages) && manifest.languages.length) this.languages = manifest.languages;
    } catch { /* Keep the bundled English and Korean choices. */ }
    if (!this.languages.some(language => language.code === this.wanted)) this.locale = this.wanted = 'en';
    const wanted = this.wanted;
    let stalled = null;
    try {
      const messages = await this.load(wanted, deadline);
      // A language picked while this ran has already been loaded and must stay.
      if (wanted === this.wanted) { this.locale = wanted; this.messages = messages; this.loaded = true; }
    } catch (error) {
      if (wanted === this.wanted) {
        this.messages = withoutPack[wanted] ?? {};
        // A pack that failed leaves a working page in the source language. One that never
        // answered is a first load that failed, so the caller shows that and Retry asks again.
        if (deadline?.aborted) stalled = deadline.reason ?? error;
        else this.locale = 'ko';
      }
    }
    document.documentElement.lang = this.locale;
    this.translate(document.body);
    if (!this.observer) {
      this.observer = new MutationObserver(records => {
        for (const record of records) {
          if (record.type === 'characterData') this.translateText(record.target);
          else if (record.type === 'attributes') this.translateAttributes(record.target);
          else for (const node of record.addedNodes) this.translate(node);
        }
      });
      this.observer.observe(document.body, {
        subtree: true, childList: true, characterData: true, attributes: true,
        attributeFilter: ['title', 'aria-label', 'placeholder'],
      });
    }
    if (stalled) throw stalled;
  }

  // Language packs are plain objects, so a name such as constructor or __proto__
  // must only ever match a key the pack really defines.
  message(key) {
    return Object.hasOwn(this.messages, key) && typeof this.messages[key] === 'string' ? this.messages[key] : null;
  }

  // A key with {n} covers any count. A "one|other" value picks the plural form.
  counted(source) {
    const number = /\d+/.exec(source)?.[0];
    const template = number ? this.message(source.replace(number, '{n}')) : null;
    return template === null ? null : this.plural(template, number);
  }

  plural(template, count) {
    const forms = template.split('|');
    return forms[String(count) === '1' ? 0 : forms.length - 1].replaceAll('{n}', () => count);
  }

  // The page observer stops here. It cannot tell a label from a name, so it never
  // looks inside a longer string.
  lookup(source) {
    return this.message(source) ?? this.counted(source);
  }

  t(source) {
    if (typeof source !== 'string') return source == null ? '' : String(source);
    const found = this.lookup(source);
    if (found !== null || !source.includes(' · ')) return found ?? source;
    // " · " joins labels that translate on their own. One unknown part means the
    // text holds data such as a name, URL or size, and all of it stays as it is.
    const parts = source.split(' · ').map(part => this.lookup(part));
    return parts.includes(null) ? source : parts.join(' · ');
  }

  // Values go in after the lookup and in one pass, so they are never matched
  // against a key or expanded again. {n} also picks the plural form.
  format(source, values = {}) {
    const template = this.message(source) ?? source;
    const counted = Object.hasOwn(values, 'n') ? this.plural(template, values.n) : template;
    return counted.replace(/\{(\w+)\}/g, (hole, name) => Object.hasOwn(values, name) ? String(values[name]) : hole);
  }

  async setLocale(locale) {
    if (!this.languages.some(language => language.code === locale) || locale === this.locale) return;
    const messages = await this.load(locale);
    this.locale = this.wanted = locale;
    this.messages = messages;
    this.loaded = true;
    try { localStorage.setItem('ctf-language', locale); } catch {}
    document.documentElement.lang = locale;
    this.translate(document.body);
    document.dispatchEvent(new CustomEvent('ctf-language-changed', {detail: {locale}}));
  }

  picker() {
    const options = this.languages.map(language => `<option value="${language.code}"${this.locale === language.code ? ' selected' : ''}>${language.name}</option>`).join('');
    return `<label class="language-picker"><span class="sr-only">Language / 언어</span><select data-language-picker aria-label="Language / 언어">${options}</select></label>`;
  }

  translateText(node) {
    if (node.parentElement?.closest(excluded)) return;
    const current = node.nodeValue;
    const previous = sourceText.get(node);
    const original = previous && current === previous.output ? previous.original : current;
    const match = /^(\s*)(.*?)(\s*)$/s.exec(original);
    const output = match ? match[1] + (this.lookup(match[2]) ?? match[2]) + match[3] : original;
    sourceText.set(node, {original, output});
    if (current !== output) node.nodeValue = output;
  }

  translateAttributes(element) {
    if (!(element instanceof Element) || element.closest(excluded)) return;
    const previous = sourceAttributes.get(element) || {};
    for (const name of ['title', 'aria-label', 'placeholder']) {
      if (!element.hasAttribute(name)) continue;
      const current = element.getAttribute(name);
      const original = previous[name]?.output === current ? previous[name].original : current;
      const output = this.lookup(original) ?? original;
      previous[name] = {original, output};
      if (current !== output) element.setAttribute(name, output);
    }
    sourceAttributes.set(element, previous);
  }

  translate(root) {
    if (root.nodeType === Node.TEXT_NODE) { this.translateText(root); return; }
    if (!(root instanceof Element)) return;
    if (root.closest(excluded)) return;
    this.translateAttributes(root);
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      if (walker.currentNode.nodeType === Node.TEXT_NODE) this.translateText(walker.currentNode);
      else this.translateAttributes(walker.currentNode);
    }
  }
}

export const i18n = new Localizer();
globalThis.ctfI18n = i18n;

document.addEventListener('change', event => {
  if (event.target.matches('[data-language-picker]')) {
    i18n.setLocale(event.target.value).catch(() => { event.target.value = i18n.locale; });
  }
});
