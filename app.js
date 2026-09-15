'use strict';
(function () {
  const presets = {
    internal: { terms: 'confidential, internal use only, not for distribution, proprietary', types: 'pdf, doc, docx, xls, xlsx, ppt, pptx', hint: 'Find indexed documents with internal-use labels. A matching label alone does not establish a data exposure.' },
    directory: { terms: 'index of /, parent directory, directory listing', types: '', hint: 'Find pages that resemble directory listings. Searches cover all file types.' },
    technical: { terms: 'architecture, network diagram, deployment guide, API documentation, runbook', types: 'pdf, docx, pptx, txt', hint: 'Review indexed technical documentation for information that should not be public.' },
    financial: { terms: 'budget, forecast, purchase order, invoice, pricing proposal', types: 'pdf, xls, xlsx, docx', hint: 'Review financial and procurement documents. Some matches may be intentionally public.' },
    policies: { terms: 'information security policy, incident response plan, business continuity, data retention', types: 'pdf, doc, docx', hint: 'Review indexed policy and compliance documents for intended publication.' }
  };
  const split = value => [...new Set(value.split(/[,\n]+/).map(x => x.trim()).filter(Boolean))];
  function buildQueries(domainsText, termsText, typesText, mode) {
    const domains = [...new Set(split(domainsText).map(value => {
      let url;
      try { url = new URL(value.includes('://') ? value : 'https://' + value); }
      catch { throw new Error('Enter valid domains, such as example.com.'); }
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]+$/i.test(url.hostname)) {
        throw new Error('Enter valid domains, such as example.com.');
      }
      return url.hostname.toLowerCase();
    }))];
    if (!domains.length) throw new Error('Add at least one domain.');
    const terms = split(termsText).map(x => x.replace(/["“”]/g, '').trim()).filter(Boolean);
    const types = [...new Set(split(typesText).map(x => x.replace(/^\./, '').toLowerCase()))];
    if (types.some(x => !/^[a-z0-9]+$/.test(x))) throw new Error('File types must contain only letters and numbers, such as pdf or docx.');
    const total = mode === 'granular' ? domains.length * Math.max(1, terms.length) * Math.max(1, types.length) : domains.length;
    if (total > 500) throw new Error('This would create ' + total + ' queries. Narrow your inputs to 500 queries or fewer.');
    const group = values => values.length > 1 ? '(' + values.join(' OR ') + ')' : (values[0] || '');
    const join = parts => parts.filter(Boolean).join(' ');
    if (mode === 'granular') return domains.flatMap(d => (terms.length ? terms : ['']).flatMap(t => (types.length ? types : ['']).map(f => join(['site:' + d, f && 'filetype:' + f, t && '"' + t + '"']))));
    return domains.map(d => join(['site:' + d, group(types.map(f => 'filetype:' + f)), group(terms.map(t => '"' + t + '"'))]));
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = { buildQueries, presets };
  if (typeof document === 'undefined') return;
  const $ = id => document.getElementById(id);
  let queries = [];
  const empty = $('results').firstElementChild.cloneNode(true);
  const presetHelp = $('preset-help').textContent;
  $('preset').addEventListener('change', () => {
    const preset = presets[$('preset').value];
    if (preset) {
      $('terms').value = preset.terms; $('types').value = preset.types;
      $('preset-help').textContent = preset.hint + ' Terms and file types remain editable.';
    } else { $('preset-help').textContent = presetHelp; }
    queries = []; render(); $('error').textContent = '';
    $('status').textContent = preset ? 'Template applied. Review your domains and generate queries.' : '';
  });
  function render() {
    $('results').replaceChildren();
    $('count').textContent = queries.length + (queries.length === 1 ? ' QUERY' : ' QUERIES');
    ['copy', 'download', 'clear'].forEach(id => $(id).disabled = !queries.length);
    if (!queries.length) $('results').append(empty.cloneNode(true));
    for (const q of queries) {
      const row = document.createElement('article'); row.className = 'query';
      const code = document.createElement('code'); code.textContent = q; row.append(code);
      for (const [label, base] of [['Google ↗', 'https://www.google.com/search?q='], ['DuckDuckGo ↗', 'https://duckduckgo.com/?q=']]) {
        const a = document.createElement('a'); a.className = 'action'; a.textContent = label;
        a.href = base + encodeURIComponent(q); a.target = '_blank'; a.rel = 'noopener noreferrer';
        a.setAttribute('aria-label', label + ': ' + q); row.append(a);
      }
      $('results').append(row);
    }
  }
  $('builder').addEventListener('submit', event => {
    event.preventDefault(); $('error').textContent = ''; $('status').textContent = '';
    try {
      queries = buildQueries($('domains').value, $('terms').value, $('types').value, document.querySelector('[name=mode]:checked').value);
      render(); $('status').textContent = 'Ready. Choose a search engine beside any query.';
    } catch (error) { queries = []; render(); $('error').textContent = error.message; }
  });
  $('builder').addEventListener('input', event => {
    if (['terms', 'types'].includes(event.target.id)) { $('preset').value = ''; $('preset-help').textContent = presetHelp; }
    if (queries.length) { queries = []; render(); $('status').textContent = 'Inputs changed. Generate queries to update the preview.'; }
    $('error').textContent = '';
  });
  $('copy').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(queries.join('\n')); $('status').textContent = 'Queries copied.'; }
    catch { $('status').textContent = 'Clipboard unavailable. Use Download .txt instead.'; }
  });
  $('download').addEventListener('click', () => {
    const url = URL.createObjectURL(new Blob([queries.join('\n') + '\n'], { type: 'text/plain;charset=utf-8' }));
    const a = document.createElement('a'); a.href = url; a.download = 'dorker-queries.txt'; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000); $('status').textContent = 'Query file downloaded.';
  });
  $('clear').addEventListener('click', () => { queries = []; render(); $('status').textContent = ''; });
})();
