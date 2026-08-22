fetch('QWID_COMPLETE_SECURITY_AUDIT.md')
  .then(r => {
    if (!r.ok) throw new Error('Failed to load');
    return r.text();
  })
  .then(md => {
    // Strip everything before the first ## heading (H1 + front matter + first ---)
    const firstH2 = md.indexOf('\n## ');
    const cleaned = (firstH2 >= 0 ? md.slice(firstH2 + 1) : md).trim();
    const html = (typeof marked.parse === 'function')
      ? marked.parse(cleaned, {breaks: true, gfm: true})
      : marked(cleaned);
    document.getElementById('content').innerHTML = html;
    // Colorize ✅ ❌ ⚠️ in table cells and list items
    document.querySelectorAll('#content td, #content li, #content p').forEach(el => {
      el.innerHTML = el.innerHTML
        .replace(/✅/g, '<span style="color:#2ed573">✅</span>')
        .replace(/❌/g, '<span style="color:#ff4757">❌</span>')
        .replace(/⚠️/g, '<span style="color:#f0b429">⚠️</span>');
    });
  })
  .catch(() => {
    document.getElementById('content').innerHTML =
      '<div class="state-msg">Could not load audit report.</div>';
  });
