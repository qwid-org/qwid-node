// The contact address is assembled here rather than written into the markup,
// so it never appears as a literal mailto: in the served HTML. This defeats
// the crawlers that harvest addresses with a regex over page source, which is
// most of them; it does not defeat a harvester that executes JavaScript, and
// nothing short of dropping the address entirely would. Without scripting the
// <noscript> fallback still shows a human-readable form, which matters because
// a privacy notice has to leave a usable channel for data-subject requests.
document.querySelectorAll('span.mail').forEach(function (el) {
  var addr = el.dataset.u + String.fromCharCode(64) + el.dataset.d;
  var a = document.createElement('a');
  a.href = 'mailto:' + addr;
  a.textContent = addr;
  el.textContent = '';
  el.appendChild(a);
});
