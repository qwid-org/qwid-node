// Behaviour for the qwid.org landing page.
//
// Extracted from two inline <script> blocks in index.html so that the
// Content-Security-Policy in deploy/security-headers-landing.conf can name
// script-src 'self' without 'unsafe-inline'. Order is preserved: the contact
// form handler came first, the stats/nav block second.

(function(){
  const form = document.getElementById('contactForm');
  const status = document.getElementById('cfStatus');
  if(!form) return;
  form.addEventListener('submit', async function(e){
    e.preventDefault();
    const btn = form.querySelector('.cf-submit');
    btn.disabled = true;
    btn.textContent = 'Sending…';
    status.style.display = 'none';
    const data = {
      name:    document.getElementById('cfName').value.trim(),
      email:   document.getElementById('cfEmail').value.trim(),
      subject: document.getElementById('cfSubject').value.trim(),
      message: document.getElementById('cfMessage').value.trim(),
    };
    try {
      const res = await fetch(API_BASE+'/api/contact', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(data),
        signal: AbortSignal.timeout(10000),
      });
      const json = await res.json();
      if(res.ok && json.success){
        status.className = 'cf-status ok';
        status.textContent = 'Message sent! We will get back to you soon.';
        form.reset();
      } else {
        status.className = 'cf-status err';
        status.textContent = json.error || 'Failed to send message.';
      }
    } catch(err){
      status.className = 'cf-status err';
      status.textContent = 'Network error — please try again.';
    }
    status.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Send Message';
  });
})();

// ===================== CANVAS QUANTUM PARTICLE NETWORK =====================
(function(){
  const canvas = document.getElementById('qCanvas');
  const ctx = canvas.getContext('2d');
  const S = 38; // hex size
  let W, H, hexes = [];
  let mouse = {x:-9999, y:-9999, active:false};
  let t = 0, lastPulse = 0;

  function buildGrid(){
    hexes = [];
    const colW = S * 1.5;
    const rowH = S * Math.sqrt(3);
    const cols = Math.ceil(W / colW) + 3;
    const rows = Math.ceil(H / rowH) + 3;
    for(let c = -1; c < cols; c++){
      for(let r = -1; r < rows; r++){
        const x = c * colW;
        const y = r * rowH + (c & 1 ? rowH * 0.5 : 0);
        hexes.push({x, y, e:Math.random()*0.2, phase:Math.random()*Math.PI*2, spd:0.006+Math.random()*0.01, nb:[]});
      }
    }
    // Precompute neighbours
    const thresh = S * 2.1;
    for(let i = 0; i < hexes.length; i++){
      for(let j = i+1; j < hexes.length; j++){
        const dx = hexes[i].x-hexes[j].x, dy = hexes[i].y-hexes[j].y;
        if(dx*dx+dy*dy < thresh*thresh){
          hexes[i].nb.push(j);
          hexes[j].nb.push(i);
        }
      }
    }
  }

  function hexPath(x, y, r){
    ctx.beginPath();
    for(let i=0;i<6;i++){
      const a = Math.PI/3*i;
      const px = x + r*Math.cos(a), py = y + r*Math.sin(a);
      i===0 ? ctx.moveTo(px,py) : ctx.lineTo(px,py);
    }
    ctx.closePath();
  }

  function draw(){
    t += 0.016;
    ctx.clearRect(0, 0, W, H);

    // Periodic lattice pulse (simulates new block)
    if(t - lastPulse > 0.8 + Math.random()*0.4){
      lastPulse = t;
      const h = hexes[Math.floor(Math.random()*hexes.length)];
      if(h){ h.e = 1.0; h.gold = 1.0; }
    }

    // Mouse excitation
    if(mouse.active){
      for(let i=0;i<hexes.length;i++){
        const h = hexes[i];
        const dx = h.x-mouse.x, dy = h.y-mouse.y;
        const d2 = dx*dx+dy*dy;
        if(d2 < 14400){ // 120px radius
          h.e = Math.min(1, h.e + (1 - Math.sqrt(d2)/120)*0.06);
        }
      }
    }

    // Update energy — each hex is independent, no propagation
    for(let i=0;i<hexes.length;i++){
      const h = hexes[i];
      h.e = Math.max(0, h.e * 0.97);
      h.phase += h.spd + h.e * 0.02;
      if(h.gold) h.gold = Math.max(0, h.gold - 0.018);
    }

    // Draw hexes
    for(let i=0;i<hexes.length;i++){
      const h = hexes[i];
      const pulse = (Math.sin(h.phase) + 1) * 0.5;
      const e = h.e;
      const g = h.gold || 0;

      // Hex fill
      const brightness = 0.06 + pulse*0.07 + e*0.18 + g*0.15;
      const r = Math.round(g*180 + e*8);
      const gv = Math.round(60 + pulse*70 + e*100 + g*120);
      const b = Math.round(90 + pulse*90 + e*40);
      hexPath(h.x, h.y, S - 1);
      ctx.fillStyle = `rgba(${r},${gv},${b},${brightness})`;
      ctx.fill();

      // Edge glow
      const edgeA = 0.08 + e*0.18 + pulse*0.07 + g*0.3;
      hexPath(h.x, h.y, S - 1);
      ctx.strokeStyle = g > 0.05
        ? `rgba(240,180,41,${edgeA})`
        : `rgba(0,229,255,${edgeA})`;
      ctx.lineWidth = 0.6 + e*0.8;
      ctx.stroke();

      // Centre dot for energised hexes
      if(e > 0.12 || g > 0.05){
        const dotR = 1.5 + e*5 + g*4;
        const grad = ctx.createRadialGradient(h.x,h.y,0,h.x,h.y,dotR);
        if(g > 0.05){
          grad.addColorStop(0, `rgba(240,180,41,${(e+g)*0.9})`);
          grad.addColorStop(1, 'rgba(240,180,41,0)');
        } else {
          grad.addColorStop(0, `rgba(0,229,255,${e*0.85})`);
          grad.addColorStop(1, 'rgba(0,229,255,0)');
        }
        ctx.beginPath();
        ctx.arc(h.x, h.y, dotR, 0, Math.PI*2);
        ctx.fillStyle = grad;
        ctx.fill();
      }
    }

    requestAnimationFrame(draw);
  }

  function resize(){
    const hero = canvas.parentElement;
    W = canvas.width = hero.offsetWidth;
    H = canvas.height = hero.offsetHeight;
    buildGrid();
  }

  document.addEventListener('mousemove', e=>{
    const rect = canvas.getBoundingClientRect();
    mouse.x = e.clientX - rect.left;
    mouse.y = e.clientY - rect.top;
    mouse.active = true;
  });
  document.addEventListener('mouseleave', ()=>{ mouse.active = false; });

  canvas.addEventListener('touchmove', e=>{
    const touch = e.touches[0];
    const rect = canvas.getBoundingClientRect();
    mouse.x = touch.clientX - rect.left;
    mouse.y = touch.clientY - rect.top;
    mouse.active = true;
  },{passive:true});
  canvas.addEventListener('touchend', ()=>{ mouse.active = false; });

  const ro = new ResizeObserver(()=>resize());
  ro.observe(canvas.parentElement);

  resize();
  draw();
})();

// ===================== LIVE STATS =====================
const API_BASE = 'https://explorer.qwid.org';

function formatNumber(n){
  if(typeof n !== 'number') n = parseFloat(n)||0;
  return n.toLocaleString('en-US', {maximumFractionDigits:2});
}

function setEl(id, val){
  const el = document.getElementById(id);
  if(el) el.textContent = val;
}

async function fetchStats(){
  try{
    const res = await fetch(API_BASE+'/api/stats',{signal:AbortSignal.timeout(8000)});
    if(!res.ok) return;
    const d = await res.json();
    if(d.height != null)     setEl('statHeight',    '#'+formatNumber(d.height));
    if(d.tps != null)        setEl('statTps',        d.tps.toFixed(1));
    if(d.supply != null)     setEl('statSupply',     formatNumber(d.supply));
    const staked = d.staked ?? d.totalStaked;
    const validators = d.validators ?? d.activeValidators;
    if(staked != null)     setEl('statStaked',     formatNumber(staked));
    if(validators != null) setEl('statValidators', validators);
  } catch(e){
    // Network unavailable during static hosting — silently ignore
  }
}

fetchStats();
setInterval(fetchStats, 15000);

// ===================== NAV HAMBURGER =====================
(function(){
  const nav = document.getElementById('mainNav');
  const btn = document.getElementById('navHamburger');
  if(!btn) return;
  btn.addEventListener('click', ()=>{
    nav.classList.toggle('open');
  });
  // Close on link click
  document.querySelectorAll('#navLinks a').forEach(a=>{
    a.addEventListener('click', ()=> nav.classList.remove('open'));
  });
})();

// ===================== SCROLL REVEAL =====================
(function(){
  const els = document.querySelectorAll('.reveal');
  if(!('IntersectionObserver' in window)){
    els.forEach(el=>el.classList.add('visible'));
    return;
  }
  const io = new IntersectionObserver((entries)=>{
    entries.forEach(e=>{
      if(e.isIntersecting){
        e.target.classList.add('visible');
        io.unobserve(e.target);
      }
    });
  },{threshold:0.08, rootMargin:'0px 0px -40px 0px'});
  els.forEach(el=>io.observe(el));
})();

// ===================== FAQ ACCORDION =====================
(function(){
  document.querySelectorAll('.faq-q').forEach(btn=>{
    btn.addEventListener('click', function(){
      const item = this.closest('.faq-item');
      const isOpen = item.classList.contains('open');
      // Close all
      document.querySelectorAll('.faq-item.open').forEach(el=>el.classList.remove('open'));
      // Open clicked if it was closed
      if(!isOpen) item.classList.add('open');
    });
  });
})();

// ===================== NAV SCROLL SHADOW =====================
(function(){
  const nav = document.getElementById('mainNav');
  window.addEventListener('scroll', ()=>{
    if(window.scrollY > 40){
      nav.style.background = 'rgba(2,8,16,0.97)';
    } else {
      nav.style.background = 'rgba(2,8,16,0.82)';
    }
  },{passive:true});
})();
