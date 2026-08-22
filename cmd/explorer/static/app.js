const API = window.location.pathname.replace(/\/+$/, '');
let refreshTimer = null;

// esc escapes a value for interpolation into HTML, both in text position and
// inside a double-quoted attribute.
//
// Every view below builds markup by string interpolation and assigns it with
// innerHTML, so any interpolated value that is not escaped is a script
// injection point. Today the API cannot deliver one — addresses and hashes are
// produced by hex-encoding fixed-size byte arrays, the search endpoint rejects
// anything that is not ^[0-9a-fA-F]+$, and every error string it returns is a
// constant. That is a property of the current handlers, not of this file, and
// one new endpoint that echoes its input would turn every sink here into a
// stored XSS. Escaping at the sink does not depend on that promise holding.
function esc(v) {
    if (v === undefined || v === null) return '';
    return String(v).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[c]);
}

function formatTime(ts) {
    if (!ts) return '-';
    return new Date(ts * 1000).toLocaleString();
}

function timeAgo(ts) {
    if (!ts) return '-';
    const s = Math.floor(Date.now()/1000) - ts;
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.floor(s/60) + 'm ago';
    if (s < 86400) return Math.floor(s/3600) + 'h ago';
    return Math.floor(s/86400) + 'd ago';
}

function truncHash(h, n) {
    if (!h) return '-';
    n = n || 8;
    h = String(h);
    return h.substring(0, n) + '…' + h.substring(h.length - n);
}

function formatAmount(a) {
    if (a === undefined || a === null) return '0';
    const s = Number(a).toFixed(8).replace(/\.?0+$/, '') || '0';
    const parts = s.split('.');
    parts[0] = Number(parts[0]).toLocaleString('en-US');
    return parts.length > 1 ? parts[0] + '.' + parts[1] : parts[0];
}

function fmt2(a) {
    if (a === undefined || a === null) return '0';
    return Math.round(Number(a)).toLocaleString('en-US');
}

function locationBadge(loc) {
    if (!loc) return '';
    if (loc === 'confirmed_db') return '<span class="badge badge-confirmed">Confirmed</span>';
    if (loc.startsWith('pool') || loc.startsWith('memory')) return '<span class="badge badge-pool">Pending</span>';
    return '<span class="badge">' + esc(loc) + '</span>';
}

async function api(path) {
    const resp = await fetch(API + path);
    if (!resp.ok) {
        const err = await resp.json().catch(() => ({error: 'Request failed'}));
        throw new Error(err.error || 'Request failed');
    }
    return resp.json();
}

function navigate(hash) { window.location.hash = hash; }

function doSearch() {
    const q = document.getElementById('searchInput').value.trim();
    if (!q) return;
    navigate('#/search/' + encodeURIComponent(q));
}

// --- Views ---

async function renderDashboard() {
    const c = document.getElementById('content');
    c.innerHTML = '<div class="loading">Loading dashboard…</div>';
    try {
        const [stats, blocksData] = await Promise.all([
            api('/api/stats'),
            api('/api/blocks?count=10')
        ]);

        c.innerHTML = `
            <div class="card">
                <h3>Network Statistics</h3>
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-label">Block Height</div>
                        <div class="stat-value accent">${esc(stats.height || 0)}</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Max Height</div>
                        <div class="stat-value">${esc(stats.heightMax || 0)}</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Transactions</div>
                        <div class="stat-value">${esc(stats.transactions || 0)}</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">TPS</div>
                        <div class="stat-value">${(Number(stats.tps) || 0).toFixed(2)}</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Difficulty</div>
                        <div class="stat-value">${esc(stats.difficulty || 0)}</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Pending TXs</div>
                        <div class="stat-value">${esc(stats.transactionsPending || 0)}</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Price Oracle</div>
                        <div class="stat-value">${(Number(stats.priceOracle) || 0).toFixed(4)}</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Syncing</div>
                        <div class="stat-value">${stats.syncing ? 'Yes' : 'No'}</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Supply</div>
                        <div class="stat-value">${stats.supply ? fmt2(stats.supply) : '-'}</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Total Staked</div>
                        <div class="stat-value accent">${stats.totalStaked ? formatAmount(stats.totalStaked) : '-'}</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Active Validators</div>
                        <div class="stat-value">${esc(stats.activeValidators || 0)}</div>
                    </div>
                </div>
            </div>
            <div class="card">
                <h3>Latest Blocks</h3>
                <div class="table-scroll">
                <table>
                    <tr><th>Height</th><th>Hash</th><th>TXs</th><th>Fee</th><th>Time</th></tr>
                    ${(blocksData.blocks || []).map(b => `
                        <tr>
                            <td><a href="#/block/${esc(b.height)}">${esc(b.height)}</a></td>
                            <td class="mono"><a class="truncate" href="#/block/${esc(b.height)}">${esc(truncHash(b.hash, 10))}</a></td>
                            <td>${esc(b.txCount || 0)}</td>
                            <td>${formatAmount(b.blockFee)}</td>
                            <td>${timeAgo(b.timestamp)}</td>
                        </tr>
                    `).join('')}
                </table>
                </div>
                <div class="card-more">
                    <a href="#/blocks">View all blocks →</a>
                </div>
            </div>
        `;
    } catch(e) {
        c.innerHTML = '<div class="error-msg">Failed to load: ' + esc(e.message) + '</div>';
    }
}

let blocksPage = null;
async function renderBlocks() {
    const c = document.getElementById('content');
    c.innerHTML = '<div class="loading">Loading blocks…</div>';
    try {
        let url = '/api/blocks?count=20';
        if (blocksPage !== null) url += '&from=' + blocksPage;
        const data = await api(url);
        const blocks = data.blocks || [];
        const fromHeight = data.fromHeight;

        c.innerHTML = `
            <div class="card">
                <h3>Blocks</h3>
                <div class="table-scroll">
                <table>
                    <tr><th>Height</th><th>Hash</th><th>TXs</th><th>Fee</th><th>Time</th></tr>
                    ${blocks.map(b => `
                        <tr>
                            <td><a href="#/block/${esc(b.height)}">${esc(b.height)}</a></td>
                            <td class="mono"><a class="truncate" href="#/block/${esc(b.height)}">${esc(truncHash(b.hash, 10))}</a></td>
                            <td>${esc(b.txCount || 0)}</td>
                            <td>${formatAmount(b.blockFee)}</td>
                            <td>${timeAgo(b.timestamp)}</td>
                        </tr>
                    `).join('')}
                </table>
                </div>
                <div class="pagination">
                    <button type="button" data-page="${esc(fromHeight + 20)}" ${fromHeight + 20 > (data.fromHeight + 20) ? 'disabled' : ''}>Newer</button>
                    <button type="button" data-page="latest">Latest</button>
                    <button type="button" data-page="${esc(fromHeight - 20)}" ${fromHeight - 20 < 0 ? 'disabled' : ''}>Older</button>
                </div>
            </div>
        `;
    } catch(e) {
        c.innerHTML = '<div class="error-msg">Failed to load: ' + esc(e.message) + '</div>';
    }
}

async function renderBlock(height) {
    const c = document.getElementById('content');
    c.innerHTML = '<div class="loading">Loading block…</div>';
    try {
        const b = await api('/api/block?height=' + encodeURIComponent(height));
        const h = parseInt(height);

        c.innerHTML = `
            <div class="card">
                <h3>Block #${esc(b.height)}</h3>
                <div class="detail-row"><div class="detail-label">Height</div><div class="detail-value">${esc(b.height)}</div></div>
                <div class="detail-row"><div class="detail-label">Block Hash</div><div class="detail-value mono">${esc(b.hash)}</div></div>
                <div class="detail-row"><div class="detail-label">Previous Hash</div><div class="detail-value mono">${b.height > 0 ? '<a href="#/block/' + esc(h-1) + '">' + esc(b.previousHash) + '</a>' : esc(b.previousHash)}</div></div>
                <div class="detail-row"><div class="detail-label">Timestamp</div><div class="detail-value">${formatTime(b.timestamp)}</div></div>
                <div class="detail-row"><div class="detail-label">Difficulty</div><div class="detail-value">${esc(b.difficulty)}</div></div>
                <div class="detail-row"><div class="detail-label">Operator Account</div><div class="detail-value mono"><a href="#/account/${esc(b.operatorAccount)}">${esc(b.operatorAccount)}</a></div></div>
                <div class="detail-row"><div class="detail-label">Delegated Account</div><div class="detail-value mono"><a href="#/account/${esc(b.delegatedAccount)}">${esc(b.delegatedAccount)}</a></div></div>
                <div class="detail-row"><div class="detail-label">Merkle Root</div><div class="detail-value mono">${esc(b.merkleRoot)}</div></div>
                <div class="detail-row"><div class="detail-label">Supply</div><div class="detail-value">${fmt2(b.supply)} QWD</div></div>
                <div class="detail-row"><div class="detail-label">Block Fee</div><div class="detail-value">${formatAmount(b.blockFee)} QWD</div></div>
                <div class="detail-row"><div class="detail-label">Reward %</div><div class="detail-value">${(Number(b.rewardPercentage) / 10).toFixed(1)}%</div></div>
                <div class="detail-row"><div class="detail-label">Price Oracle</div><div class="detail-value">${formatAmount(b.priceOracle)}</div></div>
                <div class="detail-row"><div class="detail-label">Random Oracle</div><div class="detail-value">${esc(b.randOracle)}</div></div>
                <div class="detail-row"><div class="detail-label">Transactions</div><div class="detail-value">${esc(b.txCount)}</div></div>
            </div>
            ${b.txCount > 0 ? `
            <div class="card">
                <h3>Transactions (${esc(b.txCount)})</h3>
                <div class="tag-list">
                    ${(b.txHashes || []).map(tx => `<a class="tag" href="#/tx/${esc(tx)}">${esc(truncHash(tx, 8))}</a>`).join('')}
                </div>
            </div>` : ''}
            <div class="block-nav">
                <button type="button" data-nav="#/block/${esc(h-1)}" ${h <= 0 ? 'disabled' : ''}>← Previous Block</button>
                <button type="button" data-nav="#/block/${esc(h+1)}">Next Block →</button>
            </div>
        `;
    } catch(e) {
        c.innerHTML = '<div class="error-msg">Block not found: ' + esc(e.message) + '</div>';
    }
}

async function renderTx(hash) {
    const c = document.getElementById('content');
    c.innerHTML = '<div class="loading">Loading transaction…</div>';
    try {
        const tx = await api('/api/tx?hash=' + encodeURIComponent(hash));

        let extra = '';
        if (tx.optData) {
            extra += `<div class="detail-row"><div class="detail-label">Contract Data</div><div class="detail-value mono breakall">${esc(tx.optData)}</div></div>`;
        }
        if (tx.lockedAmount !== undefined) {
            extra += `<div class="detail-row"><div class="detail-label">Locked Amount</div><div class="detail-value">${formatAmount(tx.lockedAmount)} QWD</div></div>`;
            extra += `<div class="detail-row"><div class="detail-label">Release/Block</div><div class="detail-value">${formatAmount(tx.releasePerBlock)} QWD</div></div>`;
            extra += `<div class="detail-row"><div class="detail-label">Locking Account</div><div class="detail-value mono"><a href="#/account/${esc(tx.delegatedAccountForLocking)}">${esc(tx.delegatedAccountForLocking)}</a></div></div>`;
        }
        if (tx.escrowDelay) {
            extra += `<div class="detail-row"><div class="detail-label">Escrow Delay</div><div class="detail-value">${esc(tx.escrowDelay)} blocks</div></div>`;
        }
        if (tx.contractAddress) {
            extra += `<div class="detail-row"><div class="detail-label">Contract Address</div><div class="detail-value mono"><a href="#/account/${esc(tx.contractAddress)}">${esc(tx.contractAddress)}</a></div></div>`;
        }

        c.innerHTML = `
            <div class="card">
                <h3>Transaction Details</h3>
                <div class="detail-row"><div class="detail-label">Hash</div><div class="detail-value mono">${esc(tx.hash)}</div></div>
                <div class="detail-row"><div class="detail-label">Status</div><div class="detail-value">${locationBadge(tx.location)}</div></div>
                <div class="detail-row"><div class="detail-label">Block Height</div><div class="detail-value"><a href="#/block/${esc(tx.height)}">${esc(tx.height)}</a></div></div>
                <div class="detail-row"><div class="detail-label">Timestamp</div><div class="detail-value">${formatTime(tx.timestamp)}</div></div>
                <div class="detail-row"><div class="detail-label">Sender</div><div class="detail-value mono"><a href="#/account/${esc(tx.sender)}">${esc(tx.sender)}</a></div></div>
                <div class="detail-row"><div class="detail-label">Recipient</div><div class="detail-value mono"><a href="#/account/${esc(tx.recipient)}">${esc(tx.recipient)}</a></div></div>
                <div class="detail-row"><div class="detail-label">Amount</div><div class="detail-value accent">${formatAmount(tx.amount)} QWD</div></div>
                <div class="detail-row"><div class="detail-label">Gas Price</div><div class="detail-value">${esc(tx.gasPrice)}</div></div>
                <div class="detail-row"><div class="detail-label">Gas Usage</div><div class="detail-value">${esc(tx.gasUsage)}</div></div>
                <div class="detail-row"><div class="detail-label">Nonce</div><div class="detail-value">${esc(tx.nonce)}</div></div>
                <div class="detail-row"><div class="detail-label">Chain ID</div><div class="detail-value">${esc(tx.chainId)}</div></div>
                ${extra}
            </div>
        `;
    } catch(e) {
        c.innerHTML = '<div class="error-msg">Transaction not found: ' + esc(e.message) + '</div>';
    }
}

async function renderAccount(addr) {
    const c = document.getElementById('content');
    c.innerHTML = '<div class="loading">Loading account…</div>';
    try {
        const acc = await api('/api/account?address=' + encodeURIComponent(addr));

        let stakingHtml = '';
        if (acc.stakingDetails && acc.stakingDetails.length > 0) {
            stakingHtml = `
                <div class="card">
                    <h3>Staking Details</h3>
                    <table>
                        <tr><th>Delegated Account</th><th>Staked</th><th>Rewards</th></tr>
                        ${acc.stakingDetails.map(s => `
                            <tr>
                                <td class="mono"><a href="#/account/${esc(s.delegatedAddress)}">${esc(truncHash(s.delegatedAddress, 8))}</a></td>
                                <td>${formatAmount(s.staked)} QWD</td>
                                <td>${formatAmount(s.rewards)} QWD</td>
                            </tr>
                        `).join('')}
                    </table>
                </div>
            `;
        }

        let txHtml = '';
        if (acc.transactions && acc.transactions.length > 0) {
            txHtml = `
                <div class="card">
                    <h3>Recent Transactions</h3>
                    <div class="table-scroll">
                    <table>
                        <tr><th>Type</th><th>Hash</th><th>Counterparty</th><th>Amount</th><th>Height</th><th>Time</th></tr>
                        ${acc.transactions.map(tx => {
                            const isSent = tx.type === 'sent';
                            const counterparty = isSent ? tx.recipient : tx.sender;
                            return `<tr>
                                <td><span class="badge ${isSent ? 'badge-sent' : 'badge-received'}">${esc(tx.type)}</span></td>
                                <td class="mono"><a class="truncate" href="#/tx/${esc(tx.hash)}">${esc(truncHash(tx.hash, 6))}</a></td>
                                <td class="mono"><a class="truncate" href="#/account/${esc(counterparty)}">${esc(truncHash(counterparty, 6))}</a></td>
                                <td>${formatAmount(tx.amount)} QWD</td>
                                <td><a href="#/block/${esc(tx.height)}">${esc(tx.height)}</a></td>
                                <td>${tx.timestamp ? timeAgo(tx.timestamp) : '-'}</td>
                            </tr>`;
                        }).join('')}
                    </table>
                    </div>
                </div>
            `;
        }

        c.innerHTML = `
            <div class="card">
                <h3>Account Details</h3>
                <div class="detail-row"><div class="detail-label">Address</div><div class="detail-value mono">${esc(acc.address)}</div></div>
                <div class="detail-row"><div class="detail-label">Balance</div><div class="detail-value accent">${formatAmount(acc.balance)} QWD</div></div>
                <div class="detail-row"><div class="detail-label">Staked</div><div class="detail-value">${formatAmount(acc.stakedAmount)} QWD</div></div>
                <div class="detail-row"><div class="detail-label">Locked</div><div class="detail-value">${formatAmount(acc.lockedAmount)} QWD</div></div>
                <div class="detail-row"><div class="detail-label">Rewards</div><div class="detail-value">${formatAmount(acc.rewardsAmount)} QWD</div></div>
                <div class="detail-row"><div class="detail-label">Total Holdings</div><div class="detail-value accent">${formatAmount(acc.totalHoldings)} QWD</div></div>
                <div class="detail-row"><div class="detail-label">Escrow Delay</div><div class="detail-value">${esc(acc.escrowDelay || 0)} blocks</div></div>
                <div class="detail-row"><div class="detail-label">Multi-Sig</div><div class="detail-value">${esc(acc.multiSignNumber || 0)}</div></div>
                <div class="detail-row"><div class="detail-label">Sent TXs</div><div class="detail-value">${esc(acc.sentCount || 0)}</div></div>
                <div class="detail-row"><div class="detail-label">Received TXs</div><div class="detail-value">${esc(acc.receivedCount || 0)}</div></div>
            </div>
            ${stakingHtml}
            ${txHtml}
        `;
    } catch(e) {
        c.innerHTML = '<div class="error-msg">Account not found: ' + esc(e.message) + '</div>';
    }
}

async function renderValidators() {
    const c = document.getElementById('content');
    c.innerHTML = '<div class="loading">Loading validators…</div>';
    try {
        const [vals, blockStats] = await Promise.all([
            api('/api/validators'),
            api('/api/validators/blocks?count=10')
        ]);

        const producerMap = {};
        (blockStats.producers || []).forEach(p => { producerMap[p.operatorAddress] = p; });

        const validators = (vals.validators || []).map(v => {
            const bp = producerMap[v.operatorAddress] || {};
            return { ...v, blocksProduced: bp.blocksProduced || 0, lastBlockTime: bp.lastBlockTime || 0 };
        });
        validators.sort((a, b) => b.totalStaked - a.totalStaked);

        c.innerHTML = `
            <div class="card">
                <h3>Staking Overview</h3>
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-label">Total Staked</div>
                        <div class="stat-value accent">${formatAmount(vals.totalStaked)} QWD</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Active Validators</div>
                        <div class="stat-value">${validators.length}</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Total Supply</div>
                        <div class="stat-value">${blockStats.supply ? fmt2(blockStats.supply) + ' QWD' : '-'}</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Blocks Scanned</div>
                        <div class="stat-value">${esc(blockStats.blocksScanned || 0)}</div>
                    </div>
                </div>
            </div>
            <div class="card">
                <h3>Validators</h3>
                <div class="table-scroll">
                <table>
                    <tr><th>ID</th><th>Operator</th><th>Total Staked</th><th>Stakers</th><th>Blocks (last ${esc(blockStats.blocksScanned || 100)})</th><th>Last Block</th><th>Status</th></tr>
                    ${validators.map(v => `
                        <tr>
                            <td>${esc(v.id)}</td>
                            <td class="mono"><a class="truncate" href="#/account/${esc(v.operatorAddress)}">${esc(truncHash(v.operatorAddress, 8))}</a></td>
                            <td>${formatAmount(v.totalStaked)} QWD</td>
                            <td>${esc(v.stakerCount)}</td>
                            <td>${esc(v.blocksProduced)}</td>
                            <td>${v.lastBlockTime ? timeAgo(v.lastBlockTime) : '-'}</td>
                            <td><span class="badge ${v.isOperational ? 'badge-confirmed' : 'badge-pool'}">${v.isOperational ? 'Active' : 'Inactive'}</span></td>
                        </tr>
                    `).join('')}
                </table>
                </div>
            </div>
        `;
    } catch(e) {
        c.innerHTML = '<div class="error-msg">Failed to load validators: ' + esc(e.message) + '</div>';
    }
}

async function renderSearch(query) {
    const c = document.getElementById('content');
    c.innerHTML = '<div class="loading">Searching…</div>';
    try {
        const data = await api('/api/search?q=' + encodeURIComponent(query));
        switch(data.type) {
            case 'block': navigate('#/block/' + data.result.height); return;
            case 'transaction': navigate('#/tx/' + data.result.hash); return;
            case 'account': navigate('#/account/' + data.result.address); return;
        }
        // query comes straight from the URL fragment and is entirely
        // attacker-chosen — this is the one sink here that never passes
        // through the API at all.
        c.innerHTML = '<div class="error-msg">No results found for "' + esc(query) + '"</div>';
    } catch(e) {
        c.innerHTML = '<div class="error-msg">Not found: ' + esc(e.message) + '</div>';
    }
}

// --- Router ---

function setActiveNav(id) {
    document.querySelectorAll('.nav a').forEach(a => a.classList.remove('active'));
    const el = document.getElementById(id);
    if (el) el.classList.add('active');
}

function route() {
    if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
    const hash = window.location.hash || '#/';
    const parts = hash.split('/').filter(Boolean);
    const path = parts[0] || '#';

    if (hash === '#/' || hash === '#' || hash === '') {
        setActiveNav('nav-dashboard');
        renderDashboard();
        refreshTimer = setInterval(renderDashboard, 10000);
    } else if (path === '#' && parts[1] === 'blocks') {
        setActiveNav('nav-blocks');
        blocksPage = null;
        renderBlocks();
    } else if (path === '#' && parts[1] === 'validators') {
        setActiveNav('nav-validators');
        renderValidators();
    } else if (path === '#' && parts[1] === 'block') {
        setActiveNav('');
        renderBlock(parts[2]);
    } else if (path === '#' && parts[1] === 'tx') {
        setActiveNav('');
        renderTx(parts[2]);
    } else if (path === '#' && parts[1] === 'account') {
        setActiveNav('');
        renderAccount(parts[2]);
    } else if (path === '#' && parts[1] === 'search') {
        setActiveNav('');
        renderSearch(decodeURIComponent(parts[2]));
    } else {
        setActiveNav('nav-dashboard');
        renderDashboard();
        refreshTimer = setInterval(renderDashboard, 10000);
    }
}

// --- Event wiring ---
//
// Everything below used to be onclick="" / onkeydown="" attributes in the
// markup. They were moved here because inline handlers cannot be permitted by
// any Content-Security-Policy worth setting: allowing them requires
// script-src 'unsafe-inline', which also re-permits every injected <script>.
//
// Navigation links generated by the views are now plain <a href="#/…">, which
// the router already handles via hashchange — and which, unlike an onclick
// handler, can be opened in a new tab or middle-clicked. Only the controls that
// cannot be expressed as a link carry a data attribute and are handled here by
// delegation, so they keep working across re-renders.

document.getElementById('searchBtn').addEventListener('click', doSearch);
document.getElementById('searchInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') doSearch();
});

document.getElementById('content').addEventListener('click', e => {
    const nav = e.target.closest('[data-nav]');
    if (nav) { navigate(nav.dataset.nav); return; }

    const pager = e.target.closest('[data-page]');
    if (pager) {
        const p = pager.dataset.page;
        blocksPage = (p === 'latest') ? null : parseInt(p, 10);
        renderBlocks();
    }
});

window.addEventListener('hashchange', route);
window.addEventListener('load', route);
