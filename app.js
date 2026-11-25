let currentUser = null;
let currentCatalog = [];
let selectedOption = null;
let selectedDepositAmount = 100;
let activeModalVoucher = null;

(function installCsrfFetchInterceptor() {
  const nativeFetch = window.fetch.bind(window);
  window.fetch = function (input, init = {}) {
    const method = ((init && init.method) || 'GET').toUpperCase();
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
      const urlStr = typeof input === 'string' ? input : (input && input.url) || '';
      const isSameOrigin = !urlStr.startsWith('http') || urlStr.startsWith(window.location.origin);
      if (isSameOrigin) {
        const meta = document.querySelector('meta[name="csrf-token"]');
        const token = (meta && meta.content) || window.__CSRF_TOKEN || '';
        if (token) {
          const headers = new Headers(init.headers || {});
          if (!headers.has('X-CSRF-Token')) {
            headers.set('X-CSRF-Token', token);
          }
          init = Object.assign({}, init, { headers });
        }
      }
    }
    return nativeFetch(input, init);
  };
})();

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function setCsrfToken(token) {
  if (!token) return;
  window.__CSRF_TOKEN = token;
  let meta = document.querySelector('meta[name="csrf-token"]');
  if (!meta) {
    meta = document.createElement('meta');
    meta.name = 'csrf-token';
    document.head.appendChild(meta);
  }
  meta.content = token;
}

document.addEventListener('DOMContentLoaded', () => {
  initApp();
});

async function initApp() {
  await checkUserAuth();

  if (document.getElementById('products-catalog-container')) {
    loadCatalog();
  }

  if (document.getElementById('dash-balance-val')) {
    loadDashboardStats();
  }

  setupEventListeners();

  const params = new URLSearchParams(window.location.search);
  const urlSessionId = params.get('session_id');
  const isDepositSuccess = params.get('deposit') === 'success';

  if (isDepositSuccess || urlSessionId) {
    const sessionId = urlSessionId || localStorage.getItem('ovk_pending_checkout');
    if (sessionId && !sessionId.includes('{CHECKOUT_SESSION_ID}')) {
      showToast('Loading.. Please wait.', 'info');
      try {
        const verifyRes = await fetch('/api/wallet/verify-checkout', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ session_id: sessionId })
        });
        const verifyData = await verifyRes.json();
        if (verifyData.success) {
          showToast(verifyData.message || 'Payment verified! Credits added.', 'success');
        }
        localStorage.removeItem('ovk_pending_checkout');
      } catch (err) {
        showToast('Payment received! Refreshing balance...', 'success');
      }
    } else {
      localStorage.removeItem('ovk_pending_checkout');
    }
    window.history.replaceState({}, document.title, window.location.pathname);
    await checkUserAuth();
    if (document.getElementById('dash-balance-val')) {
      loadDashboardStats();
    }
  }
}

async function checkUserAuth() {
  try {
    const res = await fetch('/api/auth/me');
    const data = await res.json();
    if (data.csrf_token) setCsrfToken(data.csrf_token);
    const actionsContainer = document.getElementById('header-actions-area');

    if (data.authenticated && data.user) {
      currentUser = data.user;
      const initial = (data.user.username || 'U').charAt(0).toUpperCase();

      if (actionsContainer) {
        const fontBtn = document.getElementById('font-picker-btn');
        const fontDrop = document.getElementById('font-picker-dropdown');
        const fontHtml = (fontBtn && fontDrop) ? fontBtn.outerHTML + fontDrop.outerHTML : '';

        actionsContainer.innerHTML = `
          ${fontHtml}
          <div class="coin-pill" onclick="openDepositModal()" title="Wallet Balance">
            <div class="coin-icon">₱</div>
            <span id="nav-coin-val">${parseFloat(data.user.balance).toFixed(2)}</span>
          </div>
          <button class="user-avatar-btn" id="avatar-btn" onclick="toggleUserMenu()">${escapeHtml(initial)}</button>
          <div class="user-dropdown-menu" id="user-dropdown">
            <div style="padding: 8px 12px; border-bottom: 1px solid var(--border-card); margin-bottom: 6px;">
              <div style="font-weight: 700; color: #fff;">${escapeHtml(data.user.username)}</div>
              <div style="font-size: 0.75rem; color: var(--text-dark);">${escapeHtml(data.user.email)}</div>
            </div>
            <a href="/dashboard" class="dropdown-item">Dashboard</a>
            <a href="/products" class="dropdown-item">Products</a>
            <a href="/referrals" class="dropdown-item">Referrals</a>
            <a href="/tutorial" class="dropdown-item">Tutorial</a>
            <a href="javascript:void(0)" onclick="openDepositModal()" class="dropdown-item" style="color: var(--accent);">+ Deposit</a>
            <a href="javascript:void(0)" onclick="openPasswordModal()" class="dropdown-item">Change Password</a>
            ${data.user.role === 'admin' ? '<a href="/admin" class="dropdown-item" style="color: var(--accent);">Admin Panel</a>' : ''}
            <a href="javascript:void(0)" onclick="logoutUser()" class="dropdown-item" style="color: var(--danger); border-top: 1px solid var(--border-card); margin-top: 4px;">Sign Out</a>
          </div>
        `;
        renderFontPickerItems();
      }
    } else {
      currentUser = null;
      if (actionsContainer) {
        actionsContainer.innerHTML = `
          <a href="/login" class="btn btn-withdraw btn-sm">Sign In</a>
          <a href="/login?tab=register" class="btn btn-deposit btn-sm">Register</a>
        `;
      }
    }
  } catch (err) {
    console.error('Auth error:', err);
  }
}

function toggleUserMenu() {
  const menu = document.getElementById('user-dropdown');
  if (menu) menu.classList.toggle('show');
}

document.addEventListener('click', (e) => {
  const menu = document.getElementById('user-dropdown');
  const btn = document.getElementById('avatar-btn');
  if (menu && menu.classList.contains('show')) {
    if (!menu.contains(e.target) && e.target !== btn) {
      menu.classList.remove('show');
    }
  }
});

function openPasswordModal() {
  const menu = document.getElementById('user-dropdown');
  if (menu) menu.classList.remove('show');
  const modal = document.getElementById('change-password-modal');
  if (modal) modal.classList.add('active');
}

function closePasswordModal() {
  const modal = document.getElementById('change-password-modal');
  if (modal) modal.classList.remove('active');
}

async function submitPasswordChange(e) {
  e.preventDefault();
  const cur = document.getElementById('cp-current').value;
  const nw = document.getElementById('cp-new').value;
  const cf = document.getElementById('cp-confirm').value;
  if (nw !== cf) {
    showToast('New passwords do not match.', 'error');
    return;
  }
  const btn = document.getElementById('btn-save-password');
  if (btn) btn.disabled = true;
  try {
    const res = await fetch('/api/auth/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ current_password: cur, new_password: nw })
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Could not update password.', 'error');
      return;
    }
    showToast(data.message || 'Password updated!', 'success');
    document.getElementById('cp-current').value = '';
    document.getElementById('cp-new').value = '';
    document.getElementById('cp-confirm').value = '';
    closePasswordModal();
  } catch (err) {
    showToast('Network error.', 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

let currentPlatformFilter = 'all';
let currentSearchQuery = '';

async function loadCatalog() {
  const container = document.getElementById('products-catalog-container');
  if (!container) return;

  try {
    const res = await fetch('/api/catalog');
    const data = await res.json();
    currentCatalog = data.catalog || [];
    renderCatalogItems();
  } catch (err) {
    container.innerHTML = '<p style="color: var(--danger); padding: 20px;">Failed to load products.</p>';
  }
}

function filterCatalog(platform, btnEl) {
  currentPlatformFilter = platform.toLowerCase();
  document.querySelectorAll('.filter-pill').forEach(btn => btn.classList.remove('active'));
  if (btnEl) btnEl.classList.add('active');
  renderCatalogItems();
}

function filterCatalogSearch(query) {
  currentSearchQuery = (query || '').toLowerCase().trim();
  renderCatalogItems();
}

function renderCatalogItems() {
  const container = document.getElementById('products-catalog-container');
  if (!container) return;

  let filtered = currentCatalog;

  if (currentPlatformFilter !== 'all') {
    filtered = filtered.filter(item =>
      (item.platform && item.platform.toLowerCase().includes(currentPlatformFilter)) ||
      (item.title && item.title.toLowerCase().includes(currentPlatformFilter))
    );
  }

  if (currentSearchQuery) {
    filtered = filtered.filter(item =>
      (item.title && item.title.toLowerCase().includes(currentSearchQuery)) ||
      (item.description && item.description.toLowerCase().includes(currentSearchQuery))
    );
  }

  if (filtered.length === 0) {
    container.innerHTML = '<div style="grid-column: 1 / -1; padding: 40px; text-align: center; color: var(--text-muted);">No products found matching your filter.</div>';
    return;
  }

  container.className = 'products-catalog-grid';
  container.innerHTML = filtered.map((item, idx) => `
    <div class="product-shop-card tilt-3d unfold-in delay-${(idx % 4) + 1}" data-tilt-max="6" onclick="window.location.href='/product/${item.id}'">
      <div class="tilt-glare"></div>
      <div class="card-banner-box">
        <img src="${escapeHtml(item.image_url)}" alt="${escapeHtml(item.title)}" class="card-banner-img" onerror="this.src='/static/images/ovk_hax.jpg'">
        <div class="card-status-badge">
          <span class="status-dot-green"></span>
          <span>Undetected</span>
        </div>
        <div class="card-platform-badge">${escapeHtml(item.platform || 'ANDROID')}</div>
        <button type="button" class="card-zoom-btn" onclick="event.stopPropagation(); openImageLightbox('${escapeHtml(item.image_url)}', '${escapeHtml(item.title)}')" title="Preview Screenshot">
          <i class="fa-solid fa-expand"></i> Preview
        </button>
      </div>

      <div class="card-info-box">
        <div class="card-cat-title">${escapeHtml(item.category || 'GAMES')} &middot; ${escapeHtml(item.platform || 'ANDROID')}</div>
        <h2 class="card-item-title">${escapeHtml(item.title)}</h2>
        <p class="card-desc-text">
          ${escapeHtml((item.description || 'Instant automated digital key delivery right after checkout.').replace(/119\s*FPS/gi, '185 FPS'))}
        </p>

        <ul class="clean-feature-list">
          <li><i class="fa-solid fa-check"></i> Radar Wheel &amp; 185 FPS Mode</li>
          <li><i class="fa-solid fa-check"></i> Aimbot &amp; Memory ESP</li>
          <li><i class="fa-solid fa-check"></i> Stream Proof (Hide Record)</li>
        </ul>

        <div class="card-action-bar">
          <div class="card-price-stack">
            <span class="price-sub">Starts at</span>
            <span class="price-main">₱${parseFloat(item.min_price || 70).toFixed(2)}</span>
          </div>
          <a href="/product/${item.id}" class="btn-buy-card" onclick="event.stopPropagation();">
            <span>Buy Key</span>
            <i class="fa-solid fa-arrow-right"></i>
          </a>
        </div>
      </div>
    </div>
  `).join('');
  bind3DTiltCards();
}

function openImageLightbox(src, caption) {
  const modal = document.getElementById('lightbox-modal');
  const img = document.getElementById('lightbox-img');
  const cap = document.getElementById('lightbox-caption');
  if (modal && img) {
    img.src = src || '/static/images/ovk_hax.jpg';
    if (cap) cap.innerText = caption || 'Preview';
    modal.style.display = 'flex';
  }
}

function closeImageLightbox() {
  const modal = document.getElementById('lightbox-modal');
  if (modal) modal.style.display = 'none';
}

function isLifetimeOption(opt) {
  if (!opt) return false;
  return /lifetime/i.test(opt.duration || '') || /lifetime/i.test(opt.name || '');
}

function openOptionsModal(catalogId) {
  const item = currentCatalog.find(c => c.id === catalogId);
  if (!item) return;

  const modal = document.getElementById('options-modal');
  if (!modal) return;

  activeModalVoucher = null;
  document.getElementById('opt-modal-title').innerText = item.title;
  document.getElementById('opt-modal-cat').innerText = item.category;

  const listContainer = document.getElementById('options-list');
  listContainer.innerHTML = item.options.map((opt, idx) => `
    <div class="option-select-item ${idx === 0 ? 'selected' : ''}" onclick="selectTierOption(${opt.id})" id="opt-item-${opt.id}">
      <div>
        <div class="option-item-name">${escapeHtml(opt.duration)}</div>
        <div style="font-size: 0.75rem; color: var(--text-dark);">${escapeHtml(opt.badge || 'Instant Delivery')} &bull; ${opt.stock > 0 ? `${opt.stock} in stock` : 'Out of stock'}</div>
      </div>
      <div class="option-item-price">₱${parseFloat(opt.price).toFixed(2)}</div>
    </div>
  `).join('');

  if (item.options.length > 0) {
    selectedOption = item.options[0];
    updateOptionSummary();
  }

  modal.classList.add('active');
}

function closeOptionsModal() {
  const modal = document.getElementById('options-modal');
  if (modal) modal.classList.remove('active');
}

function selectTierOption(id) {
  document.querySelectorAll('.option-select-item').forEach(el => el.classList.remove('selected'));
  const target = document.getElementById(`opt-item-${id}`);
  if (target) target.classList.add('selected');

  for (const item of currentCatalog) {
    const found = item.options.find(o => o.id === id);
    if (found) {
      selectedOption = found;
      break;
    }
  }
  activeModalVoucher = null;
  updateOptionSummary();
}

function updateOptionSummary() {
  if (!selectedOption) return;
  const vWrap = document.getElementById('opt-voucher-wrap');
  if (vWrap) {
    vWrap.style.display = isLifetimeOption(selectedOption) ? 'block' : 'none';
    const msg = document.getElementById('opt-voucher-msg');
    if (msg && !activeModalVoucher) msg.innerHTML = '';
  }
  const finalPrice = activeModalVoucher ? activeModalVoucher.final_price : parseFloat(selectedOption.price);
  const buyBtn = document.getElementById('btn-buy-option');
  if (buyBtn) {
    buyBtn.innerText = `PURCHASE FOR ₱${finalPrice.toFixed(2)}`;
  }
}

async function applyModalVoucher() {
  if (!selectedOption) return;
  const input = document.getElementById('opt-voucher-input');
  const msg = document.getElementById('opt-voucher-msg');
  const code = (input ? input.value : '').trim();
  if (!code) return;
  try {
    const res = await fetch('/api/voucher/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, product_id: selectedOption.id })
    });
    const data = await res.json();
    if (!res.ok) {
      activeModalVoucher = null;
      if (msg) msg.innerHTML = `<span style="color:var(--danger);">${escapeHtml(data.error || 'Invalid voucher')}</span>`;
      updateOptionSummary();
      return;
    }
    activeModalVoucher = data;
    if (msg) msg.innerHTML = `<span style="color:var(--success); font-weight:600;">${escapeHtml(data.code)}: -${data.discount_percent}% off (₱${data.final_price.toFixed(2)})</span>`;
    updateOptionSummary();
  } catch (e) {
    showToast('Could not validate voucher.', 'error');
  }
}

async function handlePurchaseSelected() {
  if (!currentUser) {
    showToast('Please sign in to make a purchase!', 'error');
    setTimeout(() => { window.location.href = '/login'; }, 1000);
    return;
  }

  if (!selectedOption) {
    showToast('Select a duration option.', 'error');
    return;
  }

  const price = activeModalVoucher ? parseFloat(activeModalVoucher.final_price) : parseFloat(selectedOption.price);
  if (currentUser.balance < price) {
    const diff = price - currentUser.balance;
    closeOptionsModal();
    openDepositModal(Math.ceil(diff));
    showToast(`Insufficient credits! You need ₱${diff.toFixed(2)} more.`, 'error');
    return;
  }

  const buyBtn = document.getElementById('btn-buy-option');
  if (buyBtn) {
    buyBtn.disabled = true;
    buyBtn.innerText = 'Delivering key...';
  }

  try {
    const payload = { product_id: selectedOption.id };
    if (activeModalVoucher && activeModalVoucher.code) {
      payload.voucher_code = activeModalVoucher.code;
    }
    const res = await fetch('/api/purchase', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Purchase failed', 'error');
      if (buyBtn) {
        buyBtn.disabled = false;
        buyBtn.innerText = `PURCHASE FOR ₱${price.toFixed(2)}`;
      }
      return;
    }

    currentUser.balance = data.new_balance;
    const navCoin = document.getElementById('nav-coin-val');
    if (navCoin) navCoin.innerText = parseFloat(data.new_balance).toFixed(2);

    closeOptionsModal();
    showKeyModal(data);
  } catch (err) {
    showToast('Network error during purchase.', 'error');
    if (buyBtn) {
      buyBtn.disabled = false;
      buyBtn.innerText = `PURCHASE FOR ₱${price.toFixed(2)}`;
    }
  }
}

function showKeyModal(data) {
  const modal = document.getElementById('key-delivery-modal');
  if (!modal) return;
  document.getElementById('delivered-key-tier').innerText = data.product_name;
  document.getElementById('delivered-key-text').innerText = data.license_key;
  document.getElementById('delivered-key-order').innerText = `Order ID: ${data.order_id}`;
  modal.classList.add('active');
}

function closeKeyModal() {
  const modal = document.getElementById('key-delivery-modal');
  if (modal) modal.classList.remove('active');
}

async function loadDashboardStats() {
  try {
    const res = await fetch('/api/dashboard/stats');
    if (res.status === 401) {
      window.location.href = '/login';
      return;
    }

    const data = await res.json();

    const userEl = document.getElementById('dash-welcome-user');
    if (userEl) userEl.innerText = data.username;

    const balEl = document.getElementById('dash-balance-val');
    if (balEl) balEl.innerText = parseFloat(data.balance).toFixed(2);

    const totalKeysEl = document.getElementById('dash-total-keys-val');
    if (totalKeysEl) totalKeysEl.innerText = data.total_keys !== undefined ? data.total_keys : '0';

    const registeredUsersEl = document.getElementById('stat-registered-users');
    if (registeredUsersEl) registeredUsersEl.innerText = Number(data.registered_users || 0).toLocaleString();

    const totalOrdersEl = document.getElementById('stat-total-orders');
    if (totalOrdersEl) {
      const oCount = data.global_orders !== undefined ? data.global_orders : data.total_orders || 0;
      totalOrdersEl.innerText = Number(oCount).toLocaleString();
    }

    const totalProductsEl = document.getElementById('stat-total-products');
    if (totalProductsEl) totalProductsEl.innerText = data.total_products !== undefined ? data.total_products : '1';

    const refPctEl = document.getElementById('dash-ref-percent');
    if (refPctEl && data.referral_percent !== undefined) refPctEl.innerText = `${data.referral_percent}%`;

    const refCodeEl = document.getElementById('dash-ref-code');
    if (refCodeEl && data.referral_code) refCodeEl.innerText = data.referral_code;

    const refEarnedEl = document.getElementById('dash-ref-earned');
    if (refEarnedEl && data.referral_earnings !== undefined) {
      refEarnedEl.innerText = `₱${parseFloat(data.referral_earnings || 0).toFixed(2)}`;
    }

    loadFeaturedProducts();
    renderRecentOrders(data.recent_orders || []);
    renderRecentTransactions(data.recent_transactions || []);
  } catch (err) {
    console.error('Dashboard load error:', err);
  }
}

async function loadFeaturedProducts() {
  const container = document.getElementById('featured-products-grid');
  if (!container) return;

  try {
    const res = await fetch('/api/catalog');
    const data = await res.json();
    const items = data.catalog || [];

    if (items.length === 0) {
      container.innerHTML = '<div class="empty-state" style="grid-column: 1 / -1;"><p>No featured products available.</p></div>';
      return;
    }

    container.innerHTML = items.map((item, idx) => `
      <div class="featured-prod-card tilt-3d unfold-in delay-${(idx % 4) + 1}" data-tilt-max="6" onclick="window.location.href='/product/${item.id}'">
        <div class="tilt-glare"></div>
        <div class="featured-thumb-wrap">
          <img src="${escapeHtml(item.image_url)}" alt="${escapeHtml(item.title)}" class="featured-thumb-img" onerror="this.src='/static/images/product1.jpg'">
          <div class="featured-badge-stock">
            <span class="stock-live-dot"></span> STOCK
          </div>
          <div class="featured-badge-platform">${escapeHtml(item.platform || 'ANDROID')}</div>
        </div>

        <div class="featured-card-info">
          <h3 class="featured-card-title">${escapeHtml(item.title)}</h3>
          <div class="card-feature-pills">
            <span class="tech-tag-pill active">185 FPS</span>
            <span class="tech-tag-pill active">AIMBOT</span>
            <span class="tech-tag-pill">ESP</span>
            <span class="tech-tag-pill">RADAR</span>
            <span class="tech-tag-pill">STREAM PROOF</span>
          </div>
          <div class="featured-card-price"><span class="price-starts-label">STARTS AT</span> PHP ${parseFloat(item.min_price || 70).toFixed(2)}</div>
          <a href="/product/${item.id}" class="btn-featured-buy" onclick="event.stopPropagation();">
            <i class="fa-solid fa-bolt"></i> BUY KEY
          </a>
        </div>
      </div>
    `).join('');
    bind3DTiltCards();
  } catch (err) {
    console.error('Featured products error:', err);
  }
}

function renderRecentOrders(orders) {
  const container = document.getElementById('recent-orders-box');
  if (!container) return;

  if (orders.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <svg class="empty-cart-icon" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M2.25 3h1.386c.51 0 .955.343 1.087.835l.383 1.437M7.5 14.25a3 3 0 0 0-3 3h15.75m-12.75-3h11.218c1.121-2.3 2.1-4.684 2.924-7.138a60.114 60.114 0 0 0-16.536-1.84M7.5 14.25 5.106 5.272M6 20.25a.75.75 0 1 1-1.5 0 .75.75 0 0 1 1.5 0Zm12.75 0a.75.75 0 1 1-1.5 0 .75.75 0 0 1 1.5 0Z"/></svg>
        <p>No orders yet. <a href="/products">Browse products →</a></p>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div class="table-wrap">
      <table class="dash-table">
        <thead>
          <tr>
            <th>Product Tier</th>
            <th>License Key</th>
            <th>Price</th>
            <th>Order Date</th>
          </tr>
        </thead>
        <tbody>
          ${orders.map(o => `
            <tr>
              <td style="font-weight: 700; color: #fff;">
                ${escapeHtml(o.product_name)}
                ${o.voucher_code ? `<span class="chip success" style="margin-left:6px; font-size:0.65rem;">${escapeHtml(o.voucher_code)}</span>` : ''}
              </td>
              <td>
                <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                  <span style="font-family: var(--font-mono); color: var(--accent-2); font-size: 0.85rem;">${escapeHtml(o.license_key)}</span>
                  <button class="btn btn-sm btn-orange-outline" style="padding: 2px 8px; font-size: 0.7rem;" onclick="copyText('${escapeHtml(o.license_key)}')">Copy</button>
                  <a href="https://t.me/ovkfiles" target="_blank" class="btn btn-sm" style="padding: 2px 8px; font-size: 0.7rem; background: rgba(34, 211, 238, 0.12); border: 1px solid rgba(34, 211, 238, 0.3); color: var(--accent-2); text-decoration: none; border-radius: 6px;"><i class="fa-solid fa-download"></i> Files</a>
                </div>
              </td>
              <td style="font-family: var(--font-mono); font-weight: 700; color: var(--text-white);">₱${parseFloat(o.price).toFixed(2)}</td>
              <td style="color: var(--text-muted); font-size: 0.82rem;">${new Date(o.created_at).toLocaleDateString()}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

function renderRecentTransactions(txs) {
  const container = document.getElementById('recent-tx-box');
  if (!container) return;

  if (txs.length === 0) {
    container.innerHTML = `<div class="empty-state"><p style="color: var(--text-dark);">No transactions recorded yet.</p></div>`;
    return;
  }

  container.innerHTML = `
    <div class="table-wrap">
      <table class="dash-table">
        <thead>
          <tr>
            <th>Type</th>
            <th>Reference</th>
            <th>Amount</th>
            <th>Status</th>
            <th>Date</th>
          </tr>
        </thead>
        <tbody>
          ${txs.map(t => {
            const isRef = t.type === 'referral_bonus';
            const isCredit = isRef || t.type === 'deposit' || (t.type === 'admin_adjustment' && parseFloat(t.amount) >= 0);
            const color = isRef ? 'var(--success)' : (isCredit ? 'var(--accent-2)' : 'var(--warning)');
            const sign = isCredit ? '+' : '-';
            const typeLabel = isRef ? 'Referral bonus' : String(t.type || '').replace(/_/g, ' ');
            return `
              <tr>
                <td style="text-transform: uppercase; font-weight: 700; font-size: 0.75rem; color: ${color};">${escapeHtml(typeLabel)}</td>
                <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(t.reference_id)}</td>
                <td style="font-family: var(--font-mono); font-weight: 700; color: ${color};">${sign}₱${Math.abs(parseFloat(t.amount)).toFixed(2)}</td>
                <td><span class="chip ${t.status === 'completed' ? 'success' : 'warn'}" style="font-size: 0.68rem; text-transform: uppercase;">${escapeHtml(t.status)}</span></td>
                <td style="color: var(--text-muted); font-size: 0.82rem;">${new Date(t.created_at).toLocaleString()}</td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    </div>
  `;
}

const ALLOWED_DEPOSIT_PRESETS = [70, 100, 150, 200, 250, 300, 320, 500, 700, 1000];

function openDepositModal(suggestedAmount = null) {
  if (!currentUser) {
    window.location.href = '/login';
    return;
  }
  const modal = document.getElementById('deposit-modal');
  if (!modal) return;

  const input = document.getElementById('deposit-amt-input');
  if (suggestedAmount) {
    selectedDepositAmount = ALLOWED_DEPOSIT_PRESETS.find(p => p >= suggestedAmount) || 1000;
  } else if (!ALLOWED_DEPOSIT_PRESETS.includes(selectedDepositAmount)) {
    selectedDepositAmount = 100;
  }

  if (input) input.value = selectedDepositAmount;
  highlightPreset(selectedDepositAmount);
  modal.classList.add('active');
}

function closeDepositModal() {
  const modal = document.getElementById('deposit-modal');
  if (modal) modal.classList.remove('active');
}

function selectDepositPreset(amt) {
  selectedDepositAmount = amt;
  const input = document.getElementById('deposit-amt-input');
  if (input) input.value = amt;
  highlightPreset(amt);
}

function highlightPreset(amt) {
  document.querySelectorAll('.preset-chip').forEach(btn => {
    btn.classList.toggle('active', parseInt(btn.dataset.amount, 10) === parseInt(amt, 10));
  });
}

async function proceedPaymongoCheckout() {
  const input = document.getElementById('deposit-amt-input');
  const amount = parseFloat(input ? input.value : selectedDepositAmount);

  if (isNaN(amount) || amount < 20) {
    showToast('Minimum deposit is ₱20.00', 'error');
    return;
  }

  const btn = document.getElementById('btn-paymongo-checkout');
  if (btn) {
    btn.disabled = true;
    btn.innerText = 'Connecting to PayMongo...';
  }

  try {
    const res = await fetch('/api/wallet/create-checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount })
    });

    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Failed to initialize PayMongo', 'error');
      return;
    }

    if (data.demo_mode) {
      showToast(data.message, 'info');
      return;
    }

    if (data.session_id) {
      localStorage.setItem('ovk_pending_checkout', data.session_id);
    }

    if (data.checkout_url) {
      showToast('Redirecting to PayMongo secure checkout...', 'success');
      setTimeout(() => { window.location.href = data.checkout_url; }, 600);
    }
  } catch (err) {
    showToast('Could not reach payment service.', 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="fa-solid fa-credit-card"></i> Deposit via PayMongo (GCash / Maya)';
    }
  }
}

function setupEventListeners() {
  document.querySelectorAll('.preset-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      selectDepositPreset(parseInt(chip.dataset.amount, 10));
    });
  });

  const amtInput = document.getElementById('deposit-amt-input');
  if (amtInput) {
    amtInput.addEventListener('input', (e) => {
      selectedDepositAmount = parseFloat(e.target.value) || 0;
      highlightPreset(selectedDepositAmount);
    });
  }
}

function copyDeliveredKey() {
  const el = document.getElementById('delivered-key-text');
  if (el) copyText(el.innerText);
}

function copyText(text) {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied to clipboard!', 'success');
  }).catch(() => {
    showToast('Failed to copy', 'error');
  });
}

async function copyReferralLink() {
  let code = currentUser && currentUser.referral_code;
  if (!code) {
    try {
      const r = await fetch('/api/referrals');
      if (r.ok) {
        const d = await r.json();
        code = d.code;
        if (currentUser) currentUser.referral_code = code;
      }
    } catch (e) {}
  }
  const refLink = `${window.location.origin}/login?ref=${encodeURIComponent(code || '')}`;
  copyText(refLink);
}

async function logoutUser() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
    showToast('Signed out.', 'info');
    setTimeout(() => { window.location.href = '/login'; }, 400);
  } catch (err) {
    window.location.reload();
  }
}

function showToast(msg, type = 'info') {
  let box = document.getElementById('toast-container');
  if (!box) {
    box = document.createElement('div');
    box.id = 'toast-container';
    box.className = 'toast-box';
    document.body.appendChild(box);
  }

  const toast = document.createElement('div');
  toast.className = `toast-msg ${type}`;
  if (String(msg).toLowerCase().includes('loading')) {
    toast.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin" style="color: var(--accent); margin-right: 8px;"></i><span>${escapeHtml(msg)}</span>`;
  } else {
    toast.innerText = msg;
  }
  toast.style.animation = 'toastSlideIn 0.24s cubic-bezier(0.16, 1, 0.3, 1) forwards';
  box.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    toast.style.transition = 'all 0.25s ease';
    setTimeout(() => toast.remove(), 250);
  }, 3200);
}

document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.shiftKey && (e.key === 'A' || e.key === 'a')) {
    e.preventDefault();
    window.location.href = '/admin';
  }
  if (e.key === 'Escape') {
    closeDepositModal();
    closeSupportModal();
    closePasswordModal();
    closeOptionsModal();
    closeImageLightbox();
  }
});

let logoClickCount = 0;
let logoClickTimer = null;
document.addEventListener('DOMContentLoaded', () => {
  const brandLogo = document.querySelector('.brand-logo');
  if (brandLogo) {
    brandLogo.addEventListener('click', (e) => {
      logoClickCount++;
      clearTimeout(logoClickTimer);
      if (logoClickCount >= 5) {
        e.preventDefault();
        logoClickCount = 0;
        window.location.href = '/admin';
      } else {
        logoClickTimer = setTimeout(() => { logoClickCount = 0; }, 1200);
      }
    });
  }
});

const AVAILABLE_FONTS = [
  { id: 'font-inter', name: 'Inter Precision', desc: 'Clean Default' },
  { id: 'font-space', name: 'Space Grotesk', desc: 'Display Sans' },
  { id: 'font-jakarta', name: 'Jakarta Crisp', desc: 'Minimalist' },
  { id: 'font-rajdhani', name: 'JetBrains Mono', desc: 'Monospace' }
];

function applySavedFont() {
  const saved = localStorage.getItem('ovk_active_font') || 'font-inter';
  document.body.className = document.body.className.replace(/\bfont-\w+\b/g, '').trim();
  document.body.classList.add(saved);
}

function selectFont(fontId) {
  localStorage.setItem('ovk_active_font', fontId);
  applySavedFont();
  const menu = document.getElementById('font-picker-dropdown');
  if (menu) menu.classList.remove('show');
  renderFontPickerItems();
}

function toggleFontPicker(e) {
  if (e) e.stopPropagation();
  const menu = document.getElementById('font-picker-dropdown');
  if (menu) menu.classList.toggle('show');
}

function renderFontPickerItems() {
  const list = document.getElementById('font-picker-list');
  if (!list) return;
  const current = localStorage.getItem('ovk_active_font') || 'font-inter';
  list.innerHTML = AVAILABLE_FONTS.map(f => `
    <div class="font-picker-item ${f.id === current ? 'active' : ''}" onclick="selectFont('${f.id}')">
      <div>
        <div style="font-weight: 700;">${escapeHtml(f.name)}</div>
        <div style="font-size: 0.68rem; color: var(--text-dark);">${escapeHtml(f.desc)}</div>
      </div>
      ${f.id === current ? '<i class="fa-solid fa-check" style="font-size: 0.75rem;"></i>' : ''}
    </div>
  `).join('');
}

document.addEventListener('click', (e) => {
  const menu = document.getElementById('font-picker-dropdown');
  const btn = document.getElementById('font-picker-btn');
  if (menu && menu.classList.contains('show')) {
    if (!menu.contains(e.target) && e.target !== btn && (!btn || !btn.contains(e.target))) {
      menu.classList.remove('show');
    }
  }
});

applySavedFont();

function openSupportModal() {
  const modal = document.getElementById('support-modal');
  if (modal) modal.classList.add('active');
  else window.open('https://t.me/kovalucy', '_blank');
}

function closeSupportModal() {
  const modal = document.getElementById('support-modal');
  if (modal) modal.classList.remove('active');
}

function toggleFaqItem(itemEl) {
  if (!itemEl) return;
  const wasOpen = itemEl.classList.contains('open');
  document.querySelectorAll('.support-faq-item').forEach(el => el.classList.remove('open'));
  if (!wasOpen) itemEl.classList.add('open');
}

// 60fps Spring-Interpolated 3D Tilt & Specular Glare Engine
const _tiltItems = new Map();
let _tiltRafRunning = false;

function _stepTiltLoop() {
  let activeAny = false;
  _tiltItems.forEach((st, el) => {
    st.rx += (st.trx - st.rx) * 0.12;
    st.ry += (st.try - st.ry) * 0.12;
    st.lift += (st.tlift - st.lift) * 0.14;

    if (Math.abs(st.trx - st.rx) > 0.01 || Math.abs(st.try - st.ry) > 0.01 || Math.abs(st.tlift - st.lift) > 0.02 || st.hover) {
      activeAny = true;
      el.style.transform = `perspective(1100px) rotateX(${st.rx.toFixed(2)}deg) rotateY(${st.ry.toFixed(2)}deg) translateY(${st.lift.toFixed(2)}px)`;
    } else if (st.rx !== 0 || st.ry !== 0 || st.lift !== 0) {
      st.rx = 0; st.ry = 0; st.lift = 0;
      el.style.transform = '';
    }
  });

  if (activeAny) {
    requestAnimationFrame(_stepTiltLoop);
  } else {
    _tiltRafRunning = false;
  }
}

function _ensureTiltLoop() {
  if (!_tiltRafRunning) {
    _tiltRafRunning = true;
    requestAnimationFrame(_stepTiltLoop);
  }
}

function bind3DTiltCards() {
  if (window.matchMedia && !window.matchMedia('(pointer: fine)').matches) return;
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  document.querySelectorAll('.tilt-3d, [data-tilt-max]').forEach(el => {
    if (_tiltItems.has(el)) return;
    if (!el.querySelector(':scope > .tilt-glare')) {
      const glare = document.createElement('div');
      glare.className = 'tilt-glare';
      el.insertBefore(glare, el.firstChild);
    }
    const maxDeg = parseFloat(el.dataset.tiltMax || '5.5');
    const liftPx = parseFloat(el.dataset.tiltLift || '-4');
    const state = { rx: 0, ry: 0, lift: 0, trx: 0, try: 0, tlift: 0, hover: false };
    _tiltItems.set(el, state);

    el.addEventListener('pointerenter', () => {
      state.hover = true;
      state.tlift = liftPx;
      el.style.setProperty('--go', '1');
      _ensureTiltLoop();
    });

    el.addEventListener('pointermove', (e) => {
      const rect = el.getBoundingClientRect();
      if (!rect.width || !rect.height) return;
      const px = (e.clientX - rect.left) / rect.width;
      const py = (e.clientY - rect.top) / rect.height;
      state.try = (px - 0.5) * (maxDeg * 2);
      state.trx = (0.5 - py) * (maxDeg * 2);
      el.style.setProperty('--gx', `${(px * 100).toFixed(1)}%`);
      el.style.setProperty('--gy', `${(py * 100).toFixed(1)}%`);
      _ensureTiltLoop();
    });

    el.addEventListener('pointerleave', () => {
      state.hover = false;
      state.trx = 0;
      state.try = 0;
      state.tlift = 0;
      el.style.setProperty('--go', '0');
      _ensureTiltLoop();
    });
  });
}

document.addEventListener('DOMContentLoaded', () => {
  bind3DTiltCards();
});
