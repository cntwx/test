const API = 'http://localhost:3000';

function getToken() { return localStorage.getItem('token'); }
function isLoggedIn() { return !!getToken(); }
function getCurrentUser() {
  try { return JSON.parse(localStorage.getItem('user') || 'null'); }
  catch { return null; }
}

async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(API + path, { ...options, headers });
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'เกิดข้อผิดพลาด');
  return data;
}

function doLogout() {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  location.href = 'homepage.html';
}

function updateNav() {
  const el = document.getElementById('nav-actions');
  if (!el) return;
  const user = getCurrentUser();
  if (user) {
    const avHtml = user.avatar
      ? `<img src="${user.avatar}" style="width:32px;height:32px;border-radius:50%;object-fit:cover;border:2px solid var(--gold)">`
      : `<div style="width:32px;height:32px;border-radius:50%;background:var(--gold);display:flex;align-items:center;justify-content:center;color:var(--dark);font-weight:700;font-size:0.85rem">${user.fname[0]}</div>`;
    el.innerHTML = `
      <div style="display:flex;align-items:center;gap:0.5rem;color:white">
        ${avHtml}
        <span style="font-size:0.9rem">${user.fname} ${user.lname}</span>
      </div>
      ${user.role === 'admin' ? `<a href="admin.html" class="btn btn-sm btn-outline">👩🏻‍💻 Admin</a>` : ''}
      <button class="btn btn-outline btn-sm" onclick="doLogout()">ออกจากระบบ</button>
    `;
  } else {
    el.innerHTML = `
      <a href="login.html" class="btn btn-outline">เข้าสู่ระบบ</a>
      <a href="login.html" class="btn btn-gold" onclick="sessionStorage.setItem('showRegister','1')">สมัครสมาชิก</a>
    `;
  }
}

function showToast(msg, type = 'success') {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.className = `toast toast-${type} show`;
  setTimeout(() => t.classList.remove('show'), 2500);
}

function renderStars(val) {
  let s = '';
  for (let i = 1; i <= 5; i++) {
    if (val >= i) s += '★';
    else if (val >= i - 0.5) s += '½';
    else s += '☆';
  }
  return s;
}

function timeAgo(dateStr) {
  const date = new Date(dateStr);
  // เพิ่มเวลาไทย +7 ชั่วโมง
  const thaiTime = new Date(date.getTime() + (7 * 60 * 60 * 1000));

  const diff = Date.now() - thaiTime;
  const m = Math.floor(diff / 60000);

  if (m < 1) return 'เพิ่งเมื่อกี้';
  if (m < 60) return `${m} นาทีที่แล้ว`;

  const h = Math.floor(m / 60);
  if (h < 24) return `${h} ชั่วโมงที่แล้ว`;

  const d = Math.floor(h / 24);
  if (d < 30) return `${d} วันที่แล้ว`;

  return thaiTime.toLocaleDateString('th-TH');
}

