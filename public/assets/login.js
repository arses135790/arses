document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = document.getElementById('err'); err.textContent = '';
  try {
    const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: document.getElementById('u').value, password: document.getElementById('p').value }) });
    const j = await r.json().catch(() => ({}));
    if (r.ok) location.href = '/dashboard'; else err.textContent = j.error || 'خطا';
  } catch { err.textContent = 'ارتباط با سرور برقرار نشد'; }
});
