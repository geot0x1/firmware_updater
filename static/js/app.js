// Minimal JS for uploads, polling, and UI updates

const fileInput = document.getElementById('fileInput');
const uploadBtn = document.getElementById('uploadBtn');
const downloadBtn = document.getElementById('downloadBtn');
const downloadsBody = document.getElementById('downloadsBody');
const firmwareListDiv = document.getElementById('firmwareList');

uploadBtn.addEventListener('click', () => fileInput.click());

fileInput.addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const firmwareId = prompt('Enter unique FirmwareID for this file:');
  if (!firmwareId) return alert('Upload cancelled: FirmwareID required.');

  const fd = new FormData();
  fd.append('file', file);
  fd.append('firmwareId', firmwareId);

  try {
    const res = await fetch('/upload', { method: 'POST', body: fd });
    const data = await res.json();
    if (!data.ok) {
      alert('Upload failed: ' + (data.error || 'unknown'));
    } else {
      alert('Uploaded: ' + data.firmwareId + ' (' + data.size + ' bytes)');
      refreshFirmwares();
    }
  } catch (err) {
    alert('Upload error: ' + err.message);
  } finally {
    fileInput.value = '';
  }
});

downloadBtn.addEventListener('click', async () => {
  const list = await fetch('/api/firmwares').then(r => r.json()).catch(() => []);
  if (!list.length) {
    alert('No firmwares stored.');
    return;
  }
  const choices = list.map(x => x.firmwareId).join(', ');
  const id = prompt('Enter FirmwareID to download:\n' + choices);
  if (!id) return;
  window.location.href = '/download/' + encodeURIComponent(id);
});

clearBtn.addEventListener('click', async () => {
  if (confirm('Clear all completed/failed downloads?')) {
    await fetch('/api/downloads_status/clear', { method: 'POST' });
    refreshDownloads();
  }
});

async function refreshDownloads() {
  try {
    const rows = await fetch('/api/downloads_status').then(r => r.json());
    downloadsBody.innerHTML = '';
    rows.forEach(rec => {
      const tr = document.createElement('tr');

      const tdId = document.createElement('td'); tdId.textContent = rec.firmwareId || ''; tr.appendChild(tdId);
      const tdStatus = document.createElement('td'); tdStatus.innerHTML = `<span class="pill">${rec.status || ''}</span>`; tr.appendChild(tdStatus);

      const tdProg = document.createElement('td');
      const prog = document.createElement('div'); prog.className = 'progress';
      const bar = document.createElement('div'); bar.className = 'bar';
      bar.style.width = (rec.progress || 0) + '%';
      prog.appendChild(bar);
      tdProg.appendChild(prog);
      tr.appendChild(tdProg);

      const tdPct = document.createElement('td'); tdPct.textContent = (rec.progress || 0) + '%'; tr.appendChild(tdPct);
      const tdIP = document.createElement('td'); tdIP.textContent = rec.ip || ''; tr.appendChild(tdIP);
      const tdBytes = document.createElement('td'); tdBytes.textContent = (rec.bytes_sent || 0) + ' / ' + (rec.total_bytes || 0); tr.appendChild(tdBytes);
      const tdStart = document.createElement('td'); tdStart.textContent = rec.start_time || ''; tr.appendChild(tdStart);
      const tdConn = document.createElement('td'); tdConn.textContent = rec.connection_id || ''; tr.appendChild(tdConn);

      downloadsBody.appendChild(tr);
    });
  } catch (_) { /* ignore */ }
}

async function refreshFirmwares() {
  try {
    const list = await fetch('/api/firmwares').then(r => r.json());
    if (!list.length) {
      firmwareListDiv.innerHTML = '<span style="color:#6b7280;">No firmwares uploaded yet.</span>';
      return;
    }
    const html = ['<table><thead><tr><th>ID</th><th>Name</th><th>Size</th><th>Action</th></tr></thead><tbody>'];
    list.forEach(x => {
      html.push(`<tr>
        <td>${x.firmwareId}</td>
        <td>${x.original_name || ''}</td>
        <td>${x.size || 0}</td>
        <td><a href="/download/${encodeURIComponent(x.firmwareId)}">Download</a></td>
      </tr>`);
    });
    html.push('</tbody></table>');
    firmwareListDiv.innerHTML = html.join('');
  } catch (_) {
    firmwareListDiv.innerHTML = '<span style="color:#ef4444;">Failed to load firmwares.</span>';
  }
}

setInterval(refreshDownloads, 1500);
refreshDownloads();
refreshFirmwares();
