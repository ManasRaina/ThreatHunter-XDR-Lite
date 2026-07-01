let currentPage = 1;

const CONF_BADGE = {
    critical: 'bg-danger',
    high: 'bg-warning text-dark',
    medium: 'bg-info text-dark',
    low: 'bg-secondary',
};

function getFilters() {
    return {
        search: document.getElementById('searchInput').value.trim(),
        type: document.getElementById('typeFilter').value,
        confidence: document.getElementById('riskFilter').value,
        feed: document.getElementById('feedFilter').value,
    };
}

async function loadIOCs(page = 1) {
    currentPage = page;
    const f = getFilters();
    const params = new URLSearchParams({ page, limit: 50, ...f });

    const tbody = document.getElementById('iocTableBody');
    tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-3">Loading...</td></tr>';

    const res = await fetch('/api/v1/iocs?' + params);
    const data = await res.json();

    if (!data.results.length) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-4">No IOCs found matching your filters.</td></tr>';
        document.getElementById('tableInfo').textContent = '0 results';
        document.getElementById('pagination').innerHTML = '';
        return;
    }

    tbody.innerHTML = data.results.map(r => {
        const conf = r.confidence || 'unscored';
        const badgeClass = CONF_BADGE[conf] || 'bg-secondary';
        const score = r.score != null ? r.score : '—';
        const typeMap = { ip: 'primary', domain: 'info', url: 'warning', md5: 'secondary', sha256: 'secondary' };
        const typeColor = typeMap[r.type] || 'secondary';
        const lastSeen = (r.last_seen || '').slice(0, 10);
        const family = r.malware_family || '—';
        const feed = r.source_feed || '—';
        const shortVal = r.value.length > 50 ? r.value.slice(0, 47) + '...' : r.value;

        return `<tr>
      <td class="ps-3 font-monospace small" title="${r.value}">${shortVal}</td>
      <td><span class="badge bg-${typeColor} bg-opacity-20 text-${typeColor}">${r.type}</span></td>
      <td><span class="badge ${badgeClass}">${conf}</span></td>
      <td class="fw-semibold">${score}</td>
      <td class="text-muted small">${family}</td>
      <td><span class="badge bg-dark border border-secondary">${feed}</span></td>
      <td class="text-muted small font-monospace">${lastSeen}</td>
      <td><a href="/iocs/${r.id}" class="btn btn-xs btn-outline-secondary py-0 px-2">
        <i class="bi bi-arrow-right-short"></i>
      </a></td>
    </tr>`;
    }).join('');

    document.getElementById('tableInfo').textContent =
        `Showing ${data.results.length} of ${data.total.toLocaleString()} IOCs`;

    renderPagination(data.pages, page);
}

function renderPagination(totalPages, currentPg) {
    const pg = document.getElementById('pagination');
    pg.innerHTML = '';
    if (totalPages <= 1) return;

    const makeBtn = (label, page, disabled = false, active = false) => {
        const btn = document.createElement('button');
        btn.className = `btn btn-xs btn-${active ? 'danger' : 'outline-secondary'} py-0 px-2`;
        btn.textContent = label;
        btn.disabled = disabled;
        btn.onclick = () => loadIOCs(page);
        return btn;
    };

    pg.appendChild(makeBtn('‹', currentPg - 1, currentPg === 1));

    const start = Math.max(1, currentPg - 2);
    const end = Math.min(totalPages, currentPg + 2);
    for (let i = start; i <= end; i++) {
        pg.appendChild(makeBtn(i, i, false, i === currentPg));
    }

    pg.appendChild(makeBtn('›', currentPg + 1, currentPg === totalPages));
}

function applyFilters() {
    loadIOCs(1);
}

// Search on Enter
document.getElementById('searchInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') applyFilters();
});

loadIOCs();