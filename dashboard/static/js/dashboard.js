const CONF_COLORS = {
    critical: '#dc3545',
    high: '#fd7e14',
    medium: '#0dcaf0',
    low: '#6c757d',
};
const TYPE_COLORS = ['#0d6efd', '#dc3545', '#ffc107', '#0dcaf0', '#6f42c1', '#20c997'];

let typeChart, scoreChart;

async function loadStats() {
    const res = await fetch('/api/v1/stats');
    const data = await res.json();

    const animate = (el, target) => {
        let cur = 0;
        const step = Math.max(1, Math.floor(target / 40));
        const iv = setInterval(() => {
            cur = Math.min(cur + step, target);
            el.textContent = cur.toLocaleString();
            if (cur >= target) clearInterval(iv);
        }, 30);
    };

    animate(document.getElementById('stat-total'), data.total_iocs || 0);
    animate(document.getElementById('stat-highrisk'), data.high_risk || 0);
    animate(document.getElementById('stat-actionable'), data.actionable || 0);
    animate(document.getElementById('stat-rules'), data.total_rules || 0);
}

async function loadTypeChart() {
    const res = await fetch('/api/v1/charts/type-distribution');
    const data = await res.json();
    if (!data.length) return;

    const ctx = document.getElementById('typeChart').getContext('2d');
    if (typeChart) typeChart.destroy();

    typeChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.map(d => d.type.toUpperCase()),
            datasets: [{
                data: data.map(d => d.count),
                backgroundColor: TYPE_COLORS.slice(0, data.length),
                borderWidth: 0,
                hoverOffset: 6,
            }],
        },
        options: {
            plugins: {
                legend: { position: 'bottom', labels: { color: '#adb5bd', boxWidth: 12, padding: 12 } },
            },
            cutout: '65%',
        },
    });
}

async function loadScoreChart() {
    const res = await fetch('/api/v1/charts/score-distribution');
    const data = await res.json();
    if (!data.length) return;

    const ctx = document.getElementById('scoreChart').getContext('2d');
    if (scoreChart) scoreChart.destroy();

    scoreChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.map(d => d.confidence.charAt(0).toUpperCase() + d.confidence.slice(1)),
            datasets: [{
                label: 'IOCs',
                data: data.map(d => d.count),
                backgroundColor: data.map(d => CONF_COLORS[d.confidence] || '#6c757d'),
                borderRadius: 6,
                borderWidth: 0,
            }],
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#adb5bd' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                y: { ticks: { color: '#adb5bd' }, grid: { color: 'rgba(255,255,255,0.05)' } },
            },
        },
    });
}

async function loadActivity() {
    const res = await fetch('/api/v1/activity');
    const events = await res.json();
    const list = document.getElementById('activity-list');

    if (!events.length) {
        list.innerHTML = '<li class="list-group-item text-muted text-center py-3">No activity yet. Run the pipeline.</li>';
        return;
    }

    list.innerHTML = events.map(e => {
        const icon = e.event_type === 'feed' ?
            '<i class="bi bi-rss text-primary me-2"></i>' :
            '<i class="bi bi-diagram-3 text-warning me-2"></i>';
        const label = e.event_type === 'feed' ?
            `${e.source} ingested <strong>${(e.count||0).toLocaleString()}</strong> new IOCs` :
            `Pipeline stage <strong>${e.source}</strong> — ${e.status}`;
        const time = (e.time || '').slice(0, 19).replace('T', ' ');
        const status = e.status === 'success' ?
            '<span class="badge bg-success ms-2">OK</span>' :
            e.status === 'error' ?
            '<span class="badge bg-danger ms-2">Error</span>' :
            '';
        return `<li class="list-group-item bg-transparent border-secondary py-2 d-flex align-items-center">
        ${icon}
        <div class="flex-grow-1">${label}${status}</div>
        <small class="text-muted font-monospace ms-3">${time}</small>
      </li>`;
    }).join('');
}

loadStats();
loadTypeChart();
loadScoreChart();
loadActivity();