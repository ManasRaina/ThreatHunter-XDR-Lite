const STAGES = ['ingest', 'enrich', 'score', 'rules'];

const STAGE_LABELS = {
    ingest: '① Collect',
    enrich: '② Enrich',
    score: '③ Score',
    rules: '④ Generate Rules',
    complete: '✅ Complete',
    error: '❌ Error',
    idle: '— Idle',
};

let pollInterval = null;

function setBadge(stageId, status) {
    const badge = document.getElementById('badge-' + stageId);
    const card = document.getElementById('stage-' + stageId);
    if (!badge || !card) return;

    const map = {
        success: ['bg-success', 'Success'],
        running: ['bg-warning', 'Running…'],
        error: ['bg-danger', 'Error'],
        pending: ['bg-secondary', 'Pending'],
        idle: ['bg-secondary', 'Idle'],
    };
    const [cls, label] = map[status] || ['bg-secondary', status];
    badge.className = 'badge mt-1 stage-badge ' + cls;
    badge.textContent = label;
    card.classList.toggle('border-warning', status === 'running');
    card.classList.toggle('border-success', status === 'success');
    card.classList.toggle('border-danger', status === 'error');
}

async function loadStatus() {
    const res = await fetch('/api/v1/pipeline/status');
    const data = await res.json();

    const stage = data.stage || 'idle';
    const status = data.status || 'idle';

    // Reset all to pending first
    STAGES.forEach(s => setBadge(s, 'pending'));

    if (stage === 'idle') {
        STAGES.forEach(s => setBadge(s, 'idle'));
        return;
    }

    const idx = STAGES.indexOf(stage);

    if (status === 'error') {
        STAGES.slice(0, idx).forEach(s => setBadge(s, 'success'));
        setBadge(stage, 'error');
    } else if (stage === 'complete' || status === 'success') {
        STAGES.forEach(s => setBadge(s, 'success'));
    } else {
        STAGES.slice(0, idx).forEach(s => setBadge(s, 'success'));
        setBadge(stage, 'running');
    }
}

async function loadHistory() {
    const res = await fetch('/api/v1/pipeline/history');
    const rows = await res.json();
    const tbody = document.getElementById('historyBody');

    if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-3">No pipeline runs yet.</td></tr>';
        return;
    }

    tbody.innerHTML = rows.map(r => {
        const statusBadge = r.status === 'success' ?
            '<span class="badge bg-success">✓ Success</span>' :
            r.status === 'error' ?
            '<span class="badge bg-danger">✗ Error</span>' :
            '<span class="badge bg-warning text-dark">⏳ Running</span>';

        let summary = '';
        try {
            const s = JSON.parse(r.summary_json || '{}');
            const parts = [];
            if (s.enriched) parts.push(`${s.enriched} enriched`);
            if (s.scored) parts.push(`${s.scored} scored`);
            if (s.sigma_rules) parts.push(`${s.sigma_rules} Sigma`);
            if (s.spl_rules) parts.push(`${s.spl_rules} SPL`);
            summary = parts.join(' · ') || '—';
        } catch (_) { summary = '—'; }

        return `<tr>
      <td class="ps-3 font-monospace small">${(r.started_at||'').slice(0,19).replace('T',' ')}</td>
      <td class="font-monospace small">${r.finished_at ? r.finished_at.slice(0,19).replace('T',' ') : '—'}</td>
      <td><span class="badge bg-primary bg-opacity-20 text-primary">${STAGE_LABELS[r.stage] || r.stage}</span></td>
      <td>${statusBadge}</td>
      <td class="text-muted small">${summary}</td>
    </tr>`;
    }).join('');
}

async function triggerPipeline() {
    const btn = document.getElementById('runBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Starting…';

    try {
        const res = await fetch('/api/v1/pipeline/run', { method: 'POST' });
        const data = await res.json();
        showToast('Pipeline started! Stages will update below.', 'success');

        // Poll every 3s
        if (pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(async() => {
            await loadStatus();
            await loadHistory();

            const statusRes = await fetch('/api/v1/pipeline/status');
            const statusData = await statusRes.json();
            if (['complete', 'error', 'idle'].includes(statusData.stage) || ['success', 'error'].includes(statusData.status)) {
                clearInterval(pollInterval);
                btn.disabled = false;
                btn.innerHTML = '<i class="bi bi-play-fill me-1"></i>Run Full Pipeline';
            }
        }, 3000);

    } catch (err) {
        showToast('Failed to start pipeline: ' + err.message, 'error');
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-play-fill me-1"></i>Run Full Pipeline';
    }
}

loadStatus();
loadHistory();