/**
 * Threat Intelligence Dashboard
 * Uses existing API endpoints: /dashboard/stats, /rules, /refresh-feeds
 */

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];
const SEVERITY_COLORS = {
    critical: "#dc3545",
    high: "#fd7e14",
    medium: "#0dcaf0",
    low: "#6c757d",
};
const FEED_COLORS = ["#0d6efd", "#dc3545", "#ffc107", "#20c997", "#6610f2", "#fd7e14"];

let severityChart = null;
let feedChart = null;

function updateClock() {
    const el = document.getElementById("live-clock");
    if (el) {
        el.textContent = new Date().toUTCString().replace(" GMT", "") + " UTC";
    }
}

function showToast(message, type = "success") {
    const area = document.getElementById("toast-area");
    const id = "toast-" + Date.now();
    const bg = type === "error" ? "text-bg-danger" : type === "info" ? "text-bg-info" : "text-bg-success";

    area.insertAdjacentHTML(
        "beforeend",
        `<div id="${id}" class="toast align-items-center ${bg} border-0 show" role="alert">
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto"
                        data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
        </div>`
    );

    setTimeout(() => {
        const toast = document.getElementById(id);
        if (toast) toast.remove();
    }, 4500);
}

function setStat(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = Number(value || 0).toLocaleString();
}

function severityBadge(confidence) {
    const level = (confidence || "unknown").toLowerCase();
    return `<span class="badge badge-severity badge-${level}">${level}</span>`;
}

function ruleBadge(ruleType) {
    const type = (ruleType || "").toLowerCase();
    const label = type === "sigma" ? "Sigma" : type === "spl" ? "SPL" : type.toUpperCase();
    const cls = type === "sigma" ? "badge-rule-sigma" : "badge-rule-spl";
    return `<span class="badge ${cls}">${label}</span>`;
}

function truncate(text, max = 40) {
    if (!text) return "—";
    return text.length > max ? text.slice(0, max) + "…" : text;
}

function formatTime(iso) {
    if (!iso) return "—";
    return iso.slice(0, 19).replace("T", " ");
}

async function fetchJson(url, options = {}) {
    const res = await fetch(url, options);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
        throw new Error(data.error || `Request failed (${res.status})`);
    }
    return data;
}

function renderSeverityChart(severityMap) {
    const labels = SEVERITY_ORDER.filter((k) => severityMap[k]);
    const values = labels.map((k) => severityMap[k]);
    const colors = labels.map((k) => SEVERITY_COLORS[k]);

    if (!labels.length) {
        labels.push("No data");
        values.push(0);
        colors.push("#495057");
    }

    const ctx = document.getElementById("severityChart");
    if (!ctx) return;

    if (severityChart) severityChart.destroy();

    severityChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels: labels.map((l) => l.charAt(0).toUpperCase() + l.slice(1)),
            datasets: [{
                label: "IOCs",
                data: values,
                backgroundColor: colors,
                borderRadius: 6,
                borderWidth: 0,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: {
                    ticks: { color: "#adb5bd" },
                    grid: { color: "rgba(255,255,255,0.05)" },
                },
                y: {
                    beginAtZero: true,
                    ticks: { color: "#adb5bd", precision: 0 },
                    grid: { color: "rgba(255,255,255,0.05)" },
                },
            },
        },
    });
}

function renderFeedChart(sources) {
    const labels = sources.map((s) => s.source_feed);
    const values = sources.map((s) => s.count);
    const colors = FEED_COLORS.slice(0, labels.length);

    const ctx = document.getElementById("feedChart");
    if (!ctx) return;

    if (feedChart) feedChart.destroy();

    feedChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels,
            datasets: [{
                data: values.length ? values : [1],
                backgroundColor: values.length ? colors : ["#495057"],
                borderWidth: 0,
                hoverOffset: 6,
            }],
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: "bottom",
                    labels: { color: "#adb5bd", boxWidth: 12, padding: 10 },
                },
            },
            cutout: "62%",
        },
    });
}

function renderRecentThreats(threats) {
    const tbody = document.getElementById("recent-threats-body");
    if (!tbody) return;

    if (!threats || !threats.length) {
        tbody.innerHTML =
            '<tr><td colspan="5" class="text-center text-muted py-4">No threats recorded yet.</td></tr>';
        return;
    }

    tbody.innerHTML = threats
        .map(
            (t) => `<tr>
                <td><span class="ioc-value" title="${t.value}">${truncate(t.value, 36)}</span></td>
                <td><span class="text-uppercase small">${t.type || "—"}</span></td>
                <td>${t.source_feed || "—"}</td>
                <td>${severityBadge(t.confidence)}</td>
                <td>${t.score != null ? t.score : "—"}</td>
            </tr>`
        )
        .join("");
}

function renderLatestRules(rules) {
    const tbody = document.getElementById("latest-rules-body");
    if (!tbody) return;

    if (!rules || !rules.length) {
        tbody.innerHTML =
            '<tr><td colspan="4" class="text-center text-muted py-4">No rules generated yet.</td></tr>';
        return;
    }

    tbody.innerHTML = rules
        .map(
            (r) => `<tr>
                <td title="${r.title}">${truncate(r.title, 42)}</td>
                <td>${ruleBadge(r.rule_type)}</td>
                <td><span class="ioc-value" title="${r.ioc_value || ""}">${truncate(r.ioc_value, 28)}</span></td>
                <td class="text-muted small font-monospace">${formatTime(r.generated_at)}</td>
            </tr>`
        )
        .join("");
}

async function loadDashboard() {
    try {
        const stats = await fetchJson("/dashboard/stats");
        const severity = stats.iocs_by_severity || {};
        const sources = stats.iocs_by_source || [];

        setStat("stat-total", stats.total_iocs);
        setStat("stat-critical", severity.critical || 0);
        setStat("stat-high", severity.high || 0);
        setStat("stat-rules", stats.total_rules);
        setStat("stat-feeds", sources.length);

        renderSeverityChart(severity);
        renderFeedChart(sources);
        renderRecentThreats(stats.recent_threats);
    } catch (err) {
        showToast("Failed to load dashboard stats: " + err.message, "error");
    }

    try {
        const rulesData = await fetchJson("/rules?limit=10");
        renderLatestRules(rulesData.results);
    } catch (err) {
        showToast("Failed to load rules: " + err.message, "error");
    }
}

async function refreshFeeds() {
    const btn = document.getElementById("btn-refresh-feeds");
    if (!btn || btn.disabled) return;

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Refreshing...';

    try {
        const data = await fetchJson("/refresh-feeds", { method: "POST" });
        showToast(data.message || "Feed refresh started.", "info");
        setTimeout(loadDashboard, 3000);
    } catch (err) {
        showToast("Feed refresh failed: " + err.message, "error");
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-arrow-repeat me-1"></i>Refresh Feeds';
    }
}

document.addEventListener("DOMContentLoaded", () => {
    updateClock();
    setInterval(updateClock, 1000);

    document.getElementById("btn-refresh-feeds")?.addEventListener("click", refreshFeeds);

    loadDashboard();
});
