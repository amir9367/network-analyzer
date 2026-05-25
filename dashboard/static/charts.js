"use strict";

const REFRESH_MS = 5000;

// ── chart instances ────────────────────────────────────────────────────────────
let protoChart = null;
let timelineChart = null;

function initCharts() {
  const baseOpts = {
    responsive: true,
    maintainAspectRatio: true,
    plugins: { legend: { labels: { color: "#e2e8f0", font: { size: 11 } } } },
  };

  protoChart = new Chart(document.getElementById("chart-protocols"), {
    type: "doughnut",
    data: { labels: [], datasets: [{ data: [], backgroundColor: ["#4f8ef7","#4ade80","#f7a94f","#f75f5f","#a78bfa"] }] },
    options: { ...baseOpts },
  });

  timelineChart = new Chart(document.getElementById("chart-timeline"), {
    type: "line",
    data: {
      labels: [],
      datasets: [{
        label: "Packets/min", data: [],
        borderColor: "#4f8ef7", backgroundColor: "rgba(79,142,247,.15)",
        fill: true, tension: 0.3, pointRadius: 3,
      }],
    },
    options: {
      ...baseOpts,
      scales: {
        x: { ticks: { color: "#6b7280", maxTicksLimit: 6 }, grid: { color: "#2a2d3e" } },
        y: { ticks: { color: "#6b7280" }, grid: { color: "#2a2d3e" }, beginAtZero: true },
      },
    },
  });
}

// ── fetch helpers ──────────────────────────────────────────────────────────────
async function fetchJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url} → ${r.status}`);
  return r.json();
}

// ── render functions ───────────────────────────────────────────────────────────
function renderProtocols(data) {
  protoChart.data.labels   = data.map(d => d.protocol);
  protoChart.data.datasets[0].data = data.map(d => d.count);
  protoChart.update("none");

  const top = data.reduce((a, b) => (b.count > a.count ? b : a), { count: 0 });
  document.getElementById("stat-proto").textContent = top.protocol || "—";
}

function renderTimeline(data) {
  timelineChart.data.labels = data.map(d => d.minute.slice(11)); // HH:MM
  timelineChart.data.datasets[0].data = data.map(d => d.count);
  timelineChart.update("none");

  const total = data.reduce((s, d) => s + d.count, 0);
  document.getElementById("stat-packets").textContent = total.toLocaleString();
}

function renderTopIPs(data) {
  const tbody = document.getElementById("ip-table");
  tbody.innerHTML = data
    .map((d, i) => `<tr>
      <td style="color:var(--muted)">${i + 1}</td>
      <td style="font-family:monospace">${d.ip}</td>
      <td>${d.count.toLocaleString()}</td>
    </tr>`)
    .join("");
}

function renderAlerts(data) {
  const list = document.getElementById("alert-list");
  document.getElementById("stat-alerts").textContent = data.length;

  list.innerHTML = data
    .map(a => {
      const cls = a.alert_type === "TRAFFIC_SPIKE" ? " spike" : "";
      return `<li class="${cls.trim()}">
        <span class="badge">${a.alert_type}</span>
        <div>
          <div class="detail">${a.src_ip} — ${a.detail}</div>
          <div class="meta">${a.timestamp}</div>
        </div>
      </li>`;
    })
    .join("");
}

// ── main refresh loop ─────────────────────────────────────────────────────────
async function refresh() {
  try {
    const [protocols, timeline, topIPs, alerts] = await Promise.all([
      fetchJSON("/api/protocols"),
      fetchJSON("/api/timeline"),
      fetchJSON("/api/top-ips"),
      fetchJSON("/api/alerts"),
    ]);

    renderProtocols(protocols);
    renderTimeline(timeline);
    renderTopIPs(topIPs);
    renderAlerts(alerts);

    const status = document.getElementById("status");
    status.textContent = `Live · ${new Date().toLocaleTimeString()}`;
    status.className = "live";
  } catch (err) {
    document.getElementById("status").textContent = "Connection lost";
    document.getElementById("status").className = "";
    console.error("Refresh error:", err);
  }
}

// ── bootstrap ──────────────────────────────────────────────────────────────────
initCharts();
refresh();
setInterval(refresh, REFRESH_MS);