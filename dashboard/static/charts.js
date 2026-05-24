let timelineChart, protocolChart;

async function fetchAndRender() {
  const res  = await fetch("/api/stats");
  const data = await res.json();

  document.getElementById("summary").textContent =
    `Total packets captured: ${data.total_packets}`;

  // --- Timeline chart ---
  const tlLabels = data.timeline.map(([t]) => t.slice(11));  // HH:MM
  const tlValues = data.timeline.map(([, v]) => v);

  if (!timelineChart) {
    timelineChart = new Chart(document.getElementById("timelineChart"), {
      type: "line",
      data: {
        labels: tlLabels,
        datasets: [{ label: "Bytes/min", data: tlValues,
          borderColor: "#58a6ff", fill: true, backgroundColor: "rgba(88,166,255,0.1)" }]
      },
      options: { plugins: { legend: { labels: { color: "#c9d1d9" } } },
                 scales: { x: { ticks: { color: "#8b949e" } }, y: { ticks: { color: "#8b949e" } } } }
    });
  } else {
    timelineChart.data.labels   = tlLabels;
    timelineChart.data.datasets[0].data = tlValues;
    timelineChart.update();
  }

  // --- Protocol pie chart ---
  const proLabels = Object.keys(data.protocols);
  const proValues = Object.values(data.protocols);

  if (!protocolChart) {
    protocolChart = new Chart(document.getElementById("protocolChart"), {
      type: "doughnut",
      data: {
        labels: proLabels,
        datasets: [{ data: proValues,
          backgroundColor: ["#58a6ff","#3fb950","#d29922","#f85149"] }]
      },
      options: { plugins: { legend: { labels: { color: "#c9d1d9" } } } }
    });
  } else {
    protocolChart.data.labels   = proLabels;
    protocolChart.data.datasets[0].data = proValues;
    protocolChart.update();
  }

  // --- Alerts ---
  const alertList = document.getElementById("alertList");
  alertList.innerHTML = data.alerts.length === 0
    ? "<p>No alerts yet.</p>"
    : data.alerts.map(a =>
        `<div class="alert-item">
          <strong>${a.alert_type}</strong> — ${a.src_ip}
          <br><span>${a.detail} &nbsp;|&nbsp; ${a.timestamp}</span>
        </div>`
      ).join("");
}

fetchAndRender();
setInterval(fetchAndRender, 5000);  // Auto-refresh every 5 seconds