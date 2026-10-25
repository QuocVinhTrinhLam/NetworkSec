(() => {
  const node = document.getElementById("dashboard-data");
  if (!node || typeof Chart === "undefined") return;
  const data = JSON.parse(node.textContent);
  window.dashboardCharts = window.dashboardCharts || [];
  window.dashboardCharts.forEach((chart) => chart.destroy());
  const common = { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: "#c8d5e6" } } }, scales: { x: { ticks: { color: "#8fa3bd" }, grid: { color: "#243650" } }, y: { beginAtZero: true, ticks: { color: "#8fa3bd" }, grid: { color: "#243650" } } } };
  const make = (id, type, rows, colors) => {
    const canvas = document.getElementById(id); if (!canvas) return;
    window.dashboardCharts.push(new Chart(canvas, { type, data: { labels: rows.map((r) => r.label), datasets: [{ label: "Alerts", data: rows.map((r) => r.value), borderColor: colors, backgroundColor: colors, tension: .3 }] }, options: type === "doughnut" ? { responsive:true, maintainAspectRatio:false, plugins:common.plugins } : common }));
  };
  make("timeline-chart", "line", data.timeline, "#4cc9f0");
  make("severity-chart", "doughnut", data.severity, ["#ff4d6d", "#ff8c42", "#ffd166", "#4cc9f0"]);
  make("device-chart", "bar", data.device_types, "#42d392");
})();
