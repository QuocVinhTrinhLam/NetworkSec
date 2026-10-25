(() => {
  const colors = {
    critical: "#ff6077",
    high: "#ff9f43",
    medium: "#f5cb5c",
    low: "#56c2ff",
  };
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const axis = {
    ticks: { color: "#8296aa", font: { family: "ui-monospace, SFMono-Regular, Menlo, monospace", size: 11 } },
    grid: { color: "rgba(117, 151, 179, 0.12)", drawBorder: false },
    border: { display: false },
  };

  const baseOptions = {
    responsive: true,
    maintainAspectRatio: false,
    animation: reducedMotion ? false : { duration: 450 },
    interaction: { intersect: false, mode: "index" },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: "#142435",
        borderColor: "#2b4258",
        borderWidth: 1,
        titleColor: "#f4f8fb",
        bodyColor: "#aab9c7",
        padding: 12,
        displayColors: false,
      },
    },
  };

  const createChart = (canvas, config) => {
    if (!canvas) return;
    window.dashboardCharts.push(new Chart(canvas, config));
  };

  window.renderDashboardCharts = () => {
    const node = document.getElementById("dashboard-data");
    if (!node || typeof Chart === "undefined") return;

    const data = JSON.parse(node.textContent);
    window.dashboardCharts = window.dashboardCharts || [];
    window.dashboardCharts.forEach((chart) => chart.destroy());
    window.dashboardCharts = [];

    createChart(document.getElementById("timeline-chart"), {
      type: "line",
      data: {
        labels: data.timeline.map((row) => row.label),
        datasets: [{
          label: "Alerts",
          data: data.timeline.map((row) => row.value),
          borderColor: "#42d7ff",
          backgroundColor: "rgba(66, 215, 255, 0.11)",
          borderWidth: 2,
          pointRadius: 2,
          pointHoverRadius: 5,
          pointBackgroundColor: "#07111c",
          pointBorderColor: "#42d7ff",
          fill: true,
          tension: 0.35,
        }],
      },
      options: { ...baseOptions, scales: { x: axis, y: { ...axis, beginAtZero: true, ticks: { ...axis.ticks, precision: 0 } } } },
    });

    createChart(document.getElementById("severity-chart"), {
      type: "doughnut",
      data: {
        labels: data.severity.map((row) => row.label),
        datasets: [{
          data: data.severity.map((row) => row.value),
          backgroundColor: data.severity.map((row) => colors[row.label] || "#8296aa"),
          borderColor: "#0d1a28",
          borderWidth: 4,
          hoverOffset: 3,
        }],
      },
      options: { ...baseOptions, cutout: "74%" },
    });

    createChart(document.getElementById("device-chart"), {
      type: "bar",
      data: {
        labels: data.device_types.map((row) => row.label),
        datasets: [{
          label: "Alerts",
          data: data.device_types.map((row) => row.value),
          backgroundColor: "rgba(57, 217, 138, 0.7)",
          borderColor: "#39d98a",
          borderWidth: 1,
          borderRadius: 4,
          maxBarThickness: 34,
        }],
      },
      options: { ...baseOptions, scales: { x: axis, y: { ...axis, beginAtZero: true, ticks: { ...axis.ticks, precision: 0 } } } },
    });
  };

  const markRefreshed = () => {
    const status = document.getElementById("last-updated");
    if (status) {
      status.textContent = `Updated ${new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date())}`;
    }
  };

  window.renderDashboardCharts();
  markRefreshed();
  document.addEventListener("htmx:afterSwap", (event) => {
    if (event.target.id === "dashboard-content") {
      window.renderDashboardCharts();
      markRefreshed();
    }
  });

  window.setInterval(() => {
    const root = document.getElementById("dashboard-content");
    const userIsInteracting = root?.contains(document.activeElement) || root?.querySelector("details[open]");
    if (!root || document.hidden || userIsInteracting || root.classList.contains("htmx-request")) return;
    if (typeof htmx !== "undefined") {
      htmx.ajax("GET", "/partials/dashboard", { target: "#dashboard-content", swap: "innerHTML" });
    }
  }, 20_000);
})();
