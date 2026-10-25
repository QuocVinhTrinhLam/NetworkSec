(() => {
  const colors = {
    critical: "#ff453a",
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
    resizeDelay: 50,
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

  /**
   * Khởi tạo và đăng ký một biểu đồ Chart.js mới vào danh sách quản lý window.dashboardCharts.
   *
   * @param {HTMLCanvasElement|null} canvas - Phần tử canvas mục tiêu trên DOM.
   * @param {object} config - Cấu hình loại biểu đồ, tập dữ liệu và tùy chọn hiển thị.
   * @returns {void}
   */
  const createChart = (canvas, config) => {
    if (!canvas) return;
    window.dashboardCharts.push(new Chart(canvas, config));
  };

  /**
   * Giải phóng và hủy toàn bộ các phiên biểu đồ Chart.js đang hoạt động.
   *
   * Thao tác này bắt buộc phải thực thi trước khi HTMX hoán đổi innerHTML
   * nhằm gỡ bỏ sạch sẽ các EventListener, ResizeObserver và tránh rò rỉ bộ nhớ
   * (zombie instances) gây lỗi vòng lặp phóng to kích thước canvas.
   *
   * @returns {void}
   */
  const cleanupCharts = () => {
    window.dashboardCharts = window.dashboardCharts || [];
    window.dashboardCharts.forEach((chart) => {
      try {
        chart.destroy();
      } catch (err) {
        // Bỏ qua ngoại lệ nếu canvas đã bị tách khỏi cây DOM trong các chu trình trước
      }
    });
    window.dashboardCharts = [];
  };

  /**
   * Phân tích dữ liệu JSON viễn thông và khởi tạo lại 3 biểu đồ giám sát trên Dashboard.
   *
   * @returns {void}
   */
  window.renderDashboardCharts = () => {
    const node = document.getElementById("dashboard-data");
    if (!node || typeof Chart === "undefined") return;

    let data;
    try {
      data = JSON.parse(node.textContent || "{}");
    } catch {
      return;
    }

    // Bảo đảm dọn dẹp mọi instance cũ trước khi dựng mới trên canvas vừa swap
    cleanupCharts();

    const timeline = Array.isArray(data.timeline) ? data.timeline : [];
    const severity = Array.isArray(data.severity) ? data.severity : [];
    const deviceTypes = Array.isArray(data.device_types) ? data.device_types : [];

    createChart(document.getElementById("timeline-chart"), {
      type: "line",
      data: {
        labels: timeline.length > 0 ? timeline.map((row) => row.label) : ["No activity"],
        datasets: [{
          label: "Alerts",
          data: timeline.length > 0 ? timeline.map((row) => row.value) : [0],
          borderColor: "#00e5ff",
          backgroundColor: "rgba(48, 209, 88, 0.12)",
          borderWidth: 2,
          pointRadius: 4,
          pointHoverRadius: 6,
          pointBackgroundColor: "#121212",
          pointBorderColor: "#00e5ff",
          fill: true,
          tension: 0.35,
        }],
      },
      options: {
        ...baseOptions,
        maintainAspectRatio: false,
        scales: {
          x: axis,
          y: { ...axis, beginAtZero: true, ticks: { ...axis.ticks, precision: 0 } },
        },
      },
    });

    createChart(document.getElementById("severity-chart"), {
      type: "doughnut",
      data: {
        labels: severity.map((row) => row.label),
        datasets: [{
          data: severity.map((row) => row.value),
          backgroundColor: severity.map((row) => colors[row.label] || "#8296aa"),
          borderColor: "#1e1e1e",
          borderWidth: 3,
          hoverOffset: 3,
        }],
      },
      options: {
        ...baseOptions,
        maintainAspectRatio: true,
        aspectRatio: 1,
        cutout: "72%",
      },
    });

    createChart(document.getElementById("device-chart"), {
      type: "bar",
      data: {
        labels: deviceTypes.map((row) => row.label),
        datasets: [{
          label: "Alerts",
          data: deviceTypes.map((row) => row.value),
          backgroundColor: "rgba(50, 215, 75, 0.7)",
          borderColor: "#32d74b",
          borderWidth: 1,
          borderRadius: 4,
          maxBarThickness: 34,
        }],
      },
      options: { ...baseOptions, scales: { x: axis, y: { ...axis, beginAtZero: true, ticks: { ...axis.ticks, precision: 0 } } } },
    });
  };

  /**
   * Cập nhật nhãn thời gian làm mới gần nhất trên thanh tiêu đề SOC Command Center.
   *
   * @returns {void}
   */
  const markRefreshed = () => {
    const status = document.getElementById("last-updated");
    if (status) {
      status.textContent = `Updated ${new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date())}`;
    }
  };

  window.renderDashboardCharts();
  markRefreshed();

  // Dọn dẹp đồ thị cũ TRƯỚC KHI HTMX hoán đổi DOM nhằm tránh rò rỉ bộ nhớ và zombie instances
  document.addEventListener("htmx:beforeSwap", (event) => {
    if (event.target.id === "dashboard-content") {
      cleanupCharts();
    }
  });

  // Khởi tạo đồ thị SAU KHI HTMX hoàn tất swap DOM mới;
  // Sử dụng requestAnimationFrame để đảm bảo trình duyệt đã hoàn tất chu trình tính toán
  // kích thước layout (Reflow) cho các phần tử DOM mới, ngăn chặn kích thước canvas bị 0x0
  document.addEventListener("htmx:afterSwap", (event) => {
    if (event.target.id === "dashboard-content") {
      window.requestAnimationFrame(() => {
        window.renderDashboardCharts();
        markRefreshed();
      });
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
