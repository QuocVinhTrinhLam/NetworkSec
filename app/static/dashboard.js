(() => {
  const colors = {
    critical: "#ff453a",
    high: "#ff9f43",
    medium: "#f5cb5c",
    low: "#56c2ff",
  };
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Màu sắc nhãn trục được tối ưu tương phản (#9cb2c6 > 8:1 đối với nền panel tối)
  // đáp ứng chuẩn tiếp cận WCAG 2.1 AA
  const axis = {
    ticks: {
      color: "#9cb2c6",
      font: { family: "ui-monospace, SFMono-Regular, Menlo, monospace", size: 11 },
    },
    grid: { color: "rgba(117, 151, 179, 0.12)", drawBorder: false },
    border: { display: false },
  };

  const baseOptions = {
    responsive: true,
    maintainAspectRatio: false,
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
    window.dashboardCharts = window.dashboardCharts || [];
    window.dashboardCharts.push(new Chart(canvas, config));
  };

  /**
   * Giải phóng và hủy toàn bộ các phiên biểu đồ Chart.js đang hoạt động.
   *
   * Thao tác này dọn dẹp bộ nhớ và EventListeners trước khi khởi tạo lại trên canvas mới,
   * ngăn chặn rò rỉ bộ nhớ (memory leaks) hoặc xung đột ResizeObserver.
   *
   * @returns {void}
   */
  const cleanupCharts = () => {
    window.dashboardCharts = window.dashboardCharts || [];
    window.dashboardCharts.forEach((chart) => {
      try {
        chart.destroy();
      } catch (err) {
        // Bỏ qua nếu canvas đã bị tách khỏi DOM
      }
    });
    window.dashboardCharts = [];
  };

  /**
   * Phân tích dữ liệu JSON và khởi tạo/cập nhật 3 biểu đồ giám sát trên Dashboard.
   *
   * @param {boolean} [isRefresh=false] - Cờ xác định xem thao tác render có bắt nguồn từ sự kiện làm mới (refresh/swap) hay không.
   * Khi làm mới, animation tắt (hoặc tức thì) để tránh việc biểu đồ bị xóa trắng 2-3s trước mắt người dùng.
   * @returns {void}
   */
  window.renderDashboardCharts = (isRefresh = false) => {
    const node = document.getElementById("dashboard-data");
    if (!node || typeof Chart === "undefined") return;

    let data;
    try {
      data = JSON.parse(node.textContent || "{}");
    } catch {
      return;
    }

    // Dọn dẹp instances cũ trước khi vẽ lên canvas mới
    cleanupCharts();

    const timeline = Array.isArray(data.timeline) ? data.timeline : [];
    const severity = Array.isArray(data.severity) ? data.severity : [];
    const deviceTypes = Array.isArray(data.device_types) ? data.device_types : [];

    const animConfig = (isRefresh || reducedMotion) ? false : { duration: 350 };

    // 1. Biểu đồ đường Alert Activity (24-hour window)
    const timelineCanvas = document.getElementById("timeline-chart");
    if (timelineCanvas) {
      createChart(timelineCanvas, {
        type: "line",
        data: {
          labels: timeline.length > 0 ? timeline.map((row) => row.label) : ["No activity"],
          datasets: [{
            label: "Alerts",
            data: timeline.length > 0 ? timeline.map((row) => row.value) : [0],
            borderColor: "#00e5ff",
            backgroundColor: "rgba(0, 229, 255, 0.12)",
            borderWidth: 2,
            pointRadius: timeline.length > 12 ? 3 : 4,
            pointHoverRadius: 6,
            pointBackgroundColor: "#080d14",
            pointBorderColor: "#00e5ff",
            fill: true,
            tension: 0.3,
          }],
        },
        options: {
          ...baseOptions,
          animation: animConfig,
          maintainAspectRatio: false,
          layout: {
            padding: { left: 8, right: 16, top: 12, bottom: 4 },
          },
          scales: {
            x: {
              ...axis,
              offset: true, // Thêm offset 2 đầu giúp điểm dữ liệu đầu tiên không đè lên trục Y
              ticks: {
                ...axis.ticks,
                maxTicksLimit: 8, // Giới hạn số mốc giờ hiển thị để thoáng mắt trên 24 buckets
                maxRotation: 0,
                callback: function (val) {
                  const label = this.getLabelForValue(val);
                  if (typeof label === "string" && label.length >= 16) {
                    return label.slice(11, 16); // Hiển thị "HH:00"
                  }
                  return label;
                },
              },
            },
            y: {
              ...axis,
              beginAtZero: true,
              ticks: {
                ...axis.ticks,
                padding: 10, // Đệm cách trục Y để tooltip và điểm không che nhãn số
                precision: 0,
              },
            },
          },
        },
      });
    }

    // 2. Biểu đồ tròn Severity Mix (Donut chart)
    const severityCanvas = document.getElementById("severity-chart");
    if (severityCanvas) {
      createChart(severityCanvas, {
        type: "doughnut",
        data: {
          labels: severity.map((row) => row.label),
          datasets: [{
            data: severity.map((row) => row.value),
            backgroundColor: severity.map((row) => colors[row.label] || "#8296aa"),
            borderColor: "#101721",
            borderWidth: 2,
            hoverOffset: 4,
          }],
        },
        options: {
          ...baseOptions,
          animation: animConfig,
          responsive: true,
          maintainAspectRatio: true, // Giữ tỷ lệ hình tròn 1:1 chuẩn, triệt tiêu co méo elip gây cắt xén
          aspectRatio: 1,
          cutout: "70%",
          layout: {
            padding: 6, // Đệm 6px bảo đảm lát cắt không bị clip ngoài biên canvas
          },
        },
      });

      // Đánh dấu container sẵn sàng để hiển thị số events đồng bộ với vòng tròn
      const donutWrap = severityCanvas.closest(".chart-wrap-donut");
      if (donutWrap) {
        donutWrap.classList.add("chart-ready");
      }
    }

    // 3. Biểu đồ cột Device Distribution
    const deviceCanvas = document.getElementById("device-chart");
    if (deviceCanvas) {
      createChart(deviceCanvas, {
        type: "bar",
        data: {
          labels: deviceTypes.map((row) => row.label),
          datasets: [{
            label: "Alerts",
            data: deviceTypes.map((row) => row.value),
            backgroundColor: "rgba(60, 200, 255, 0.7)",
            borderColor: "#3cc8ff",
            borderWidth: 1,
            borderRadius: 4,
            maxBarThickness: 34,
          }],
        },
        options: {
          ...baseOptions,
          animation: animConfig,
          scales: {
            x: axis,
            y: { ...axis, beginAtZero: true, ticks: { ...axis.ticks, precision: 0 } },
          },
        },
      });
    }
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

  // Đảm bảo vẽ biểu đồ khi trang nạp lần đầu, ngay cả khi Chart.js được tải bất đồng bộ (defer)
  const initCharts = () => {
    if (typeof Chart === "undefined") {
      window.addEventListener("load", () => {
        window.renderDashboardCharts(false);
        markRefreshed();
      }, { once: true });
    } else {
      window.renderDashboardCharts(false);
      markRefreshed();
    }
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initCharts, { once: true });
  } else {
    initCharts();
  }

  // Khi HTMX hoàn tất swap DOM mới:
  // Tái tạo lại đồ thị ngay trong frame hiển thị với animation=false để không gây giật/chớp tắt canvas
  document.addEventListener("htmx:afterSwap", (event) => {
    if (event.target.id === "dashboard-content") {
      window.requestAnimationFrame(() => {
        window.renderDashboardCharts(true);
        markRefreshed();
      });
    }
  });

  // Tự động làm mới dữ liệu telemetry định kỳ mỗi 20 giây khi người dùng không tương tác
  window.setInterval(() => {
    const root = document.getElementById("dashboard-content");
    const userIsInteracting = root?.contains(document.activeElement) || root?.querySelector("details[open]");
    if (!root || document.hidden || userIsInteracting || root.classList.contains("htmx-request")) return;
    if (typeof htmx !== "undefined") {
      htmx.ajax("GET", "/partials/dashboard", { target: "#dashboard-content", swap: "innerHTML" });
    }
  }, 20_000);
})();
