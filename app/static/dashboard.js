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
   * Lưu trữ các instance Chart.js đang hoạt động để cập nhật trực tiếp (in-place update)
   * khi có dữ liệu mới từ HTMX thay vì hủy và tạo lại từ đầu (remount),
   * triệt tiêu hiện tượng layout shift và chớp tắt canvas.
   */
  const chartRegistry = {
    timeline: null,
    severity: null,
    device: null,
  };

  /**
   * Giải phóng và hủy toàn bộ các phiên biểu đồ Chart.js đang hoạt động.
   *
   * @returns {void}
   */
  const cleanupCharts = () => {
    Object.keys(chartRegistry).forEach((key) => {
      if (chartRegistry[key]) {
        try {
          chartRegistry[key].destroy();
        } catch (_) {
          // Bỏ qua nếu canvas đã bị tách khỏi DOM
        }
        chartRegistry[key] = null;
      }
    });
    window.dashboardCharts = [];
  };

  /**
   * Phân tích dữ liệu JSON và khởi tạo hoặc cập nhật in-place 3 biểu đồ giám sát trên Dashboard.
   *
   * @param {boolean} [isRefresh=false] - Cờ xác định thao tác render bắt nguồn từ sự kiện làm mới (refresh/swap).
   * Khi làm mới, animation tắt (hoặc tức thì) và dữ liệu được cập nhật trực tiếp vào Chart instance hiện có
   * để giữ nguyên hình vẽ, không gây biến mất hoặc remount.
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

    const timeline = Array.isArray(data.timeline) ? data.timeline : [];
    const severity = Array.isArray(data.severity) ? data.severity : [];
    const deviceTypes = Array.isArray(data.device_types) ? data.device_types : [];

    const animConfig = (isRefresh || reducedMotion) ? false : { duration: 350 };

    // 1. Biểu đồ đường Alert Activity (24-hour window)
    const timelineCanvas = document.getElementById("timeline-chart");
    if (timelineCanvas) {
      const timelineLabels = timeline.length > 0 ? timeline.map((row) => row.label) : ["No activity"];
      const timelineValues = timeline.length > 0 ? timeline.map((row) => row.value) : [0];

      if (chartRegistry.timeline && chartRegistry.timeline.canvas === timelineCanvas) {
        // Cập nhật dữ liệu in-place không remount canvas
        chartRegistry.timeline.data.labels = timelineLabels;
        chartRegistry.timeline.data.datasets[0].data = timelineValues;
        chartRegistry.timeline.update("none");
      } else {
        if (chartRegistry.timeline) {
          try { chartRegistry.timeline.destroy(); } catch (_) {}
        }
        chartRegistry.timeline = new Chart(timelineCanvas, {
          type: "line",
          data: {
            labels: timelineLabels,
            datasets: [{
              label: "Alerts",
              data: timelineValues,
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
                offset: true,
                ticks: {
                  ...axis.ticks,
                  maxTicksLimit: 8,
                  maxRotation: 0,
                  callback: function (val) {
                    const label = this.getLabelForValue(val);
                    if (typeof label === "string" && label.length >= 16) {
                      return label.slice(11, 16);
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
                  padding: 10,
                  precision: 0,
                },
              },
            },
          },
        });
      }
    }

    // 2. Biểu đồ tròn Severity Mix (Donut chart)
    const severityCanvas = document.getElementById("severity-chart");
    if (severityCanvas) {
      const severityLabels = severity.length > 0 ? severity.map((row) => row.label) : ["No alerts"];
      const severityValues = severity.length > 0 ? severity.map((row) => row.value) : [1];
      const severityColors = severity.length > 0
        ? severity.map((row) => colors[row.label] || "#8296aa")
        : ["rgba(130, 150, 170, 0.2)"];

      if (chartRegistry.severity && chartRegistry.severity.canvas === severityCanvas) {
        // Cập nhật in-place không remount donut
        chartRegistry.severity.data.labels = severityLabels;
        chartRegistry.severity.data.datasets[0].data = severityValues;
        chartRegistry.severity.data.datasets[0].backgroundColor = severityColors;
        chartRegistry.severity.update("none");
      } else {
        if (chartRegistry.severity) {
          try { chartRegistry.severity.destroy(); } catch (_) {}
        }
        chartRegistry.severity = new Chart(severityCanvas, {
          type: "doughnut",
          data: {
            labels: severityLabels,
            datasets: [{
              data: severityValues,
              backgroundColor: severityColors,
              borderColor: "#101721",
              borderWidth: 2,
              hoverOffset: severity.length > 0 ? 4 : 0,
            }],
          },
          options: {
            ...baseOptions,
            animation: (isRefresh || reducedMotion) ? false : {
              duration: 350,
              animateRotate: true,
              animateScale: false,
            },
            responsive: true,
            maintainAspectRatio: true,
            aspectRatio: 1,
            cutout: "70%",
            layout: {
              padding: 8, // Đệm 8px bảo đảm khi hover (+4px) không bị chạm biên canvas
            },
            interaction: {
              mode: "nearest",
              intersect: true, // Chỉ kích hoạt khi chạm đúng lát cắt, không bắt tâm rỗng
            },
            plugins: {
              legend: { display: false },
              tooltip: {
                ...baseOptions.plugins.tooltip,
                displayColors: true,
                callbacks: {
                  label: function (context) {
                    const label = context.label || "";
                    const val = context.parsed || 0;
                    return ` ${label.charAt(0).toUpperCase() + label.slice(1)}: ${val} alerts`;
                  },
                },
              },
            },
          },
        });
      }

      // Cập nhật con số tổng số sự kiện trong tâm vòng donut
      const donutTotalNode = document.getElementById("donut-total-count");
      if (donutTotalNode && typeof data.total !== "undefined") {
        donutTotalNode.textContent = String(data.total);
      }

      // Đánh dấu container sẵn sàng để hiển thị số events
      const donutWrap = severityCanvas.closest(".chart-wrap-donut");
      if (donutWrap) {
        donutWrap.classList.add("chart-ready");
      }
    }

    // 3. Biểu đồ cột Device Distribution
    const deviceCanvas = document.getElementById("device-chart");
    if (deviceCanvas) {
      const deviceLabels = deviceTypes.map((row) => row.label);
      const deviceValues = deviceTypes.map((row) => row.value);

      if (chartRegistry.device && chartRegistry.device.canvas === deviceCanvas) {
        chartRegistry.device.data.labels = deviceLabels;
        chartRegistry.device.data.datasets[0].data = deviceValues;
        chartRegistry.device.update("none");
      } else {
        if (chartRegistry.device) {
          try { chartRegistry.device.destroy(); } catch (_) {}
        }
        chartRegistry.device = new Chart(deviceCanvas, {
          type: "bar",
          data: {
            labels: deviceLabels,
            datasets: [{
              label: "Alerts",
              data: deviceValues,
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
    }

    // Cung cấp danh sách biểu đồ đang chạy cho window.dashboardCharts
    window.dashboardCharts = [
      chartRegistry.timeline,
      chartRegistry.severity,
      chartRegistry.device,
    ].filter(Boolean);
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
  // Cập nhật dữ liệu tức thì lên các biểu đồ được bảo lưu (hx-preserve), không remount
  document.addEventListener("htmx:afterSwap", (event) => {
    if (event.target.id === "dashboard-content") {
      window.renderDashboardCharts(true);
      markRefreshed();
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
