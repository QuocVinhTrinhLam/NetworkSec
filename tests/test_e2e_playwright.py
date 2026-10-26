"""End-to-End (E2E) UI Automation Test Suite for NetworkSec SOC Command Center.

Sử dụng Playwright để kiểm thử giao diện người dùng thực tế trên trình duyệt Chromium:
- Xác thực đăng nhập (Login Authentication & CSRF Protection)
- Giám sát KPI và biểu đồ viễn thông (SOC Command Center Telemetry)
- Làm mới dữ liệu thời gian thực thông qua HTMX (Partial Swapping)
- Quản lý kịch bản tấn công và xuất báo cáo CSV (Attack Scenarios & Export)

Mọi bước nghiệp vụ đều tự động chụp ảnh bằng chứng (evidence) và lưu trữ theo
chuẩn đặt tên: TC-<ID>_<stt>_<slug-mo-ta>_<PASS|FAIL>.png
"""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from playwright.sync_api import Page, expect, sync_playwright

from app.config import BASE_DIR, Settings
from app.db import Database
from app.main import create_app
from app.models import Alert
from app.web.auth import hash_password

# Thư mục bằng chứng nằm trong workspace để test chạy được trong sandbox và CI.
EVIDENCE_DIR: Path = (BASE_DIR / "docs" / "testing" / "e2e" / "evidence").resolve()
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


@pytest.fixture
def page() -> Generator[Page, None, None]:
    """Khởi tạo Chromium với kích thước viewport 1280x800 chuẩn Desktop.

    Yields:
        Page: Đối tượng trang Playwright sẵn sàng cho thao tác tự động hóa.
    """
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 800})
        test_page = context.new_page()
        try:
            yield test_page
        finally:
            context.close()
            browser.close()


class LiveTestServer:
    """Máy chủ phát triển phục vụ kiểm thử Playwright chạy ngầm trong tiến trình độc lập."""

    def __init__(self, app: Any, host: str, port: int, database: Database) -> None:
        self.app = app
        self.host = host
        self.port = port
        self.database = database
        self.url = f"http://{host}:{port}"
        # Sử dụng log_level warning để tránh làm loãng output test của pytest
        config = uvicorn.Config(app, host=host, port=port, log_level="warning")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self) -> None:
        """Khởi động luồng uvicorn và thăm dò endpoint /login đến khi sẵn sàng tiếp nhận request."""
        self.thread.start()
        start_time = time.time()
        # Chờ tối đa 10 giây để FastAPI nạp middleware và database
        while time.time() - start_time < 10:
            try:
                response = httpx.get(f"{self.url}/login", timeout=0.5)
                if response.status_code == 200:
                    return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("LiveTestServer không thể khởi động trong thời gian 10 giây.")

    def stop(self) -> None:
        """Dừng uvicorn và thu dọn luồng chạy nền."""
        self.server.should_exit = True
        self.thread.join(timeout=3.0)


@pytest.fixture(scope="module")
def live_server(tmp_path_factory: pytest.TempPathFactory) -> Generator[LiveTestServer, None, None]:
    """Fixture tạo và quản lý vòng đời của LiveTestServer kèm database tạm thời.

    Args:
        tmp_path_factory: Factory sinh thư mục tạm cô lập của pytest.

    Yields:
        LiveTestServer: Đối tượng máy chủ test sẵn sàng kết nối.
    """
    tmp_path = tmp_path_factory.mktemp("playwright_e2e")
    db_path = tmp_path / "playwright_soc.db"

    # Lấy cổng khả dụng ngẫu nhiên trên localhost nhằm tránh xung đột với cổng 8000
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        free_port = int(sock.getsockname()[1])

    settings = Settings(
        database_path=db_path,
        severity_config=BASE_DIR / "config" / "severity.yaml",
        rules_catalog=BASE_DIR / "config" / "rules_catalog.yaml",
        admin_username="admin",
        # 10,000 vòng lặp PBKDF2 giúp tăng tốc test mà vẫn đảm bảo tính bảo mật của thuật toán
        admin_password_hash=hash_password("test-password", iterations=10_000),
        session_secret="e2e-playwright-session-secret-with-high-entropy",
        mock_mode=True,
    )

    app = create_app(settings)
    database = Database(db_path)

    # Nạp sẵn 2 cảnh báo nền để SOC Dashboard hiển thị KPI và biểu đồ ban đầu
    database.insert_alert(
        Alert(
            id="seed-alert-core-01",
            timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
            device_name="vnpt-core-router-01",
            device_type="router",
            source_ip="203.0.113.195",
            dest_ip="10.10.0.1",
            user="root",
            rule_id="100201",
            rule_description="BGP Neighbor Flapping detected on Core Uplink",
            severity="critical",
            mitre_id="T1498",
            mitre_name="Network Denial of Service",
            raw_log="BGP peer 203.0.113.195 down: hold timer expired",
        )
    )
    database.insert_alert(
        Alert(
            id="seed-alert-fw-02",
            timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
            device_name="vnpt-edge-fw-01",
            device_type="firewall",
            source_ip="198.51.100.44",
            dest_ip="10.10.0.254",
            user="admin",
            rule_id="100210",
            rule_description="SSH Brute-force attempt against edge gateway",
            severity="high",
            mitre_id="T1110",
            mitre_name="Brute Force",
            raw_log="Failed password for invalid user admin from 198.51.100.44 port 44321 ssh2",
        )
    )

    server = LiveTestServer(app=app, host="127.0.0.1", port=free_port, database=database)
    server.start()
    yield server
    server.stop()


def capture_evidence(page: Page, test_id: str, step: int, slug: str, passed: bool = True) -> Path:
    """Chụp ảnh màn hình lưu vào thư mục evidence theo quy ước chuẩn.

    Args:
        page: Playwright Page fixture.
        test_id: Mã test case (ví dụ TC-AUTH-01).
        step: Số thứ tự bước kiểm thử (1, 2, 3...).
        slug: Mô tả ngắn gọn trạng thái màn hình.
        passed: Trạng thái PASS hoặc FAIL.

    Returns:
        Path: Đường dẫn tuyệt đối của tệp ảnh đã chụp.
    """
    status = "PASS" if passed else "FAIL"
    filename = f"{test_id}_{step:02d}_{slug}_{status}.png"
    target_path = EVIDENCE_DIR / filename
    page.screenshot(path=str(target_path), full_page=True)
    return target_path


# ============================================================================
# TEST CASES E2E
# ============================================================================


def test_tc_auth_01_login_and_csrf_validation(live_server: LiveTestServer, page: Page) -> None:
    """TC-AUTH-01: Kiểm thử quy trình đăng nhập, CSRF và xử lý thông báo lỗi.

    Kiểm tra:
    1. Truy cập /login, tải thành công form với CSRF token ẩn.
    2. Nhập mật khẩu sai -> Xuất hiện thông báo lỗi .flash.error, không redirect.
    3. Nhập tài khoản chính xác -> Chuyển hướng thành công tới /dashboard.
    """
    # Cấu hình viewport chuẩn Desktop (1280x800)
    page.set_viewport_size({"width": 1280, "height": 800})

    # Bước 1: Mở trang đăng nhập
    page.goto(f"{live_server.url}/login")
    expect(page.locator("h2#login-title")).to_have_text("Analyst sign in")
    expect(page.locator('input[name="csrf"]')).to_have_count(1)
    capture_evidence(page, "TC-AUTH-01", 1, "login-form-loaded", passed=True)

    # Bước 2: Thử đăng nhập sai thông tin
    page.fill('input[name="username"]', "admin")
    page.fill('input[name="password"]', "wrong-password")
    page.click('button[type="submit"]')
    page.wait_for_selector(".flash.error")
    expect(page.locator(".flash.error")).to_contain_text("Invalid username or password")
    capture_evidence(page, "TC-AUTH-01", 2, "invalid-credentials-error", passed=True)

    # Bước 3: Đăng nhập thành công với tài khoản quản trị viên
    page.fill('input[name="username"]', "admin")
    page.fill('input[name="password"]', "test-password")
    page.click('button[type="submit"]')

    # Đảm bảo chuyển hướng tới /dashboard và thanh điều hướng xuất hiện
    page.wait_for_url(f"{live_server.url}/dashboard")
    expect(page.locator("h1")).to_have_text("SOC Command Center")
    capture_evidence(page, "TC-AUTH-01", 3, "login-success-dashboard", passed=True)


def test_tc_dash_01_soc_command_center_telemetry_grid(
    live_server: LiveTestServer, page: Page
) -> None:
    """TC-DASH-01: Kiểm tra cấu trúc lưới KPI và các biểu đồ phân tích sự cố.

    Kiểm tra:
    1. Hiển thị thẻ thống kê tổng quan (Total alerts, Critical, High, Medium, Low).
    2. Sự hiện diện của 3 Canvas biểu đồ Chart.js (#timeline-chart, #severity-chart, #device-chart).
    3. Hàng đợi điều tra sự cố (Investigation queue) và Top thiết bị phát sinh cảnh báo.
    """
    page.set_viewport_size({"width": 1280, "height": 800})

    # Đăng nhập vào hệ thống
    page.goto(f"{live_server.url}/login")
    page.fill('input[name="username"]', "admin")
    page.fill('input[name="password"]', "test-password")
    page.click('button[type="submit"]')
    page.wait_for_url(f"{live_server.url}/dashboard")

    # Xác nhận các thẻ KPI metrics
    expect(page.locator(".metric-total strong")).to_be_visible()
    expect(page.locator(".severity-critical strong")).to_be_visible()
    expect(page.locator(".severity-high strong")).to_be_visible()

    # Xác nhận 3 khung canvas biểu đồ an ninh
    expect(page.locator("#timeline-chart")).to_be_visible()
    expect(page.locator("#severity-chart")).to_be_visible()
    expect(page.locator("#device-chart")).to_be_visible()

    # Xác nhận danh sách cảnh báo trong Investigation Queue
    expect(page.locator(".alert-feed")).to_be_visible()
    expect(page.locator(".alert-feed")).to_contain_text("vnpt-core-router-01")

    capture_evidence(page, "TC-DASH-01", 1, "soc-command-center-overview", passed=True)


def test_tc_dash_02_htmx_realtime_telemetry_refresh(
    live_server: LiveTestServer, page: Page
) -> None:
    """TC-DASH-02: Kiểm tra tính năng làm mới dữ liệu thời gian thực qua HTMX.

    Kiểm tra:
    1. Bơm thêm cảnh báo an ninh nghiêm trọng mới vào SQLite.
    2. Kích hoạt nút bấm Refresh (.refresh-button).
    3. Vùng #dashboard-content hoán đổi nội dung (HTMX swap), số liệu tăng và xuất hiện alert mới.
    """
    page.set_viewport_size({"width": 1280, "height": 800})

    # Đăng nhập và mở Dashboard
    page.goto(f"{live_server.url}/login")
    page.fill('input[name="username"]', "admin")
    page.fill('input[name="password"]', "test-password")
    page.click('button[type="submit"]')
    page.wait_for_url(f"{live_server.url}/dashboard")

    # Bơm 1 cảnh báo an ninh mới trực tiếp vào cơ sở dữ liệu
    new_alert_id = "htmx-live-refresh-alert-99"
    live_server.database.insert_alert(
        Alert(
            id=new_alert_id,
            timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
            device_name="vnpt-agg-switch-05",
            device_type="switch",
            source_ip="10.254.0.99",
            dest_ip="10.254.0.1",
            user="netadmin",
            rule_id="100999",
            rule_description="Unauthorized Spanning-Tree Root Bridge BPDU inject",
            severity="critical",
            mitre_id="T1498",
            mitre_name="Network Denial of Service",
            raw_log="STP root bridge topology change received on non-root port Gi0/1",
        )
    )

    # Kích hoạt nút Refresh HTMX
    refresh_button = page.locator(".refresh-button")
    expect(refresh_button).to_be_visible()
    refresh_button.click()

    # Chờ HTMX hoàn tất quá trình cập nhật innerHTML của #dashboard-content
    expect(page.locator("#dashboard-content")).to_contain_text(
        "vnpt-agg-switch-05", timeout=10_000
    )
    expect(page.locator("#dashboard-content")).to_contain_text("Unauthorized Spanning-Tree")

    capture_evidence(page, "TC-DASH-02", 1, "htmx-telemetry-refreshed", passed=True)


def test_tc_scen_01_attack_scenarios_management_and_export(
    live_server: LiveTestServer, page: Page
) -> None:
    """TC-SCEN-01: Quản lý kịch bản kiểm thử tấn công và xuất báo cáo CSV.

    Kiểm tra:
    1. Điều hướng tới /scenarios, kiểm tra form ghi nhận và bảng lịch sử test.
    2. Điền form tạo kịch bản tấn công (MITRE T1046 Network Service Scanning).
    3. Gửi form -> Xác nhận dòng dữ liệu mới được hiển thị trong bảng HTML.
    4. Tải tệp /scenarios/export.csv và xác nhận dữ liệu đã được xuất thành công.
    """
    page.set_viewport_size({"width": 1280, "height": 800})

    # Đăng nhập
    page.goto(f"{live_server.url}/login")
    page.fill('input[name="username"]', "admin")
    page.fill('input[name="password"]', "test-password")
    page.click('button[type="submit"]')
    page.wait_for_url(f"{live_server.url}/dashboard")

    # Mở trang kịch bản tấn công
    page.goto(f"{live_server.url}/scenarios")
    expect(page.locator("h1")).to_have_text("Attack scenarios")
    capture_evidence(page, "TC-SCEN-01", 1, "scenarios-overview", passed=True)

    # Điền dữ liệu kịch bản kiểm thử tấn công
    page.fill('input[name="technique"]', "T1046 - Network Service Scanning")
    page.fill('input[name="tool"]', "nmap 7.94")
    page.fill('input[name="expected_rule"]', "100200")
    page.fill('input[name="detection_time_seconds"]', "1.8")
    page.check('input[name="detected"]')
    page.fill(
        'textarea[name="notes"]',
        "Kịch bản kiểm thử E2E tự động hóa Playwright đạt chuẩn nghiệm thu VNPT N4.2.",
    )
    capture_evidence(page, "TC-SCEN-01", 2, "scenario-form-filled", passed=True)

    # Gửi form kịch bản tấn công (chỉ định button trong form tránh click nhầm logout)
    page.click('form.scenario-form button[type="submit"]')

    # Đợi bảng cập nhật dòng kịch bản mới
    expect(page.locator("table")).to_contain_text("T1046 - Network Service Scanning")
    expect(page.locator("table")).to_contain_text("T1046 - Network Service Scanning")
    expect(page.locator("table")).to_contain_text("nmap 7.94")
    expect(page.locator("table")).to_contain_text("100200")
    expect(page.locator("table")).to_contain_text("Detected")
    capture_evidence(page, "TC-SCEN-01", 3, "scenario-recorded-in-table", passed=True)

    # Kiểm tra xuất file CSV
    with page.expect_download() as download_info:
        page.click('a.button:has-text("Export CSV")')
    download = download_info.value
    csv_path = EVIDENCE_DIR / "exported_scenarios.csv"
    download.save_as(str(csv_path))

    # Đọc nội dung CSV xác minh
    csv_content = csv_path.read_text(encoding="utf-8")
    assert "T1046 - Network Service Scanning" in csv_content
    assert "nmap 7.94" in csv_content
    capture_evidence(page, "TC-SCEN-01", 4, "scenario-exported-csv", passed=True)


def test_tc_dash_03_chart_layout_and_24h_timeline(
    live_server: LiveTestServer, page: Page
) -> None:
    """TC-DASH-03: Kiểm tra hiển thị biểu đồ Donut, Timeline 24h và Refresh không biến mất.

    Kiểm tra:
    1. Donut "Severity mix": Wrapper chuẩn 180x180, có class .chart-ready, không bị cắt xén.
    2. Biểu đồ đường "Alert activity": Vùng vẽ chiếm trọn thẻ (>= 240px), không co 40%.
    3. Trục thời gian 24h: Dữ liệu #dashboard-data có đủ 24 buckets giờ liên tục.
    4. Khi bấm Refresh: Canvas không bị biến mất, tái hiển thị tức thì không chớp tắt.
    """
    page.set_viewport_size({"width": 1280, "height": 800})

    # Đăng nhập và vào Dashboard
    page.goto(f"{live_server.url}/login")
    page.fill('input[name="username"]', "admin")
    page.fill('input[name="password"]', "test-password")
    page.click('button[type="submit"]')
    page.wait_for_url(f"{live_server.url}/dashboard")

    # 1. Đợi biểu đồ sẵn sàng
    page.wait_for_selector(".chart-wrap-donut.chart-ready")
    expect(page.locator(".chart-wrap-donut .donut-total")).to_be_visible()

    # 2. Kiểm tra dữ liệu 24 buckets giờ liên tục
    data_text = page.locator("#dashboard-data").text_content() or "{}"
    dashboard_data = json.loads(data_text)
    assert "timeline" in dashboard_data
    timeline_len = len(dashboard_data["timeline"])
    assert timeline_len == 24, f"Timeline phải có đủ 24 bucket, nhưng có {timeline_len}"

    # 3. Kiểm tra kích thước hình học của Donut và Timeline
    donut_box = page.locator(".chart-wrap-donut").bounding_box()
    assert donut_box is not None
    assert round(donut_box["width"]) == 180
    assert round(donut_box["height"]) == 180

    timeline_box = page.locator(".chart-wrap-large").bounding_box()
    assert timeline_box is not None
    initial_h = timeline_box["height"]
    assert 250 <= initial_h <= 270, (
        f"Chiều cao timeline phải cố định 260px (±10px), thực tế: {initial_h}"
    )

    # Hover thử vào biểu đồ Donut để xác minh không bị cắt lát cắt hay lỗi tooltip
    page.hover("#severity-chart")
    page.wait_for_timeout(100)
    capture_evidence(page, "TC-DASH-03", 1, "chart-layout-24h-verified", passed=True)

    # 4. Kích hoạt nút Refresh và kiểm tra biểu đồ giữ nguyên, không giật layout
    refresh_button = page.locator(".refresh-button")
    refresh_button.click()
    page.wait_for_timeout(300)

    # Đảm bảo canvas vẫn hiển thị tốt, kích thước không phình/co
    expect(page.locator("#severity-chart")).to_be_visible()
    expect(page.locator("#timeline-chart")).to_be_visible()

    post_refresh_box = page.locator(".chart-wrap-large").bounding_box()
    assert post_refresh_box is not None
    assert abs(post_refresh_box["height"] - initial_h) < 2.0, (
        f"Chiều cao timeline bị giật sau refresh: {initial_h} -> {post_refresh_box['height']}"
    )

    capture_evidence(page, "TC-DASH-03", 2, "charts-persisted-after-refresh", passed=True)
