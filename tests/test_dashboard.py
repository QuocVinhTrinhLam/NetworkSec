from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import BASE_DIR, Settings
from app.main import create_app
from app.models import Alert
from app.web.auth import hash_password
from app.web.routes import csv_safe_row


def build_client(tmp_path: Path) -> TestClient:
    settings = Settings(
        database_path=tmp_path / "web.db",
        severity_config=BASE_DIR / "config" / "severity.yaml",
        rules_catalog=BASE_DIR / "config" / "rules_catalog.yaml",
        admin_username="admin",
        admin_password_hash=hash_password("test-password", iterations=10_000),
        session_secret="test-session-secret-with-enough-entropy",
        mock_mode=True,
    )
    app = create_app(settings)
    seeded_alert = Alert(
        id="web-alert",
        timestamp="2020-01-01T10:00:00+00:00",
        device_name='=HYPERLINK("https://attacker.invalid")',
        device_type="firewall",
        source_ip="203.0.113.5",
        dest_ip="10.0.0.1",
        user=None,
        rule_id="100201",
        rule_description="Port scan <img src=x>",
        severity="high",
        mitre_id="T1046",
        mitre_name="Discovery",
        raw_log="<script>owned()</script>",
    )
    app.state.database.insert_alert(seeded_alert)
    app.state.test_alert_id = seeded_alert.alert_id
    return TestClient(app, follow_redirects=False)


def login(client: TestClient) -> None:
    page = client.get("/login")
    token = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/login",
        data={"username": "admin", "password": "test-password", "csrf": token},
    )
    assert response.status_code == 303


def test_csv_formula_guard_handles_leading_whitespace_and_bom() -> None:
    fields = ["space", "newline", "bom", "safe"]
    row = csv_safe_row(
        {"space": "  =1+1", "newline": "\n@SUM(A:A)", "bom": "\ufeff-2+2", "safe": "text"},
        fields,
    )
    assert row == {
        "space": "'  =1+1",
        "newline": "'\n@SUM(A:A)",
        "bom": "'\ufeff-2+2",
        "safe": "text",
    }


def test_authentication_csrf_and_output_escaping(tmp_path: Path) -> None:
    with build_client(tmp_path) as client:
        assert client.get("/dashboard").status_code == 303
        client.get("/login")
        assert (
            client.post(
                "/login", data={"username": "admin", "password": "test-password", "csrf": "bad"}
            ).status_code
            == 403
        )
        login(client)
        detail = client.get(f"/alerts/{client.app.state.test_alert_id}")
        assert detail.status_code == 200
        assert "Back to alert queue" in detail.text
        assert '<dl class="detail-grid detail-facts">' in detail.text
        assert "<script>owned()" not in detail.text
        assert "&lt;script&gt;owned()&lt;/script&gt;" in detail.text
        assert "Chặn hoặc giới hạn tốc độ IP nguồn" in detail.text


def test_alert_filters_and_csv_export(tmp_path: Path) -> None:
    with build_client(tmp_path) as client:
        login(client)
        page = client.get("/alerts?time_range=all&severity=high&source_ip=203.0.113.5")
        assert page.status_code == 200
        assert client.app.state.test_alert_id in page.text
        search_page = client.get("/alerts?time_range=all&search=203.0.113.5")
        assert client.app.state.test_alert_id in search_page.text
        csv_response = client.get(
            "/alerts/export.csv?time_range=all&severity=high&source_ip=203.0.113.5"
        )
        assert csv_response.status_code == 200
        assert client.app.state.test_alert_id in csv_response.text
        assert "'=HYPERLINK" in csv_response.text
        excluded = client.get(
            "/alerts/export.csv?time_range=all&severity=high&source_ip=198.51.100.10"
        )
        assert client.app.state.test_alert_id not in excluded.text


def test_device_becomes_silent(tmp_path: Path) -> None:
    with build_client(tmp_path) as client:
        login(client)
        page = client.get("/devices")
        assert page.status_code == 200
        assert "Quiet in window" in page.text
        assert "not that the device is offline" in page.text


def test_dashboard_renders_network_event_dashboard_and_live_queue(tmp_path: Path) -> None:
    with build_client(tmp_path) as client:
        critical_alert = Alert(
            id="live-critical-alert",
            timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
            device_name="edge-fw-01",
            device_type="firewall",
            source_ip="198.51.100.23",
            dest_ip="10.0.0.10",
            user="network-analyst",
            rule_id="100900",
            rule_description='Suspicious </script><script>alert("owned")</script> access',
            severity="critical",
            mitre_id="T1078",
            mitre_name="Valid Accounts",
            raw_log="authentication anomaly",
        )
        client.app.state.database.insert_alert(critical_alert)
        login(client)

        page = client.get("/dashboard")

        assert page.status_code == 200
        assert "Network Event Dashboard" in page.text
        assert 'aria-label="Primary navigation"' in page.text
        assert 'aria-current="page"' in page.text
        assert "Recent detections" in page.text
        assert "Demo mode" in page.text
        assert critical_alert.alert_id in page.text
        assert "edge-fw-01" in page.text
        assert '</script><script>alert("owned")</script>' not in page.text

        partial = client.get("/partials/dashboard")
        assert partial.status_code == 200
        assert '</script><script>alert("owned")</script>' not in partial.text


def test_attack_scenario_requires_csrf_and_exports_csv(tmp_path: Path) -> None:
    with build_client(tmp_path) as client:
        login(client)
        page = client.get("/scenarios")
        token = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        response = client.post(
            "/scenarios",
            data={
                "csrf": token,
                "technique": "Network Service Scanning",
                "tool": "nmap",
                "expected_rule": "100201",
                "detected": "true",
                "detection_time_seconds": "8.4",
                "notes": "Detected in mock mode",
            },
        )
        assert response.status_code == 303
        exported = client.get("/scenarios/export.csv")
        assert "Network Service Scanning" in exported.text


def test_network_event_dashboard_refresh_and_kpi_grid_layout(tmp_path: Path) -> None:
    """Xác minh tính toàn vẹn của chu trình làm mới dữ liệu và layout dashboard.

    Kịch bản kiểm thử đảm bảo giao diện giám sát viễn thông hoạt động ổn định khi nhận dữ liệu
    bổ sung thời gian thực qua cơ chế HTMX partial, ngăn chặn các lỗi hiển thị phổ biến trong
    hệ thống giám sát (như số liệu NaN/undefined làm vỡ biểu đồ Chart.js, mất liên kết DOM hoặc
    vỡ layout grid hiển thị trên màn hình điều hành NOC).

    Args:
        tmp_path: Fixture thư mục tạm thời của Pytest nhằm cô lập cơ sở dữ liệu SQLite
            trên từng ca kiểm thử, tuân thủ nguyên tắc không can thiệp database production.

    Returns:
        None. Hàm kiểm thử assert trực tiếp trạng thái HTTP, DOM element và CSS styles.

    Raises:
        AssertionError: Nếu thiếu CSRF token, response status không phải 200/303, số liệu
            KPI xuất hiện ký tự phi số (NaN/undefined), hoặc thiếu các canvas đồ thị.
    """
    with build_client(tmp_path) as client:
        # Khởi tạo bản ghi cảnh báo ban đầu trong khung thời gian 24h
        # để thiết lập baseline cho các thẻ KPI
        refreshed_alert = Alert(
            id="initial-network-alert-01",
            timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
            device_name="edge-fw-01",
            device_type="firewall",
            source_ip="198.51.100.10",
            dest_ip="10.0.0.1",
            user="network-analyst",
            rule_id="100200",
            rule_description="Perimeter port scan detected",
            severity="high",
            mitre_id="T1046",
            mitre_name="Network Service Scanning",
            raw_log="initial perimeter log",
        )
        client.app.state.database.insert_alert(refreshed_alert)

        # Trích xuất CSRF token từ trang /login để mô phỏng chính xác luồng xác thực;
        # việc kiểm tra token ngăn chặn Timing Attack và bảo vệ phiên làm việc khỏi CSRF.
        login_page = client.get("/login")
        assert login_page.status_code == 200
        assert 'name="csrf"' in login_page.text
        csrf_token = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        assert csrf_token, "CSRF token không được rỗng"

        login_resp = client.post(
            "/login",
            data={
                "username": "admin",
                "password": "test-password",
                "csrf": csrf_token,
            },
        )
        assert login_resp.status_code == 303
        assert login_resp.headers.get("location") == "/dashboard"

        # Xác nhận sau khi đăng nhập thành công, trình duyệt chuyển hướng tới dashboard
        dashboard_resp = client.get("/dashboard")
        assert dashboard_resp.status_code == 200
        assert "Network Event Dashboard" in dashboard_resp.text
        assert 'id="dashboard-content"' in dashboard_resp.text

        # Kiểm tra sự hiện diện của các thành phần hiển thị cốt lõi trước khi làm mới:
        # Thẻ tổng số sự cố và phân loại mức độ nghiêm trọng trọng yếu (critical/high).
        assert "metric-total" in dashboard_resp.text
        assert "severity-critical" in dashboard_resp.text
        assert "severity-high" in dashboard_resp.text

        # Các định danh canvas (#timeline-chart, #severity-chart, #device-chart) bắt buộc phải
        # tồn tại trong DOM ban đầu để Chart.js khởi tạo ngữ cảnh vẽ (CanvasRenderingContext2D).
        assert 'id="timeline-chart"' in dashboard_resp.text
        assert 'id="severity-chart"' in dashboard_resp.text
        assert 'id="device-chart"' in dashboard_resp.text

        # Nút refresh mang thuộc tính HTMX chuẩn để nạp partial thay vì tải lại toàn bộ trang
        assert "refresh-button" in dashboard_resp.text
        assert 'hx-get="/partials/dashboard"' in dashboard_resp.text
        assert 'hx-target="#dashboard-content"' in dashboard_resp.text

        # Mô phỏng nút .refresh-button bằng cách chèn sự cố mới và yêu cầu /partials/dashboard;
        # Sử dụng HTMX partial thay vì full reload nhằm tiết kiệm băng thông mạng truyền dẫn.
        refreshed_alert = Alert(
            id="refreshed-network-alert-02",
            timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
            device_name="network-core-gw-01",
            device_type="firewall",
            source_ip="198.51.100.99",
            dest_ip="10.0.0.1",
            user="network-admin",
            rule_id="100999",
            rule_description="Critical lateral privilege escalation",
            severity="critical",
            mitre_id="T1078",
            mitre_name="Valid Accounts",
            raw_log="network event refresh test log",
        )
        client.app.state.database.insert_alert(refreshed_alert)

        refresh_resp = client.get("/partials/dashboard")

        # Kiểm tra tính toàn vẹn của dữ liệu nhận về sau khi refresh partial:
        # Status code 200 đảm bảo endpoint partial hoạt động thông suốt
        assert refresh_resp.status_code == 200

        content_html = refresh_resp.text
        assert refreshed_alert.alert_id in content_html
        assert "network-core-gw-01" in content_html
        assert '<div class="metric-grid">' in content_html
        assert "metric-total" in content_html
        assert "severity-critical" in content_html
        assert "severity-high" in content_html
        assert 'id="timeline-chart"' in content_html
        assert 'id="severity-chart"' in content_html
        assert 'id="device-chart"' in content_html

        # Dữ liệu JSON nhúng trong thẻ script #dashboard-data phải phản ánh sự cố critical mới thêm
        # nhằm phục vụ cho hàm JavaScript render lại đồ thị phân bố mức độ nghiêm trọng
        match = re.search(
            r'<script type="application/json" id="dashboard-data">(.*?)</script>',
            content_html,
            re.DOTALL,
        )
        assert match is not None, "Thẻ script #dashboard-data phải tồn tại"
        dashboard_data = json.loads(match.group(1))
        assert dashboard_data["total"] >= 2
        assert any(
            item["label"] == "critical" and item["value"] >= 1
            for item in dashboard_data["severity"]
        )

        # Cấm 'NaN', 'undefined', 'None' vì Chart.js và các hàm JS định dạng số sẽ ném ngoại lệ
        assert "NaN" not in content_html
        assert "undefined" not in content_html
        assert "None" not in content_html

        # Đảm bảo các thẻ thống kê duy trì định dạng số nguyên hợp lệ cho ca trực viễn thông
        metric_values = re.findall(
            r'<article class="metric[^"]*">.*?<strong>(.*?)</strong>',
            content_html,
            re.DOTALL,
        )
        assert len(metric_values) >= 3, "Phải có ít nhất 3 thẻ KPI metric"
        for val in metric_values:
            assert val.isdigit(), f"Giá trị KPI phải là số nguyên hợp lệ, nhận được: {val}"

        # Xác nhận CSS layout grid của thẻ KPI không bị phá vỡ để co giãn đúng trên màn hình NOC
        css_resp = client.get("/static/styles.css")
        assert css_resp.status_code == 200
        assert ".metric-grid { display: grid;" in css_resp.text
        assert ".metric { position: relative; display: flex;" in css_resp.text
