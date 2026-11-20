# Làm việc nhóm

1. Tạo Issue có tiêu chí nghiệm thu và người phụ trách.
2. Tạo nhánh từ `main`: `feature/<ten-ngan>`, `fix/<ten-ngan>` hoặc `docs/<ten-ngan>`.
3. Commit nhỏ, mô tả hành vi: `feat(bot): aggregate duplicate alerts`.
4. Chạy `make lint test` trước khi push.
5. Mở Pull Request; người không viết code review logic, bảo mật và cách demo.
6. Squash chỉ khi commit trung gian không có giá trị giải thích.

Không đưa `.env`, dữ liệu log thật, token Telegram, mật khẩu dịch vụ hay private key lên GitHub. Khi vô tình lộ token, phải revoke/rotate; xóa commit không đủ vì secret vẫn có thể tồn tại trong lịch sử clone.
