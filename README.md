# Custom VPS Monitor — HTTP public IP

Tự đăng ký VPS bằng ID ngẫu nhiên, không giới hạn số lượng. Dashboard HTTP, Python standard library + SQLite, agent Bash + curl.

## Tính năng
- Hiển thị `Last Block` cùng hàng với số VPS/UAM, lấy từ mining API cấu hình trong `config.json`; API được truy vấn nền mặc định mỗi 60 giây (có thể chỉnh bằng `last_block_poll_seconds` trong `config.json`); khi lỗi sẽ thử lại tối đa 3 lần, cách nhau 10 giây. Vì block thường phát hành mỗi 15 phút, chu kỳ 60 giây giúp cập nhật block mới nhanh mà không gọi API quá dày. `fromBlockId` đọc từ `lastBlock.txt` nếu file có giá trị, nếu không dùng mặc định `184846`.
- Cột `Missing Block` tính `Last Block - Processed block` cho Tmux và từng Docker container. Chỉ hiển thị Missing Block khi chênh lệch `Last Block - Processed block` từ 0 trở lên; số âm được ẩn. Chênh lệch từ 10 block trở lên được tô đỏ và có tab cảnh báo riêng.
- Tự thêm VPS khi agent đăng ký và gửi heartbeat.
- Online/offline, địa chỉ IP, lần phản hồi gần nhất, uptime, load, trạng thái container `uam_1`.
- Cột Hostname đã bỏ khỏi bảng; bấm **Xem cấu hình** để mở popup CPU (model, vCPU, % sử dụng), RAM (đã dùng/tổng và %), disk root (đã dùng/tổng và %), OS, load và uptime.
- Tab Tất cả / Online / Offline, mỗi tab phân trang 50 VPS. Danh sách có bộ lọc ISP/nhà cung cấp; ISP được tra cứu từ IP và cache tối đa 7 ngày. Các IP chưa có cache sẽ được tra cứu tự động lần lượt.
- Xóa từng VPS offline; chọn nhiều VPS offline để xóa cùng lúc; xóa tất cả VPS offline thuộc ISP đang lọc; hoặc xóa hàng loạt VPS offline từ 24 giờ trở lên. Backend xác minh trạng thái offline trước khi xóa. Xóa là vĩnh viễn khỏi database, agent bị xóa sẽ cần đăng ký lại nếu tiếp tục chạy.
- Cột IP đứng đầu bảng; ẩn VPS ID và cột trạng thái UAM dạng chữ khỏi bảng. Chỉ giữ nút **Xem thông tin UAM** để mở popup.
- Popup thông tin UAM: Total Threads, PBKey, Termial và Version. Agent phát hiện tmux session `Utopia` và các container từ `debian:bookworm-slim`; nếu có cả hai thì hiển thị cả hai. Total Threads là 1 cho tmux cộng số container Docker tìm thấy. PBKey tmux được đọc từ `/opt/uam/PBKEY.txt` (dự phòng `$HOME/PBKEY.txt` và `$PWD/PBKEY.txt`); PBKey/Version Docker được đọc riêng theo từng container.
- Tương thích database cũ: các cột cấu hình mới sẽ được tự thêm khi khởi động server.

## Cảnh báo bảo mật
Phiên bản HTTP **không mã hóa** mật khẩu, enrollment key hay dữ liệu heartbeat khi truyền qua mạng. Nên giới hạn cổng bằng firewall chỉ cho IP quản trị của bạn. Không dùng mạng không đáng tin cậy.

## 1. Server trung tâm
Trên Ubuntu/Debian VPS trung tâm:

```bash
sudo apt update
sudo apt install -y python3
sudo mkdir -p /opt/vps-monitor
# Chép server.py và generate_config.py vào /opt/vps-monitor
sudo chmod 700 /opt/vps-monitor
cd /opt/vps-monitor
sudo python3 generate_config.py
```

Nhập host `0.0.0.0`, port `8080`, username và mật khẩu dashboard dài tối thiểu 16 ký tự. Tiếp theo nhập URL mining API (mặc định `http://157.230.45.47:22825/api/1.0`), `API_KEY`, và `fromBlockId` mặc định. Các giá trị này được lưu trong `config.json` quyền `0600`; không chia sẻ file vì chứa API key và thông tin đăng nhập. Nếu đã cài bản cũ, không chạy lại `generate_config.py` vì sẽ tạo thông tin đăng nhập/enrollment key mới; chỉ thêm các trường dưới đây vào `config.json` hiện có:

```json
"last_block_api_url": "http://157.230.45.47:22825/api/1.0",
"last_block_api_key": "YOUR_API_KEY",
"last_block_file": "/opt/vps-monitor/lastBlock.txt",
"last_block_from_block": "184846",
"last_block_poll_seconds": 60
```

Đặt các dòng này bên trong object JSON hiện có, thêm dấu phẩy cho đúng cú pháp và thay `YOUR_API_KEY` bằng key thật. Lấy enrollment key:

```bash
sudo cat /opt/vps-monitor/enrollment-key.txt
```

Khởi chạy:

```bash
sudo python3 /opt/vps-monitor/server.py
```

Mở TCP port 8080 trong firewall của hệ điều hành và nhà cung cấp. Nếu dùng UFW, ưu tiên chỉ cho IP máy bạn:

```bash
sudo ufw allow from YOUR_HOME_IP to any port 8080 proto tcp
```

Truy cập `http://PUBLIC_IP_VPS_TRUNG_TAM:8080/` và đăng nhập. Không dùng `https://`.

### Chạy tự động bằng systemd

Đây là cách nên dùng khi triển khai lâu dài, để dịch vụ tự chạy lại sau khi VPS reboot.
Trên server trung tâm

Tạo service:

```bash
sudo nano /etc/systemd/system/vps-monitor.service
```

Nội dung:

```bash
[Unit]
Description=VPS Monitor Dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/ubuntu/custom-vps-monitor
ExecStart=/usr/bin/python3 /home/ubuntu/custom-vps-monitor/server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Lưu file rồi chạy:

```bash
sudo systemctl daemon-reload
sudo systemctl enable vps-monitor
sudo systemctl restart vps-monitor || systemctl start vps-monitor
```

## 2. Agent trên từng VPS

Cách 1 cài đặt nhanh

```bash
wget https://github.com/mahaliabpqvn07/custom-vps-monitor/raw/main/install-vps-heartbeat.sh
sudo bash install-vps-heartbeat.sh http://PUBLIC_IP_VPS_TRUNG_TAM:8080 "ENROLLMENT_KEY"
```

Cách 2 cài đặt từng bước
Chép `agent.sh` sang VPS cần theo dõi. Không cần chỉnh sửa file để chèn IP hoặc enrollment key. Chạy thử bằng tham số truyền từ bên ngoài:

```bash
sudo install -m 700 agent.sh /usr/local/bin/vps-heartbeat.sh
sudo /usr/local/bin/vps-heartbeat.sh http://PUBLIC_IP_VPS_TRUNG_TAM:8080 'ENROLLMENT_KEY'
```

Hoặc cấu hình biến môi trường bên ngoài script (khuyến nghị cho systemd để không nhúng secret trong file mã nguồn):

```bash
sudo install -m 600 /dev/null /etc/vps-heartbeat.env
sudo nano /etc/vps-heartbeat.env
```

Nội dung `/etc/vps-heartbeat.env`:

```bash
VPSMON_SERVER_BASE="http://PUBLIC_IP_VPS_TRUNG_TAM:8080"
VPSMON_ENROLLMENT_KEY="ENROLLMENT_KEY"
```

Sau đó thêm `EnvironmentFile=/etc/vps-heartbeat.env` vào phần `[Service]` của systemd bên dưới. Không chia sẻ file này.

Để tự chạy lại sau reboot, tạo `/etc/systemd/system/vps-heartbeat.service`:

```ini
[Unit]
Description=Custom VPS heartbeat agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/vps-heartbeat.env
ExecStart=/usr/local/bin/vps-heartbeat.sh
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

Kích hoạt:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vps-heartbeat.service
sudo systemctl status vps-heartbeat.service
```

Agent gửi heartbeat mỗi 60 giây; sau 180 giây không có heartbeat, VPS được đánh dấu offline. Nút xóa hàng loạt theo thời gian chỉ xóa VPS offline ít nhất 24 giờ; các nút xóa VPS đã chọn/theo ISP cho phép xóa VPS offline ở mọi thời lượng offline. Thông số CPU được lấy mẫu trong khoảng 1 giây mỗi vòng; RAM/disk là mức dùng tại thời điểm heartbeat.

## 3. Kiểm tra

```bash
curl -i http://127.0.0.1:8080/healthz
```

Kỳ vọng HTTP 200 và `{"ok": true}`. Dashboard tự làm mới mỗi 15 giây. Sao lưu định kỳ `vpsmon.sqlite3`. Bảo toàn `/var/lib/vps-heartbeat/` trên agent để không mất ID/token.


### Cột CPU load và UAM Uptime
- Cột `CPU load` hiển thị mức sử dụng CPU gần nhất (phần trăm), thay cho Load 1m.
- Bảng có thêm `Total Threads` và `Terminal`.
- Popup `Thông tin UAM` có thêm `Uptime`: Tmux tính từ thời điểm tạo session `Utopia` và hiển thị `ngày - giờ`; Docker hiển thị trạng thái chạy đã bỏ tiền tố `Up`, kèm tên từng container đang chạy.
- Agent cần quyền đọc `sudo tmux list-sessions`; nếu `sudo` yêu cầu mật khẩu hoặc bị chặn, uptime Tmux sẽ báo không đọc được.
- Sau khi thay `agent.sh`, cần cập nhật/restart agent trên từng VPS giám sát; server tự thêm cột `uam_uptime` vào SQLite khi khởi động.

### Processed block UAM và UAM logs
- Bảng hiển thị theo thứ tự `Total Threads`, `Terminal`, `CPU load`, `Processed block UAM`.
- `Processed block UAM`: lấy giá trị cuối cùng trong 500 dòng log gần nhất của `/root/miner.log` (Tmux) hoặc `docker logs <container_name> --tail 500` (Docker), bỏ dòng `sendto: Invalid argument`. Với nhiều Docker container, hiển thị từng dòng `container name - block`; nếu có hơn 5 mục, hiển thị nút popup.
- `Last Block` được gọi từ `last_block_api_url` và `last_block_api_key` trong `config.json`. API lỗi thì dashboard giữ Last Block gần nhất đã lấy được; nếu chưa từng lấy thành công sẽ hiển thị `—` và ghi trạng thái API chưa cập nhật. Tạo/sửa `lastBlock.txt` trong thư mục server nếu cần thay `fromBlockId`; file rỗng hoặc giá trị `null` sẽ dùng `last_block_from_block` (mặc định `184846`).
- `Missing Block` = Last Block trừ block cuối cùng của Tmux hoặc từng Docker container. Chênh lệch `>= 10` block được đánh dấu đỏ và xuất hiện trong tab `Block thiếu ≥10`.
- `UAM logs`: nút popup hiển thị log Tmux từ `sudo tail -n 100 /root/miner.log` và log riêng của từng container đang chạy từ `docker logs <container_name> --tail 100`.
- PBKey và Version trong popup Thông tin UAM dùng tên container Docker thay vì ID, mỗi container một dòng.
- Cập nhật `server.py` trên VPS trung tâm và `agent.sh` trên từng VPS giám sát; khởi động lại dịch vụ sau khi thay file. Giữ nguyên database và token agent.
- Agent gửi log trong heartbeat, nên log popup được cập nhật theo chu kỳ heartbeat (mặc định 60 giây). Dịch vụ agent chạy bằng root được khuyến nghị; lệnh `sudo tail` phải chạy được không cần nhập mật khẩu.


### Phân loại VPS, cảnh báo tài nguyên và thống kê Terminal
- Thứ tự cột UAM mới: `Total Threads`, `Terminal`, `Processed block UAM`, `CPU load`.
- `Processed block UAM` bổ sung uptime của từng Terminal/container theo dữ liệu Uptime trong popup Thông tin UAM: `Tmux UAM - block - uptime` hoặc `Docker <container name> - block - uptime`.
- Popup `UAM logs` tách Tmux và từng Docker container thành các khung riêng, mỗi khung có vùng cuộn độc lập.
- Có tab `Không có Terminal` cho VPS không phát hiện Tmux UAM hoặc Docker UAM.
- Có tab `Cảnh báo tài nguyên >95%`; VPS được đưa vào danh sách này khi CPU, RAM hoặc disk vượt 95%, đồng thời được tô nền cảnh báo trong bảng.
- Tìm kiếm theo IP và lọc danh sách theo `Tmux UAM` hoặc `Docker UAM`; VPS chạy cả hai xuất hiện ở cả hai bộ lọc Terminal.
- Các ô tổng quan bổ sung tổng UAM Tmux Online và tổng UAM Docker Online, chỉ tính VPS Online. Với VPS chạy đồng thời Tmux và Docker, Tmux được tính là 1 thread; phần còn lại của `Total Threads` được tính cho Docker.
