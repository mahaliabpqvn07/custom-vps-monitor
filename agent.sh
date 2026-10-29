#!/usr/bin/env bash
# Self-registering heartbeat agent. Requires bash, curl, python3 and standard Linux tools.
set -u
# Pass values as positional arguments or environment variables; no secrets are hard-coded here.
SERVER_BASE="${1:-${VPSMON_SERVER_BASE:-}}"
ENROLLMENT_KEY="${2:-${VPSMON_ENROLLMENT_KEY:-}}"
if [[ -z "$SERVER_BASE" || -z "$ENROLLMENT_KEY" ]]; then
    echo "Usage: $0 http://SERVER_PUBLIC_IP:8080 ENROLLMENT_KEY" >&2
    echo "Or set VPSMON_SERVER_BASE and VPSMON_ENROLLMENT_KEY in the environment." >&2
    exit 2
fi
SERVER_BASE="${SERVER_BASE%/}"
if [[ "$SERVER_BASE" != http://* ]]; then
    echo "SERVER_BASE must start with http:// (this build uses plain HTTP)." >&2
    exit 2
fi
INTERVAL=180
STATE_DIR="/var/lib/vps-heartbeat"
ID_FILE="$STATE_DIR/agent_id"
TOKEN_FILE="$STATE_DIR/token"
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

if [[ ! -s "$ID_FILE" ]]; then
    if command -v uuidgen >/dev/null 2>&1; then uuidgen | tr 'A-Z' 'a-z' > "$ID_FILE"
    else python3 -c 'import uuid; print(uuid.uuid4())' > "$ID_FILE"; fi
    chmod 600 "$ID_FILE"
fi
AGENT_ID="$(cat "$ID_FILE")"

register_agent() {
    local response token
    response="$(curl --silent --show-error --fail --max-time 10 -X POST "$SERVER_BASE/api/register" -H "Content-Type: application/json" -H "X-Enrollment-Key: $ENROLLMENT_KEY" --data "{\"agent_id\":\"$AGENT_ID\"}")" || return 1
    token="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' <<< "$response")" || return 1
    [[ -n "$token" ]] || return 1
    printf '%s' "$token" > "$TOKEN_FILE"; chmod 600 "$TOKEN_FILE"
}
if [[ ! -s "$TOKEN_FILE" ]]; then register_agent || { echo "$(date -Is) registration failed" >&2; exit 1; }; fi
TOKEN="$(cat "$TOKEN_FILE")"

send_heartbeat() {
    local host uptime load memory disk uam cpu_model cpu_cores cpu_usage ram_total ram_used os_name disk_total disk_used
    local uam_threads uam_pbkey uam_terminal uam_version uam_uptime uam_processed uam_logs tmux_uam docker_ids docker_count container container_name container_pbkey container_version tmux_pbkey tmux_version tmux_created elapsed docker_running docker_name docker_status tmux_block docker_block tmux_log
    host="$(hostname 2>/dev/null || echo unknown)"
    uptime="$(cut -d' ' -f1 /proc/uptime 2>/dev/null | cut -d. -f1)"; uptime="${uptime:-0}"
    load="$(cut -d' ' -f1 /proc/loadavg 2>/dev/null || echo unknown)"
    read -r memory ram_total ram_used < <(awk '/MemTotal:/ {t=$2} /MemAvailable:/ {a=$2} END {if(t>0){printf "%.0f%% %.0fMiB %.0fMiB",(t-a)*100/t,t/1024,(t-a)/1024}else print "unknown unknown unknown"}' /proc/meminfo 2>/dev/null)
    disk="$(df -P / 2>/dev/null | awk 'NR==2 {print $5}')"
    read -r disk_total disk_used < <(df -hP / 2>/dev/null | awk 'NR==2 {print $2, $3}')
    cpu_model="$(awk -F: '/model name|Hardware/ {gsub(/^[ \t]+/,"",$2); print $2; exit}' /proc/cpuinfo 2>/dev/null)"; cpu_model="${cpu_model:-unknown}"
    cpu_cores="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
    # Sample CPU utilization over one second using /proc/stat.
    read -r cpu1 idle1 < <(awk '/^cpu / {idle=$5+$6; total=0; for(i=2;i<=NF;i++) total+=$i; print total,idle; exit}' /proc/stat)
    sleep 1
    read -r cpu2 idle2 < <(awk '/^cpu / {idle=$5+$6; total=0; for(i=2;i<=NF;i++) total+=$i; print total,idle; exit}' /proc/stat)
    cpu_usage="$(awk -v t1="$cpu1" -v i1="$idle1" -v t2="$cpu2" -v i2="$idle2" 'BEGIN{dt=t2-t1; di=i2-i1; if(dt>0) printf "%.1f%%",100*(dt-di)/dt; else print "unknown"}')"
    os_name="$(. /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-unknown}")"
    if command -v docker >/dev/null 2>&1; then
        if docker inspect -f '{{.State.Running}}' uam_1 2>/dev/null | grep -qx true; then uam="running"
        elif docker inspect uam_1 >/dev/null 2>&1; then uam="stopped"
        else uam="not_found"; fi
    else uam="docker_unavailable"; fi
    # Detect UAM running in the known tmux session and Docker containers based on the requested image.
    tmux_uam=0; docker_ids=""; docker_count=0
    uam_threads=0; uam_pbkey=""; uam_terminal=""; uam_version=""; uam_uptime=""; uam_processed=""; uam_logs=""
    if command -v tmux >/dev/null 2>&1 && tmux has-session -t Utopia 2>/dev/null; then
        tmux_uam=1
        uam_threads=1
        tmux_pbkey="$(cat /opt/uam/PBKEY.txt 2>/dev/null || cat "$HOME/PBKEY.txt" 2>/dev/null || cat "$PWD/PBKEY.txt" 2>/dev/null || true)"
        tmux_version="$(/opt/uam/uam --version 2>&1 || true)"
        tmux_block="$(sudo -n tail -n 500 /root/miner.log 2>&1 | grep -v "sendto: Invalid argument" | awk '/Processed block/ {block=$NF} END {print block}')"
        tmux_log="$(sudo -n tail -n 100 /root/miner.log 2>&1 || true)"
        uam_processed="Tmux UAM - ${tmux_block:-—}"
        uam_logs="===== Tmux UAM ====="$'\n'"$tmux_log"
        tmux_created="$(sudo -n tmux list-sessions -F '#{session_name} #{session_created}' 2>/dev/null | awk '$1 == "Utopia" {print $2; exit}')"
        if [[ "$tmux_created" =~ ^[0-9]+$ ]]; then
            elapsed=$(( $(date +%s) - tmux_created )); (( elapsed < 0 )) && elapsed=0
            uam_uptime="$((elapsed/86400)) ngày - $(((elapsed%86400)/3600)) giờ"
        else
            uam_uptime="Tmux UAM: không đọc được thời điểm tạo session Utopia (cần quyền sudo tmux)"
        fi
        tmux_pbkey="$(printf '%s' "$tmux_pbkey" | tr '\r\n' '  ' | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//')"
        tmux_version="$(printf '%s' "$tmux_version" | tr '\r\n' '  ' | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//')"
        uam_terminal="Tmux UAM"
        uam_pbkey="Tmux UAM: ${tmux_pbkey:-không đọc được PBKEY.txt}"
        uam_version="Tmux UAM: ${tmux_version:-không đọc được version}"
    fi
    if command -v docker >/dev/null 2>&1; then
        docker_ids="$(docker ps -aq --filter ancestor=debian:bookworm-slim 2>/dev/null || true)"
        if [[ -n "$docker_ids" ]]; then
            docker_count="$(printf '%s\n' "$docker_ids" | awk 'NF {n++} END {print n+0}')"
            uam_threads=$((uam_threads + docker_count))
            if [[ -n "$uam_terminal" ]]; then uam_terminal+=", "; fi
            uam_terminal+="Docker UAM"
            while IFS= read -r container; do
                [[ -n "$container" ]] || continue
                container_name="$(docker inspect -f '{{.Name}}' "$container" 2>/dev/null | sed 's#^/##')"; container_name="${container_name:-$container}"
                container_pbkey="$(docker exec "$container" printenv PBKEY 2>/dev/null || true)"
                container_version="$(docker exec "$container" ./opt/uam/uam --version 2>&1 || true)"
                container_pbkey="$(printf '%s' "$container_pbkey" | tr '\r\n' '  ' | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//')"
                container_version="$(printf '%s' "$container_version" | tr '\r\n' '  ' | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//')"
                uam_pbkey+="${uam_pbkey:+$'\n'}Docker ${container_name}: ${container_pbkey:-không đọc được PBKEY}"
                uam_version+="${uam_version:+$'\n'}Docker ${container_name}: ${container_version:-không đọc được version}"
            done <<< "$docker_ids"
            # Uptime is reported for each currently running container, including its name.
            docker_running="$(docker ps --filter ancestor=debian:bookworm-slim --format '{{.Names}}|{{.Status}}' 2>/dev/null || true)"
            while IFS='|' read -r docker_name docker_status; do
                [[ -n "$docker_name" ]] || continue
                docker_status="$(printf '%s' "$docker_status" | sed 's/^Up //')"
                uam_uptime+="${uam_uptime:+$'\n'}Docker ${docker_name}: ${docker_status:-không rõ trạng thái}"
                docker_block="$(docker logs "$docker_name" --tail 500 2>&1 | grep -v "sendto: Invalid argument" | awk '/Processed block/ {block=$NF} END {print block}')"
                uam_processed+="${uam_processed:+$'\n'}${docker_name} - ${docker_block:-—}"
                uam_logs+="${uam_logs:+$'\n'}===== Docker ${docker_name} =====$'\n'$(docker logs "$docker_name" --tail 100 2>&1 || true)"
            done <<< "$docker_running"
        fi
    fi
    uam_terminal="${uam_terminal:-Không phát hiện}"
    uam_pbkey="${uam_pbkey:-Không có PBKey UAM}"
    uam_version="${uam_version:-Không có version UAM}"
    uam_uptime="${uam_uptime:-Không có dữ liệu Uptime UAM}"
    uam_processed="${uam_processed:-Không có Processed block UAM}"
    uam_logs="${uam_logs:-Không có log UAM hoặc chưa phát hiện Terminal UAM}"
    # Convert the literal \n separators into real line breaks for a readable multi-container popup.
    uam_uptime="$(printf '%b' "$uam_uptime")"
    curl --silent --show-error --fail --max-time 10 -X POST "$SERVER_BASE/api/heartbeat" \
      -H "Authorization: Bearer $TOKEN" -H "X-Agent-ID: $AGENT_ID" \
      --data-urlencode "hostname=$host" --data-urlencode "uptime=$uptime" \
      --data-urlencode "load1=$load" --data-urlencode "memory=$memory" --data-urlencode "disk=$disk" \
      --data-urlencode "uam=$uam" --data-urlencode "cpu_model=$cpu_model" --data-urlencode "cpu_cores=$cpu_cores" \
      --data-urlencode "cpu_usage=$cpu_usage" --data-urlencode "ram_total=$ram_total" --data-urlencode "ram_used=$ram_used" \
      --data-urlencode "os_name=$os_name" --data-urlencode "disk_total=$disk_total" --data-urlencode "disk_used=$disk_used" \
      --data-urlencode "uam_threads=$uam_threads" --data-urlencode "uam_pbkey=$uam_pbkey" \
      --data-urlencode "uam_terminal=$uam_terminal" --data-urlencode "uam_version=$uam_version" \
      --data-urlencode "uam_uptime=$uam_uptime" --data-urlencode "uam_processed=$uam_processed" \
      --data-urlencode "uam_logs=$uam_logs" >/dev/null
}
while true; do
    if ! send_heartbeat; then echo "$(date -Is) heartbeat failed for $AGENT_ID" >&2; fi
    sleep "$INTERVAL"
done
