#!/bin/bash

#    Author: Deepseek(R1)
#
# This script is based on wait_for module of Ansible and translated by Deepseek R1.
# For more detail: https://docs.ansible.com/ansible-core/devel/collections/ansible/builtin/wait_for_module.html

# Default parameters
HOST="0.0.0.0"
TIMEOUT=30
CONNECT_TIMEOUT=5
DELAY=0
PORTS=()
ACTIVE_STATES=("ESTABLISHED" "SYN_SENT" "SYN_RECV" "FIN_WAIT1" "FIN_WAIT2" "TIME_WAIT")
_PATH=""
SEARCH_REGEX=""
STATE="started"
EXCLUDE_HOSTS=()
SLEEP=1
MSG=""

ANSI=0
RED=
GREEN=
NC=
# ANSI color codes
if [ $ANSI = 1 ]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  NC='\033[0m' # No Color
fi

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
  --host)
    HOST="$2"
    shift 2
    ;;
  --timeout)
    TIMEOUT="$2"
    shift 2
    ;;
  --connect-timeout)
    CONNECT_TIMEOUT="$2"
    shift 2
    ;;
  --delay)
    DELAY="$2"
    shift 2
    ;;
  --port | --ports)
    IFS=',' read -ra PORTS <<<"$2"
    shift 2
    ;;
  --path)
    _PATH="$2"
    shift 2
    ;;
  --search-regex)
    SEARCH_REGEX="$2"
    shift 2
    ;;
  --state)
    STATE="$2"
    shift 2
    ;;
  --exclude-hosts)
    IFS=',' read -ra EXCLUDE_HOSTS <<<"$2"
    shift 2
    ;;
  --sleep)
    SLEEP="$2"
    shift 2
    ;;
  --msg)
    MSG="$2"
    shift 2
    ;;
  *)
    echo "Unknown option: $1"
    exit 1
    ;;
  esac
done

# Helper functions
fail() {
  local elapsed=$(($(date +%s) - START_TIME))
  echo -e "${RED}✘ ${MSG:-$1}${NC}" >&2
  exit 1
}

success() {
  local elapsed=$(($(date +%s) - START_TIME))
  echo -e "${GREEN}✓ Success${NC}"
  exit 0
}

# Convert port(s) to hex format used in /proc/net/tcp*
ports_to_hex() {
  local ports=("$@")
  local hex_ports=()
  for port in "${ports[@]}"; do
    printf "%04X" "$port" | awk '{print substr($0,3,2) substr($0,1,2)}'
  done
  echo "${hex_ports[@]}"
}

# Convert IPv4 to proc hex format
ipv4_to_proc_hex() {
  IFS='.' read -ra octets <<<"$1"
  printf "%02X%02X%02X%02X" "${octets[3]}" "${octets[2]}" "${octets[1]}" "${octets[0]}"
}

# Get active connections count for multiple ports
get_active_connections() {
  local port_hexes=($1)
  local exclude_ips=("${@:2}")
  local count=0

  for proc_file in /proc/net/tcp /proc/net/tcp6; do
    [ -f "$proc_file" ] || continue

    while read -r line; do
      [[ "$line" =~ ^[[:space:]]*[0-9]+: ]] || continue

      local local_address=$(awk '{print $2}' <<<"$line")
      local remote_address=$(awk '{print $3}' <<<"$line")
      local state=$(awk '{print $4}' <<<"$line")
      local port="${local_address##*:}"

      # Check if port is in target list
      [[ " ${port_hexes[@]} " =~ " $port " ]] || continue

      # Check state
      [[ " 01 02 03 04 05 06 " =~ " $state " ]] || continue

      # Check exclude IPs
      local remote_ip="${remote_address%%:*}"
      for ex_ip in "${exclude_ips[@]}"; do
        [ "$remote_ip" == "$ex_ip" ] && continue 2
      done

      count=$((count + 1))
    done <"$proc_file"
  done

  echo $count
}

# Check multiple ports availability
check_ports_available() {
  local host=$1
  shift
  local ports=("$@")

  for port in "${ports[@]}"; do
    timeout $CONNECT_TIMEOUT bash -c ">/dev/tcp/$host/$port" 2>/dev/null || return 1
  done
  return 0
}

# Main logic
START_TIME=$(date +%s)

# Handle delay
[ "$DELAY" -gt 0 ] && sleep "$DELAY"

# Validate parameters
if [ -n "${PORTS[0]}" ] && [ -n "$_PATH" ]; then
  fail "Cannot specify both ports and path"
fi

case "$STATE" in
absent | stopped)
  END_TIME=$((START_TIME + TIMEOUT))
  while [ $(date +%s) -lt $END_TIME ]; do
    if [ -n "$_PATH" ]; then
      [ ! -e "$_PATH" ] && success
    else
      check_ports_available "$HOST" "${PORTS[@]}" || success
    fi
    sleep "$SLEEP"
  done
  fail "Timeout waiting for $_PATH:-$HOST:${PORTS[@]}} to stop"
  ;;

started | present)
  END_TIME=$((START_TIME + TIMEOUT))
  while [ $(date +%s) -lt $END_TIME ]; do
    if [ -n "$_PATH" ]; then
      if [ -e "$_PATH" ]; then
        if [ -n "$SEARCH_REGEX" ]; then
          grep -q "$SEARCH_REGEX" "$_PATH" && success
        else
          success
        fi
      fi
    else
      check_ports_available "$HOST" "${PORTS[@]}" && {
        if [ -n "$SEARCH_REGEX" ]; then
          (timeout $TIMEOUT tail -f /dev/null | nc "$HOST" "${PORTS[0]}" | grep -q "$SEARCH_REGEX") && success
        else
          success
        fi
      }
    fi
    sleep "$SLEEP"
  done
  fail "Timeout waiting for $_PATH:-$HOST:${PORTS[@]}}"
  ;;

drained)
  [ -z "${PORTS[0]}" ] && fail "Port(s) required for drained state"
  PORT_HEXES=($(ports_to_hex "${PORTS[@]}"))
  EXCLUDE_IPS=()

  for host in "${EXCLUDE_HOSTS[@]}"; do
    while IFS=$'\n' read -r ip; do
      [ -n "$ip" ] && EXCLUDE_IPS+=("$(ipv4_to_proc_hex "$ip")")
    done < <(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u)
  done

  END_TIME=$((START_TIME + TIMEOUT))
  while [ $(date +%s) -lt $END_TIME ]; do
    [ $(get_active_connections "${PORT_HEXES[*]}" "${EXCLUDE_IPS[@]}") -eq 0 ] && success
    sleep "$SLEEP"
  done
  fail "Timeout waiting for $HOST:${PORTS[@]} to drain"
  ;;

*)
  fail "Invalid state: $STATE"
  ;;
esac
