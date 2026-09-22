#!/bin/bash
# Dependency-free HTTP GET via bash /dev/tcp, for minimal images whose package
# mirrors cannot install curl/wget (e.g. a drifted debian:11). Usage: http-get.sh <url>
# Prints the response body to stdout; non-zero on connection failure.
set -eu

url="$1"
case "$url" in
  http://*) ;;
  *) echo "only http:// is supported" >&2; exit 2 ;;
esac

rest="${url#http://}"
hostport="${rest%%/*}"
path="/${rest#*/}"
host="${hostport%%:*}"
port="${hostport##*:}"
[ "$port" = "$hostport" ] && port=80

exec 3<>"/dev/tcp/${host}/${port}"
printf 'GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n' "$path" "$host" >&3

# Skip response headers.
while IFS= read -r line <&3; do
  line="${line%$'\r'}"
  [ -z "$line" ] && break
done

cat <&3
exec 3<&-
