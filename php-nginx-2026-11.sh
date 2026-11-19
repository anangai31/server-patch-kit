#!/usr/bin/env bash
# =============================================================================
#  php-nginx-2026-11.sh  (PHP + nginx, host & container Docker/Podman)
#  Repo: https://github.com/anangai31/server-patch-kit
#  - Mengecek semua versi PHP (multi-versi) terhadap rilis keamanan PHP
#    19 Nov 2026, update opsional, dan mitigasi sementara untuk versi EOL.
#  - Mengecek nginx terhadap advisory 18 Nov 2026 ("nginx2root",
#    CVE-2026-123007/-123633/-123634/-121810/-113425; fix: 1.30.7 / 1.31.9),
#    termasuk fitur konfigurasi mana yang membuat server terpapar.
#  - Container Docker/Podman yang berjalan ikut dicek (HANYA BACA). Update
#    dan mitigasi untuk container tidak dilakukan otomatis; script memberi
#    langkah yang perlu Anda jalankan (pull image + buat ulang container).
#
#  Pemakaian (pin ke tag/commit, jangan ke branch main):
#    Laporan saja (tidak mengubah apa pun; sudo agar config & Docker terbaca):
#      curl -fsSL https://raw.githubusercontent.com/anangai31/server-patch-kit/v1.3.0/php-nginx-2026-11.sh | sudo bash -s -- --check
#    Interaktif (menu):
#      curl -fsSL https://raw.githubusercontent.com/anangai31/server-patch-kit/v1.3.0/php-nginx-2026-11.sh | sudo bash
#    Non-interaktif:
#      ... | sudo bash -s -- --update --mitigate --yes
#
#  Opsi:
#    --check             Hanya laporan (default bila tidak ada terminal)
#    --update            Update PHP dan nginx yang belum di-patch
#    --mitigate          Mitigasi PHP (session.upload_progress.enabled = Off)
#    --nginx-no-http2    Mitigasi nginx: matikan HTTP/2 (hanya bila diminta)
#    --all               --update + --mitigate (HTTP/2 tidak disentuh)
#    --system-upgrade    Update & upgrade SEMUA paket sistem (apt update && apt upgrade
#                        / dnf upgrade). Tidak menghapus paket; config lama dipertahankan.
#    --skip-php          Lewati semua bagian PHP
#    --skip-nginx        Lewati semua bagian nginx
#    --skip-containers   Jangan memeriksa container Docker/Podman
#    --yes               Jawab "ya" untuk semua konfirmasi
#    --no-restart        Jangan restart PHP-FPM / web server
#    -h, --help          Bantuan
#
#  Kode keluar: 0 = semua aman, 1 = ada yang rentan/EOL, 2 = error.
#
#  Keamanan: script tidak pernah menghapus file atau paket. Setiap file
#  konfigurasi dibackup ke /var/backups/php-patch-check/<waktu>/ sebelum diubah. Perubahan
#  nginx divalidasi dengan "nginx -t" dan dikembalikan bila gagal.
# =============================================================================

SCRIPT_VERSION="1.3.0"
SCRIPT_NAME="server-patch-kit · php-nginx-2026-11"

# ---- Acuan PHP (perbarui saat ada rilis baru) --------------------------------
PHP_RELEASE_DATE="19 Nov 2026"
declare -A MIN_PATCHED=(
  [8.6]="8.6.0"
  [8.5]="8.5.13"
  [8.4]="8.4.28"
  [8.3]="8.3.37"
  [8.2]="8.2.36"
)

# ---- Acuan nginx Open Source -------------------------------------------------
NGX_ADVISORY="18 Nov 2026 (nginx2root)"
NGX_FIX_STABLE="1.30.7"     # cabang stable 1.30.x
NGX_FIX_MAINLINE="1.31.9"   # cabang mainline 1.31.x (dan semua versi di atasnya)
NGX_PLUS_FIX="37.0.8.1 / 37.3.0.1"

TS="$(date +%Y%m%d-%H%M%S)"
START_EPOCH="$(date +%s)"
START_HUMAN="$(date '+%Y-%m-%d %H:%M:%S %Z (UTC%:z)')"
# Backup disimpan di luar direktori konfigurasi, supaya tidak ikut ter-include
# oleh pola seperti "include sites-enabled/*;" di nginx.
BACKUP_DIR="/var/backups/php-patch-check/${TS}-$$"
ASSUME_YES=0; DO_RESTART=1; FROM_FLAG=0; SKIP_PHP=0; SKIP_NGX=0; SKIP_CTR=0; CHECK_ONLY=0; CTR_DENIED=0
A_PHP_UPD=0; A_PHP_MIT=0; A_NGX_UPD=0; A_NGX_H2=0; A_SYS=0
php_upd=(); php_mit=(); ngx_vul=(); ctr_vul=0
PKG=""; HAS_TTY=0
declare -a E_BRANCH=() E_FULL=() E_UP=() E_KIND=() E_BIN=() E_ORIGIN=() E_STATUS=()
declare -a X_BIN=() X_FULL=() X_UP=() X_KIND=() X_ORIGIN=() X_STATUS=() X_PKG=() X_CONF=() X_FEAT=()
# Info container per entri (kosong = instalasi di host)
declare -a E_CTR=() E_RT=() E_IMG=() E_WD=() X_CTR=() X_RT=() X_IMG=() X_WD=()
declare -A RESTART_SET=()
CHOSEN=()

# ---------------------------------------------------------------- tampilan ---
if [ -t 1 ]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; B=$'\e[1m'; D=$'\e[2m'; N=$'\e[0m'
else
  R=""; G=""; Y=""; C=""; B=""; D=""; N=""
fi
info() { printf '%s\n' "${B}${C}==>${N} ${B}$*${N}"; }
ok()   { printf '%s\n' "  ${G}✔${N} $*"; }
warn() { printf '%s\n' "  ${Y}!${N} $*"; }
err()  { printf '%s\n' "  ${R}✘${N} $*" >&2; }

usage() {
  cat <<'EOF'
server-patch-kit php-nginx-2026-11: cek PHP & nginx (host + container) terhadap advisory terbaru.
  --check  --update  --mitigate  --nginx-no-http2  --all  --system-upgrade
  --skip-php  --skip-nginx  --skip-containers  --yes  --no-restart  -h|--help
Contoh: curl -fsSL <URL> | sudo bash -s -- --update --mitigate --yes
EOF
}

# --------------------------------------------------------------- input tty ---
# Saat dijalankan via "curl | bash", stdin berisi script, jadi input dibaca dari /dev/tty.
detect_tty() { if { : </dev/tty; } 2>/dev/null; then HAS_TTY=1; fi; }
ask_yn() {
  [ "$ASSUME_YES" -eq 1 ] && return 0
  [ "$HAS_TTY" -eq 1 ] || return 1
  local a; read -r -p "  $1 [y/N] " a </dev/tty || return 1
  [[ "$a" =~ ^[yY] ]]
}
ask_line() { local a=""; read -r -p "$1" a </dev/tty || a=""; printf '%s' "$a"; }

# ------------------------------------------------------------------ helper ---
version_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]; }

detect_pkg() {
  if command -v apt-get >/dev/null 2>&1; then PKG=apt
  elif command -v dnf >/dev/null 2>&1; then PKG=dnf
  elif command -v yum >/dev/null 2>&1; then PKG=yum
  fi
}

classify() {
  case "$1" in
    /opt/remi/*)   echo remi ;;
    /opt/cpanel/*) echo cpanel ;;
    /opt/plesk/*)  echo plesk ;;
    /usr/local/*)  echo source ;;
    /usr/bin/*|/usr/sbin/*)
      if [ "$PKG" = apt ]; then echo deb; elif [ -n "$PKG" ]; then echo rpm; else echo other; fi ;;
    *) echo other ;;
  esac
}

# Upgrade paket via apt, dengan pratinjau dan konfirmasi. $1=label, sisanya paket.
apt_upgrade() {
  local label="$1"; shift
  local pkgs=("$@")
  [ "${#pkgs[@]}" -gt 0 ] || { warn "Tidak menemukan paket terpasang untuk $label."; return 3; }
  apt-get update -qq || { err "apt-get update gagal"; return 1; }
  echo "  Pratinjau (simulasi, belum mengubah apa pun):"
  apt-get -s install --only-upgrade "${pkgs[@]}" 2>/dev/null | grep -E '^Inst' | sed 's/^/    /' \
    || { ok "Tidak ada pembaruan untuk $label di repo yang aktif."; return 3; }
  ask_yn "Upgrade ${#pkgs[@]} paket $label?" || { warn "Dibatalkan."; return 3; }
  DEBIAN_FRONTEND=noninteractive UCF_FORCE_CONFFOLD=1 apt-get install -y --only-upgrade \
    -o Dpkg::Options::=--force-confold "${pkgs[@]}"
}

# Upgrade paket via dnf/yum. $1=label, sisanya pola paket.
rpm_upgrade() {
  local label="$1"; shift
  echo "  Pratinjau:"
  "$PKG" -q check-update "$@" | sed 's/^/    /'
  [ "${PIPESTATUS[0]}" -eq 100 ] || { ok "Tidak ada pembaruan untuk $label di repo yang aktif."; return 3; }
  ask_yn "Upgrade paket $*?" || { warn "Dibatalkan."; return 3; }
  "$PKG" upgrade -y "$@"
}

backup_file() { # $1 = file; salin ke BACKUP_DIR dengan path lengkap
  local dst="${BACKUP_DIR}$1"
  mkdir -p "$(dirname "$dst")" && cp -pL "$1" "$dst"
}

# Asal paket .deb: hanya "repo distro" bila versinya memang build Ubuntu/Debian.
# Selain itu, sumber repo dibaca dari "apt-cache policy" (hanya baca).
deb_origin() { # paket
  local v src host
  v="$(dpkg-query -W -f='${Version}' "$1" 2>/dev/null)"
  [ -n "$v" ] || { echo "-"; return; }
  if [[ "$v" == *sury* ]]; then echo "ondrej/sury"; return; fi
  if [[ "$v" =~ ubuntu[0-9] || "$v" =~ \+deb[0-9]+u ]]; then echo "repo distro"; return; fi
  src="$(apt-cache policy "$1" 2>/dev/null | awk '/\*\*\*/{getline; print $2; exit}')"
  case "$src" in
    *ondrej*)            echo "ondrej/sury" ;;
    *nginx.org*)         echo "nginx.org" ;;
    ""|/var/lib/dpkg/*)  echo "lokal/manual" ;;
    *) host="${src#*://}"; host="${host%%/*}"; echo "${host:0:17}" ;;
  esac
}

deb_installed() { # pola paket → nama paket berstatus ii
  dpkg-query -W -f='${db:Status-Abbrev} ${binary:Package}\n' "$@" 2>/dev/null | awk '$1 ~ /^ii/ {print $2}'
}

# =============================================================================
#                                    PHP
# =============================================================================
php_origin() { # kind branch realpath
  local v=""
  case "$1" in
    deb) deb_origin "php$2-common" ;;
    rpm) v="$(rpm -qf --qf '%{RELEASE}' "$3" 2>/dev/null)"
         if [[ "$v" == *remi* ]]; then echo "remi"; elif [ -n "$v" ]; then echo "repo distro"; else echo "-"; fi ;;
    remi)   echo "remi (SCL)" ;;
    cpanel) echo "cPanel EA" ;;
    plesk)  echo "Plesk" ;;
    source) echo "kompilasi manual" ;;
    *)      echo "-" ;;
  esac
}

php_status() { # upstream branch
  local maj="${2%%.*}" min="${2#*.}"
  if [ "$maj" -lt 8 ] || { [ "$maj" -eq 8 ] && [ "$min" -le 1 ]; }; then echo EOL; return; fi
  if [ -n "${MIN_PATCHED[$2]:-}" ]; then
    if version_ge "$1" "${MIN_PATCHED[$2]}"; then echo PATCHED; else echo VULNERABLE; fi
  else
    echo UNKNOWN
  fi
}

php_discover() {
  local cands=() b real line full up branch kind key
  declare -A seen=()
  shopt -s nullglob
  cands+=( /usr/bin/php[0-9].[0-9] /usr/bin/php[0-9].[0-9][0-9]
           /usr/sbin/php-fpm[0-9].[0-9] /usr/sbin/php-fpm[0-9].[0-9][0-9] )
  cands+=( /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm )
  cands+=( /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/sbin/php-fpm )
  cands+=( /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm )
  cands+=( /usr/bin/php /usr/sbin/php-fpm /usr/local/bin/php /usr/local/sbin/php-fpm )
  shopt -u nullglob
  b="$(command -v php 2>/dev/null)" && cands+=("$b")

  for b in "${cands[@]}"; do
    [ -x "$b" ] || continue
    real="$(readlink -f "$b")"
    line="$("$b" -v 2>/dev/null | head -n1)" || continue
    full="$(awk '{print $2}' <<<"$line")"
    up="$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' <<<"$full")" || continue
    branch="${up%.*}"
    kind="$(classify "$real")"
    key="${kind}|${branch}|${full}"
    [ -n "${seen[$key]:-}" ] && continue
    seen[$key]=1
    E_BRANCH+=("$branch"); E_FULL+=("$full"); E_UP+=("$up"); E_KIND+=("$kind"); E_BIN+=("$b")
    E_ORIGIN+=("$(php_origin "$kind" "$branch" "$real")")
    E_STATUS+=("$(php_status "$up" "$branch")")
    E_CTR+=(""); E_RT+=(""); E_IMG+=(""); E_WD+=("")
  done
}

php_report() {
  local i st col need hint=0
  info "PHP (acuan rilis keamanan ${PHP_RELEASE_DATE})"
  if [ "${#E_BRANCH[@]}" -eq 0 ]; then warn "Tidak ada instalasi PHP terdeteksi."; echo; return; fi
  printf '  %-4s %-7s %-26s %-17s %-11s %s\n' "No" "Cabang" "Versi terpasang" "Sumber" "Minimum" "Status"
  for i in "${!E_BRANCH[@]}"; do
    st="${E_STATUS[$i]}"; need="${MIN_PATCHED[${E_BRANCH[$i]}]:--}"
    case "$st" in
      PATCHED)    col="${G}AMAN${N}" ;;
      VULNERABLE) col="${R}RENTAN${N}" ;;
      EOL)        col="${R}EOL — tidak ada patch${N}"; need="upgrade" ;;
      *)          col="${Y}TIDAK DIKENAL${N}" ;;
    esac
    printf '  %-4s %-7s %-26s %-17s %-11s %s\n' "$((i+1))" "${E_BRANCH[$i]}" "${E_FULL[$i]}" "${E_ORIGIN[$i]}" "$need" "$col"
    printf '  %s\n' "${D}     ${E_BIN[$i]}${N}"
    if [ "${E_ORIGIN[$i]}" = "repo distro" ] && [ "$st" != PATCHED ]; then hint=1; fi
  done
  if [ "$hint" -eq 1 ]; then
    warn "Paket PHP dari repo resmi distro sering menerima backport patch tanpa mengubah"
    warn "nomor versi upstream. Cek security tracker distro Anda untuk CVE terkait."
  fi
  echo
}

# ------------------------------------------------------------ restart --------
queue_restart_php() { # branch kind
  local br="$1" kind="$2" nd="${1/./}" f
  case "$kind" in
    deb)    RESTART_SET["php${br}-fpm"]=1 ;;
    rpm)    RESTART_SET["php-fpm"]=1 ;;
    remi)   RESTART_SET["php${nd}-php-fpm"]=1 ;;
    cpanel) RESTART_SET["ea-php${nd}-php-fpm"]=1 ;;
    plesk)  RESTART_SET["plesk-php${nd}-fpm"]=1 ;;
  esac
  for f in /etc/apache2/mods-enabled/php*.load; do [ -e "$f" ] && RESTART_SET["apache2"]=1; done
  if grep -lqs 'php' /etc/httpd/conf.modules.d/*.conf 2>/dev/null; then RESTART_SET["httpd"]=1; fi
  RESTART_SET["lsws"]=1
}

run_restarts() {
  [ "${#RESTART_SET[@]}" -gt 0 ] || return 0
  local s active=()
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl tidak ada. Restart manual: ${!RESTART_SET[*]}"; return
  fi
  for s in "${!RESTART_SET[@]}"; do
    systemctl is-active --quiet "$s" 2>/dev/null && active+=("$s")
  done
  [ "${#active[@]}" -gt 0 ] || { warn "Tidak ada layanan aktif yang perlu di-restart."; return; }
  info "Restart layanan agar semua worker memakai biner/konfigurasi baru"
  printf '   - %s\n' "${active[@]}"
  if [ "$DO_RESTART" -eq 0 ]; then
    warn "--no-restart: dilewati. Perubahan BELUM berlaku sampai layanan di-restart."; return
  fi
  if ask_yn "Restart layanan di atas sekarang? (ada jeda singkat)"; then
    for s in "${active[@]}"; do
      if systemctl restart "$s"; then ok "restart $s"; else err "gagal restart $s (cek: journalctl -u $s)"; fi
    done
  else
    warn "Restart dilewati. Jalankan manual: systemctl restart ${active[*]}"
  fi
}

# ------------------------------------------------------------- PHP update ----
php_update() {
  local i="$1" br="${E_BRANCH[$1]}" kind="${E_KIND[$1]}" nd="${E_BRANCH[$1]/./}" rc pkgs=()
  info "Update PHP ${E_FULL[$i]} (${E_ORIGIN[$i]})"
  if [ "${E_STATUS[$i]}" = EOL ] && [ "${E_ORIGIN[$i]}" != "repo distro" ]; then
    warn "PHP $br sudah EOL di upstream: tidak ada patch. Gunakan mitigasi dan rencanakan migrasi ke 8.2+."
    return
  fi
  case "$kind" in
    deb)    mapfile -t pkgs < <(deb_installed "php${br}" "php${br}-*"); apt_upgrade "PHP $br" "${pkgs[@]}"; rc=$? ;;
    rpm)    rpm_upgrade "PHP" "php" "php-*"; rc=$? ;;
    remi)   rpm_upgrade "PHP $br" "php${nd}" "php${nd}-*"; rc=$? ;;
    cpanel) rpm_upgrade "PHP $br" "ea-php${nd}" "ea-php${nd}-*"; rc=$? ;;
    plesk)  warn "Plesk: update lewat Tools & Settings > Updates."; return ;;
    *)      warn "Instalasi ${E_ORIGIN[$i]} (${E_BIN[$i]}) harus di-update manual."; return ;;
  esac
  [ "$rc" -eq 3 ] && return
  if [ "$rc" -eq 0 ]; then
    ok "Selesai. Versi sekarang: $("${E_BIN[$i]}" -v 2>/dev/null | head -n1 | awk '{print $2}')"
    queue_restart_php "$br" "$kind"
  else
    err "Update gagal (kode $rc). Tidak ada file yang dihapus; cek output di atas."
  fi
}

# ----------------------------------------------------------- PHP mitigasi ----
ini_files_for() {
  local i="$1" br="${E_BRANCH[$1]}" nd="${E_BRANCH[$1]/./}" f
  case "${E_KIND[$i]}" in
    deb)    for f in /etc/php/"$br"/*/php.ini; do [[ "$f" == */cli/* ]] && continue; [ -f "$f" ] && echo "$f"; done ;;
    remi)   echo "/etc/opt/remi/php${nd}/php.ini" ;;
    cpanel) echo "/opt/cpanel/ea-php${nd}/root/etc/php.ini" ;;
    plesk)  echo "/opt/plesk/php/${br}/etc/php.ini" ;;
    rpm)    echo "/etc/php.ini" ;;
    *)      "${E_BIN[$i]}" -i 2>/dev/null | awk -F' => ' '/^Loaded Configuration File/ && $2 != "(none)" {print $2}' ;;
  esac
}

fpm_bin_for() {
  local i="$1" br="${E_BRANCH[$1]}" nd="${E_BRANCH[$1]/./}"
  case "${E_KIND[$i]}" in
    deb)    echo "/usr/sbin/php-fpm${br}" ;;
    rpm)    echo "/usr/sbin/php-fpm" ;;
    remi)   echo "/opt/remi/php${nd}/root/usr/sbin/php-fpm" ;;
    cpanel) echo "/opt/cpanel/ea-php${nd}/root/usr/sbin/php-fpm" ;;
    plesk)  echo "/opt/plesk/php/${br}/sbin/php-fpm" ;;
  esac
}

KEY_RE='session\.upload_progress\.enabled'

apply_ini() {
  local f="$1"
  [ -f "$f" ] || { warn "Tidak ditemukan: $f"; return 1; }
  if grep -Eiq "^[[:space:]]*${KEY_RE}[[:space:]]*=[[:space:]]*\"?(off|0|false|no)\"?[[:space:]]*$" "$f" \
     && ! grep -Eiq "^[[:space:]]*${KEY_RE}[[:space:]]*=[[:space:]]*\"?(on|1|true|yes)" "$f"; then
    ok "Sudah Off: $f"; return 0
  fi
  backup_file "$f" || { err "Gagal backup $f — file ini dilewati."; return 1; }
  if grep -Eq "^[[:space:]]*;?[[:space:]]*${KEY_RE}[[:space:]]*=" "$f"; then
    sed -i --follow-symlinks -E \
      "s/^[[:space:]]*;?[[:space:]]*${KEY_RE}[[:space:]]*=.*/session.upload_progress.enabled = Off/" "$f"
  elif grep -q '^\[Session\]' "$f"; then
    sed -i --follow-symlinks '/^\[Session\]/a session.upload_progress.enabled = Off' "$f"
  else
    printf '\n; mitigasi sementara php-patch-check %s\nsession.upload_progress.enabled = Off\n' "$TS" >> "$f"
  fi
  ok "Diubah: $f  ${D}(backup: ${BACKUP_DIR}${f})${N}"
}

scan_overrides() {
  local i="$1" br="${E_BRANCH[$1]}" nd="${E_BRANCH[$1]/./}" dirs=() d existing=() hits
  case "${E_KIND[$i]}" in
    deb)    dirs=("/etc/php/$br") ;;
    remi)   dirs=("/etc/opt/remi/php${nd}") ;;
    cpanel) dirs=("/opt/cpanel/ea-php${nd}/root/etc") ;;
    plesk)  dirs=("/opt/plesk/php/${br}/etc") ;;
    rpm)    dirs=("/etc/php.d" "/etc/php-fpm.d") ;;
  esac
  dirs+=(/etc/apache2 /etc/httpd /etc/nginx /usr/local/lsws/conf)
  for d in "${dirs[@]}"; do [ -d "$d" ] && existing+=("$d"); done
  [ "${#existing[@]}" -gt 0 ] || return 0
  hits="$(grep -rIEn 'upload_progress\.enabled' "${existing[@]}" 2>/dev/null \
          | grep -vE ':[0-9]+:[[:space:]]*[;#]' \
          | grep -viE '(=|[[:space:]])[[:space:]]*"?(off|0|false|no)"?[[:space:]]*;?[[:space:]]*$')"
  if [ -n "$hits" ]; then
    warn "Ditemukan pengaturan yang bisa MENIMPA mitigasi (pool FPM / web server):"
    sed 's/^/      /' <<<"$hits"
    warn "Ubah baris di atas menjadi Off/0 secara manual, lalu restart layanannya."
  fi
}

verify_mitigation() {
  local i="$1" f fpm
  echo "  Verifikasi file:"
  while IFS= read -r f; do
    [ -f "$f" ] && grep -H "upload_progress.enabled" "$f" | grep -v ':[[:space:]]*;' | sed 's/^/    /'
  done < <(ini_files_for "$i")
  fpm="$(fpm_bin_for "$i")"
  if [ -n "$fpm" ] && [ -x "$fpm" ]; then
    echo "  Nilai efektif menurut $(basename "$fpm") (berlaku setelah restart):"
    "$fpm" -i 2>/dev/null | grep -i '^session.upload_progress.enabled' | sed 's/^/    /'
  fi
}

php_mitigate() {
  local i="$1" files=() f changed=0
  info "Mitigasi sementara PHP ${E_FULL[$i]} (${E_ORIGIN[$i]})"
  mapfile -t files < <(ini_files_for "$i")
  [ "${#files[@]}" -gt 0 ] || { warn "Tidak menemukan php.ini untuk ${E_BIN[$i]}."; return; }
  printf '   - %s\n' "${files[@]}"
  ask_yn "Set session.upload_progress.enabled = Off pada file di atas (dengan backup)?" \
    || { warn "Dibatalkan."; return; }
  for f in "${files[@]}"; do apply_ini "$f" && changed=1; done
  scan_overrides "$i"
  verify_mitigation "$i"
  [ "$changed" -eq 1 ] && queue_restart_php "${E_BRANCH[$i]}" "${E_KIND[$i]}"
  if [ "${E_STATUS[$i]}" = EOL ]; then
    warn "Mitigasi ini hanya mengurangi satu jalur serangan; PHP ${E_BRANCH[$i]} tetap tidak aman."
    warn "Rencanakan migrasi ke PHP 8.2+ (8.2 sendiri EOL 31 Des 2026)."
  fi
}

# =============================================================================
#                                   NGINX
# =============================================================================
ngx_status() { # upstream_version is_plus
  [ "$2" = 1 ] && { echo PLUS; return; }
  if version_ge "$1" "$NGX_FIX_MAINLINE"; then echo PATCHED
  elif [[ "$1" == 1.30.* ]] && version_ge "$1" "$NGX_FIX_STABLE"; then echo PATCHED
  else echo VULNERABLE; fi
}

ngx_origin_pkg() { # kind realpath → "origin|package"
  local p="" v="" o="-"
  case "$1" in
    deb)
      p="$(dpkg-query -S "$2" 2>/dev/null | head -n1 | cut -d: -f1)"
      [ -n "$p" ] && o="$(deb_origin "$p")" ;;
    rpm)
      p="$(rpm -qf --qf '%{NAME}' "$2" 2>/dev/null)"; v="$(rpm -qf --qf '%{RELEASE}' "$2" 2>/dev/null)"
      if   [[ "$p" == ea-* ]]; then o="cPanel EA"
      elif [[ "$p" == sw-* ]]; then o="Plesk"
      elif [[ "$v" == *ngx* ]]; then o="nginx.org"
      elif [ -n "$p" ] && [[ "$p" != *"not owned"* ]]; then o="repo distro"
      else p=""; fi ;;
    source) o="kompilasi manual" ;;
  esac
  printf '%s|%s' "$o" "$p"
}

# Dump konfigurasi efektif (tanpa komentar). Butuh root agar "nginx -T" bisa membaca semua file.
ngx_conf_dump() { # bin
  local out
  out="$("$1" -T 2>/dev/null)"
  if [ -z "$out" ]; then
    local cp; cp="$("$1" -V 2>&1 | grep -oE -- '--conf-path=[^ ]+' | cut -d= -f2)"
    out="$(cat "$(dirname "${cp:-/etc/nginx/nginx.conf}")"/{nginx.conf,conf.d/*.conf,sites-enabled/*} 2>/dev/null)"
  fi
  sed 's/#.*$//' <<<"$out"
}

ngx_features() { # dump → daftar fitur terpapar dipisah koma
  local d="$1" f=()
  grep -Eq '(^|[[:space:];{])http2[[:space:]]+on[[:space:]]*;|listen[^;]*[[:space:]]http2([[:space:];]|$)' <<<"$d" \
    && f+=("HTTP/2 → CVE-2026-123007, -123633")
  grep -Eq '(^|[[:space:];{])http3[[:space:]]+on[[:space:]]*;|listen[^;]*[[:space:]]quic([[:space:];]|$)' <<<"$d" \
    && f+=("HTTP/3/QUIC → CVE-2026-121810")
  if grep -Eq '(^|[[:space:]])mail[[:space:]]*\{' <<<"$d" && grep -Eq '(^|[[:space:]])auth_http[[:space:]]' <<<"$d"; then
    f+=("mail proxy + auth_http → CVE-2026-113425")
  fi
  if grep -Eq '(^|[[:space:];{])resolver[[:space:]]' <<<"$d" \
     && grep -Eq '(^|[[:space:];{])(ssi[[:space:]]+on|mirror[[:space:]]+[^o])' <<<"$d"; then
    f+=("resolver + SSI/mirror → CVE-2026-123634")
  fi
  local IFS=';'; printf '%s' "${f[*]}"
}

ngx_discover() {
  local cands=() b real line prod up plus kind key op
  declare -A seen=()
  shopt -s nullglob
  cands+=( /usr/sbin/nginx /usr/bin/nginx /usr/local/sbin/nginx /usr/local/nginx/sbin/nginx
           /usr/local/openresty/nginx/sbin/nginx /opt/*/sbin/nginx /opt/*/nginx/sbin/nginx )
  shopt -u nullglob
  b="$(command -v nginx 2>/dev/null)" && cands+=("$b")
  for b in "${cands[@]}"; do
    [ -x "$b" ] || continue
    real="$(readlink -f "$b")"
    [ -n "${seen[$real]:-}" ] && continue
    seen[$real]=1
    line="$("$b" -v 2>&1 | head -n1)"
    [[ "$line" == *"version:"* ]] || continue
    prod="$(sed -E 's/.*version:[[:space:]]*([^/]+)\/.*/\1/' <<<"$line")"
    up="$(grep -oE '/[0-9]+\.[0-9]+\.[0-9]+' <<<"$line" | head -n1 | tr -d /)"
    [ -n "$up" ] || continue
    plus=0; [[ "$line" == *nginx-plus* ]] && plus=1
    kind="$(classify "$real")"; [ "$prod" = openresty ] && kind=openresty
    op="$(ngx_origin_pkg "$kind" "$real")"
    X_BIN+=("$b"); X_UP+=("$up"); X_KIND+=("$kind")
    X_FULL+=("$(sed -E 's/.*version:[[:space:]]*//' <<<"$line")")
    X_ORIGIN+=("${op%%|*}"); X_PKG+=("${op#*|}")
    X_STATUS+=("$(ngx_status "$up" "$plus")")
    X_FEAT+=("$(ngx_features "$(ngx_conf_dump "$b")")")
    X_CTR+=(""); X_RT+=(""); X_IMG+=(""); X_WD+=("")
  done
}

ngx_report() {
  local i st col need hint=0
  info "nginx (acuan advisory ${NGX_ADVISORY})"
  if [ "${#X_BIN[@]}" -eq 0 ]; then warn "nginx tidak terdeteksi."; echo; return; fi
  [ "$(id -u)" -ne 0 ] && warn "Bukan root: pembacaan konfigurasi bisa tidak lengkap (nginx -T)."
  printf '  %-4s %-34s %-17s %-15s %s\n' "No" "Versi terpasang" "Sumber" "Minimum" "Status"
  for i in "${!X_BIN[@]}"; do
    st="${X_STATUS[$i]}"
    if [[ "${X_UP[$i]}" == 1.31.* ]] || version_ge "${X_UP[$i]}" 1.32.0; then need="$NGX_FIX_MAINLINE"; else need="$NGX_FIX_STABLE"; fi
    case "$st" in
      PATCHED)    col="${G}AMAN${N}" ;;
      VULNERABLE) col="${R}RENTAN${N}" ;;
      PLUS)       col="${Y}NGINX Plus — cek F5${N}"; need="$NGX_PLUS_FIX" ;;
    esac
    printf '  %-4s %-34s %-17s %-15s %s\n' "$((i+1))" "${X_FULL[$i]}" "${X_ORIGIN[$i]}" "$need" "$col"
    printf '  %s\n' "${D}     ${X_BIN[$i]}${N}"
    if [ "$st" != PATCHED ]; then
      if [ -n "${X_FEAT[$i]}" ]; then
        local IFS=';' ft
        for ft in ${X_FEAT[$i]}; do printf '       %s\n' "${R}terpapar:${N} $ft"; done
        unset IFS
      else
        printf '       %s\n' "${D}tidak ditemukan fitur pemicu di konfigurasi; tetap disarankan update${N}"
      fi
    fi
    [ "${X_ORIGIN[$i]}" = "repo distro" ] && [ "$st" = VULNERABLE ] && hint=1
  done
  if [ "$hint" -eq 1 ]; then
    warn "nginx dari repo distro bisa sudah berisi backport tanpa nomor versi berubah."
    warn "Cek security tracker distro (mis. ubuntu.com/security) untuk CVE di atas."
  fi
  echo
}

ngx_update() {
  local i="$1" rc pkgs=()
  info "Update nginx ${X_FULL[$i]} (${X_ORIGIN[$i]})"
  case "${X_KIND[$i]}" in
    deb)
      mapfile -t pkgs < <(deb_installed "nginx" "nginx-*" "libnginx-mod-*")
      apt_upgrade "nginx" "${pkgs[@]}"; rc=$? ;;
    rpm)
      if [ "${X_ORIGIN[$i]}" = "cPanel EA" ]; then rpm_upgrade "nginx" "ea-nginx" "ea-nginx-*"
      elif [ "${X_ORIGIN[$i]}" = "Plesk" ]; then warn "Plesk: update lewat Tools & Settings > Updates."; return
      else rpm_upgrade "nginx" "nginx" "nginx-*"; fi
      rc=$? ;;
    openresty) warn "OpenResty: perbarui ke rilis OpenResty yang memuat fix nginx $NGX_FIX_STABLE/$NGX_FIX_MAINLINE."; return ;;
    *) warn "nginx ${X_ORIGIN[$i]} (${X_BIN[$i]}) harus di-update/di-build ulang manual."; return ;;
  esac
  [ "$rc" -eq 3 ] && return
  if [ "$rc" -ne 0 ]; then err "Update gagal (kode $rc). Cek output di atas."; return; fi
  ok "Selesai. Versi sekarang: $("${X_BIN[$i]}" -v 2>&1 | sed -E 's/.*version:[[:space:]]*//')"
  if "${X_BIN[$i]}" -t >/dev/null 2>&1; then
    RESTART_SET["nginx"]=1
  else
    err "nginx -t GAGAL setelah update; nginx TIDAK akan di-restart. Periksa: ${X_BIN[$i]} -t"
  fi
}

# Matikan HTTP/2 (menutup CVE-2026-123007 & -123633 saja). Backup + validasi + rollback.
ngx_disable_http2() {
  local i="$1" bin="${X_BIN[$1]}" cp dir files=() f done_files=()
  info "Mitigasi nginx: matikan HTTP/2 (${X_FULL[$i]})"
  cp="$("$bin" -V 2>&1 | grep -oE -- '--conf-path=[^ ]+' | cut -d= -f2)"
  dir="$(dirname "${cp:-/etc/nginx/nginx.conf}")"
  [ -d "$dir" ] || { warn "Direktori konfigurasi tidak ditemukan: $dir"; return; }
  mapfile -t files < <(grep -rlIE \
    '^[[:space:]]*(http2[[:space:]]+on[[:space:]]*;|listen[^#;]*[[:space:]]http2([[:space:];]|$))' "$dir" 2>/dev/null)
  if [ "${#files[@]}" -eq 0 ]; then
    ok "Tidak ada HTTP/2 aktif di $dir."
    warn "Jika HTTP/2 diatur di luar $dir (mis. via include lain), periksa manual."
    return
  fi
  printf '   - %s\n' "${files[@]}"
  warn "Klien akan turun ke HTTP/1.1 (fungsi tetap jalan, performa bisa sedikit turun)."
  ask_yn "Matikan HTTP/2 pada file di atas (dengan backup + nginx -t)?" || { warn "Dibatalkan."; return; }
  for f in "${files[@]}"; do
    backup_file "$f" || { err "Gagal backup $f — dilewati."; continue; }
    sed -i --follow-symlinks -E \
      -e 's/^([[:space:]]*)http2[[:space:]]+on[[:space:]]*;/\1http2 off;/' \
      -e '/^[[:space:]]*listen[[:space:]]/ s/[[:space:]]+http2([[:space:];]|$)/\1/g' "$f"
    done_files+=("$f")
  done
  if "$bin" -t 2>&1 | sed 's/^/    /'; [ "${PIPESTATUS[0]}" -eq 0 ]; then
    for f in "${done_files[@]}"; do ok "Diubah: $f  ${D}(backup: ${BACKUP_DIR}${f})${N}"; done
    RESTART_SET["nginx"]=1
    warn "Mitigasi ini hanya menutup 2 dari 5 CVE. Update ke $NGX_FIX_STABLE / $NGX_FIX_MAINLINE tetap wajib."
  else
    err "nginx -t gagal — mengembalikan file dari backup."
    for f in "${done_files[@]}"; do cat "${BACKUP_DIR}${f}" > "$f" && ok "Dikembalikan: $f"; done
  fi
}

ngx_advice() {
  local i
  for i in "${!X_BIN[@]}"; do
    [ "${X_STATUS[$i]}" = PATCHED ] && continue
    case "${X_FEAT[$i]}" in *mail*)
      warn "nginx ${X_UP[$i]}: mail proxy terpapar — pertimbangkan menonaktifkan blok mail{} sampai update." ;; esac
    case "${X_FEAT[$i]}" in *resolver*)
      warn "nginx ${X_UP[$i]}: resolver + SSI/mirror — hindari variabel di proxy_pass pada lokasi SSI/mirror." ;; esac
    case "${X_FEAT[$i]}" in *QUIC*)
      warn "nginx ${X_UP[$i]}: HTTP/3 aktif — pertimbangkan mematikan listen ... quic sampai update." ;; esac
  done
}

# =============================================================================
#                          CONTAINER (Docker / Podman)
# =============================================================================
# Semua perintah di sini hanya membaca: "ps", "inspect", dan "exec <biner> -v/-T".
cexec() { # runtime id cmd... ; stdin ditutup agar tidak "memakan" input script
  timeout 20 "$1" exec "$2" "${@:3}" </dev/null 2>&1
}

ctr_discover() {
  local rt out id name image wd cmd line up full prod plus feat
  for rt in docker podman; do
    command -v "$rt" >/dev/null 2>&1 || continue
    if ! out="$("$rt" ps --format '{{.ID}}|{{.Names}}|{{.Image}}' 2>/dev/null </dev/null)"; then
      CTR_DENIED=1; warn "$rt terpasang tapi daftar container tidak bisa dibaca (jalankan dengan sudo)."
      continue
    fi
    [ "$rt" = podman ] && [ -n "$(command -v docker 2>/dev/null)" ] &&       readlink -f "$(command -v docker)" | grep -q podman && continue   # docker = alias podman
    while IFS='|' read -r id name image; do
      [ -n "$id" ] || continue
      wd="$("$rt" inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$id" 2>/dev/null </dev/null)"
      [ "$wd" = "<no value>" ] && wd=""

      # --- nginx / OpenResty
      if [ "$SKIP_NGX" -eq 0 ]; then
        line=""
        for cmd in nginx openresty /usr/local/openresty/nginx/sbin/nginx; do
          line="$(cexec "$rt" "$id" "$cmd" -v | grep -m1 'version:')" && break
          line=""
        done
        if [ -n "$line" ]; then
          prod="$(sed -E 's/.*version:[[:space:]]*([^/]+)\/.*/\1/' <<<"$line")"
          up="$(grep -oE '/[0-9]+\.[0-9]+\.[0-9]+' <<<"$line" | head -n1 | tr -d /)"
          if [ -n "$up" ]; then
            plus=0; [[ "$line" == *nginx-plus* ]] && plus=1
            feat="$(ngx_features "$(cexec "$rt" "$id" "$cmd" -T | sed 's/#.*$//')")"
            X_BIN+=("$rt: $name ($image)"); X_UP+=("$up")
            if [ "$prod" = openresty ]; then X_KIND+=("container-openresty"); else X_KIND+=("container"); fi
            X_FULL+=("$(sed -E 's/.*version:[[:space:]]*//' <<<"$line")")
            X_ORIGIN+=("$rt"); X_PKG+=("")
            X_STATUS+=("$(ngx_status "$up" "$plus")"); X_FEAT+=("$feat")
            X_CTR+=("$id"); X_RT+=("$rt"); X_IMG+=("$image"); X_WD+=("$wd")
          fi
        fi
      fi

      # --- PHP (php, php-fpm, dan php-fpmX.Y gaya Debian)
      if [ "$SKIP_PHP" -eq 0 ]; then
        declare -A seenv=()
        local cmds=(php php-fpm)
        mapfile -t -O 2 cmds < <(cexec "$rt" "$id" sh -c 'ls /usr/sbin/php-fpm[0-9]* /usr/bin/php[0-9]* 2>/dev/null' | grep '^/')
        for cmd in "${cmds[@]}"; do
          line="$(cexec "$rt" "$id" "$cmd" -v | grep -m1 '^PHP ')" || continue
          full="$(awk '{print $2}' <<<"$line")"
          up="$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' <<<"$full")" || continue
          [ -n "${seenv[$full]:-}" ] && continue
          seenv[$full]=1
          E_BRANCH+=("${up%.*}"); E_FULL+=("$full"); E_UP+=("$up"); E_KIND+=("container")
          E_BIN+=("$rt: $name ($image)"); E_ORIGIN+=("$rt")
          E_STATUS+=("$(php_status "$up" "${up%.*}")")
          E_CTR+=("$id"); E_RT+=("$rt"); E_IMG+=("$image"); E_WD+=("$wd")
        done
        unset seenv
      fi
    done <<<"$out"
  done
}

# Langkah perbaikan untuk container (tidak dijalankan otomatis).
ctr_advice() {
  local i shown=0 rt img wd tag
  declare -A done_ctr=()
  for i in "${!E_BRANCH[@]}"; do
    [ -n "${E_CTR[$i]}" ] || continue
    case "${E_STATUS[$i]}" in VULNERABLE|EOL) ;; *) continue ;; esac
    [ "$shown" -eq 0 ] && { echo; info "Langkah untuk container (jalankan manual)"; shown=1; }
    if [ "${E_STATUS[$i]}" = EOL ]; then warn "${E_BIN[$i]}: PHP ${E_FULL[$i]} — EOL"
    else warn "${E_BIN[$i]}: PHP ${E_FULL[$i]} — RENTAN"; fi
    if [ "${E_STATUS[$i]}" = EOL ]; then
      printf '      %s
' "Image memakai PHP ${E_BRANCH[$i]} (EOL): pull ulang TIDAK menolong, ganti tag image ke PHP 8.2+."         "Sementara: mount file ini ke conf.d PHP di container (mis. /usr/local/etc/php/conf.d/zz-mitigasi.ini):"         "  session.upload_progress.enabled = Off" "lalu buat ulang container."
    else
      printf '      %s
' "Butuh PHP >= ${MIN_PATCHED[${E_BRANCH[$i]}]}. Pull image versi terbaru lalu buat ulang container."
    fi
    done_ctr["${E_CTR[$i]}"]="${E_RT[$i]}|${E_IMG[$i]}|${E_WD[$i]}"
  done
  for i in "${!X_BIN[@]}"; do
    [ -n "${X_CTR[$i]}" ] || continue
    [ "${X_STATUS[$i]}" = PATCHED ] && continue
    [ "$shown" -eq 0 ] && { echo; info "Langkah untuk container (jalankan manual)"; shown=1; }
    warn "${X_BIN[$i]}: ${X_FULL[$i]} — RENTAN (butuh nginx $NGX_FIX_STABLE / $NGX_FIX_MAINLINE)"
    if [ "${X_KIND[$i]}" = container-openresty ]; then
      printf '      %s
' "Image berbasis OpenResty: tunggu/cek rilis image yang memuat fix nginx terbaru sebelum pull."         "Sementara: matikan HTTP/2 di konfigurasi proxy (mis. opsi \"HTTP/2 Support\" di Nginx Proxy Manager)."
    fi
    done_ctr["${X_CTR[$i]}"]="${X_RT[$i]}|${X_IMG[$i]}|${X_WD[$i]}"
  done
  [ "$shown" -eq 1 ] || return 0
  echo; echo "  Cara memperbarui per container:"
  for i in "${!done_ctr[@]}"; do
    IFS='|' read -r rt img wd <<<"${done_ctr[$i]}"
    tag="${img##*:}"; [ "$tag" = "$img" ] && tag="latest"
    if [ -n "$wd" ]; then
      printf '    %s
' "# $img (compose di $wd)" "cd $wd && $rt compose pull && $rt compose up -d"
    else
      printf '    %s
' "# $img (tanpa compose)" "$rt pull $img   # lalu buat ulang container dengan opsi yang sama"
    fi
    [[ "$tag" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] && printf '    %s
' "# catatan: tag '$tag' dipin ke versi tertentu — ganti tag ke rilis yang sudah berisi fix."
  done
  echo
  warn "Sebelum membuat ulang container: data yang TIDAK berada di volume/bind mount akan hilang."
  warn "Cek dulu (hanya baca):  $rt inspect -f '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{println}}{{end}}' <nama_container>"
  warn "Pada Docker lama tanpa plugin compose, gunakan 'docker-compose' (pakai tanda hubung)."
}

# ------------------------------------------------------------- pilih item ----
choose() { # $1 = php|ngx, sisanya indeks kandidat
  CHOSEN=()
  local t="$1"; shift
  local list=("$@") n=1 i ans tok
  if [ "$HAS_TTY" -ne 1 ] || [ "$ASSUME_YES" -eq 1 ] || [ "$FROM_FLAG" -eq 1 ] || [ "${#list[@]}" -eq 1 ]; then
    CHOSEN=("${list[@]}"); return
  fi
  for i in "${list[@]}"; do
    if [ "$t" = php ]; then printf '   %d) PHP %s  (%s, %s)\n' "$n" "${E_FULL[$i]}" "${E_ORIGIN[$i]}" "${E_STATUS[$i]}"
    else printf '   %d) %s  (%s)\n' "$n" "${X_FULL[$i]}" "${X_BIN[$i]}"; fi
    n=$((n+1))
  done
  ans="$(ask_line "  Pilih nomor (pisahkan spasi) atau 'a' untuk semua [a]: ")"
  if [ -z "$ans" ] || [[ "$ans" =~ ^[aA] ]]; then CHOSEN=("${list[@]}"); return; fi
  for tok in $ans; do
    if [[ "$tok" =~ ^[0-9]+$ ]] && [ "$tok" -ge 1 ] && [ "$tok" -le "${#list[@]}" ]; then
      CHOSEN+=("${list[$((tok-1))]}")
    else
      warn "Abaikan pilihan tidak valid: $tok"
    fi
  done
}

# Hitung ulang daftar kandidat aksi dari status terkini.
compute_candidates() {
  local i
  php_upd=(); php_mit=(); ngx_vul=(); ctr_vul=0
  for i in "${!E_BRANCH[@]}"; do
    if [ -n "${E_CTR[$i]}" ]; then
      case "${E_STATUS[$i]}" in VULNERABLE|EOL) ctr_vul=1 ;; esac
      continue
    fi
    case "${E_STATUS[$i]}" in
      VULNERABLE) php_upd+=("$i"); php_mit+=("$i") ;;
      EOL)        php_mit+=("$i"); [ "${E_ORIGIN[$i]}" = "repo distro" ] && php_upd+=("$i") ;;
    esac
  done
  for i in "${!X_BIN[@]}"; do
    [ "${X_STATUS[$i]}" = PATCHED ] && continue
    if [ -n "${X_CTR[$i]}" ]; then ctr_vul=1; else ngx_vul+=("$i"); fi
  done
}

# Baca ulang versi PHP/nginx di host; antrikan restart bila versinya berubah.
refresh_host() {
  local i up full nu
  for i in "${!E_BRANCH[@]}"; do
    [ -n "${E_CTR[$i]}" ] && continue
    full="$("${E_BIN[$i]}" -v 2>/dev/null | head -n1 | awk '{print $2}')"
    up="$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' <<<"$full")" || continue
    if [ "$full" != "${E_FULL[$i]}" ]; then
      ok "PHP ${E_BRANCH[$i]}: ${E_FULL[$i]} → $full"
      E_FULL[$i]="$full"; E_UP[$i]="$up"
      queue_restart_php "${E_BRANCH[$i]}" "${E_KIND[$i]}"
    fi
    E_STATUS[$i]="$(php_status "$up" "${E_BRANCH[$i]}")"
  done
  for i in "${!X_BIN[@]}"; do
    [ -n "${X_CTR[$i]}" ] && continue
    nu="$("${X_BIN[$i]}" -v 2>&1 | grep -oE '/[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | tr -d /)"
    [ -n "$nu" ] || continue
    if [ "$nu" != "${X_UP[$i]}" ]; then
      ok "nginx: ${X_UP[$i]} → $nu"
      X_UP[$i]="$nu"
      if "${X_BIN[$i]}" -t >/dev/null 2>&1; then RESTART_SET["nginx"]=1
      else err "nginx -t GAGAL setelah upgrade; nginx tidak akan di-restart. Periksa: ${X_BIN[$i]} -t"; fi
    fi
    [ "${X_STATUS[$i]}" != PLUS ] && X_STATUS[$i]="$(ngx_status "$nu" 0)"
  done
}

# Update & upgrade semua paket sistem (apt update && apt upgrade / dnf upgrade).
# "apt upgrade" tidak pernah menghapus paket; file konfigurasi yang ada dipertahankan.
sys_upgrade() {
  local plan n rc kept
  info "Update & upgrade paket sistem"
  case "$PKG" in
    apt)
      apt-get update || { err "apt-get update gagal"; return 1; }
      plan="$(apt-get -s upgrade 2>/dev/null)"
      n="$(grep -c '^Inst ' <<<"$plan")"
      kept="$(awk '/kept back:/{f=1;next} f&&/^  /{printf "%s ",$0;next} {f=0}' <<<"$plan" | xargs)"
      if [ "$n" -eq 0 ]; then
        ok "Semua paket sudah versi terbaru."
        [ -n "$kept" ] && warn "Ditahan (butuh perubahan dependensi, tidak ikut upgrade): $kept"
        return 0
      fi
      echo "  $n paket akan di-upgrade:"
      grep '^Inst ' <<<"$plan" | awk '{gsub(/[][]/,"",$3); gsub(/\(/,"",$4); printf "    %-32s %s → %s\n",$2,$3,$4}' | head -n 40
      [ "$n" -gt 40 ] && echo "    ... dan $((n-40)) paket lainnya"
      [ -n "$kept" ] && warn "Ditahan (tidak ikut upgrade): $kept"
      if grep -Eq '^Inst (docker-ce|docker-ce-cli|docker\.io|containerd|containerd\.io|runc|moby-[a-z-]+) ' <<<"$plan"; then
        warn "Docker/containerd ikut di-upgrade: daemon Docker akan restart dan SEMUA container"
        warn "berhenti sebentar (service Swarm dijadwalkan ulang). Jalankan di luar jam sibuk."
      fi
      ask_yn "Jalankan apt upgrade untuk $n paket?" || { warn "Dibatalkan."; return 3; }
      DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l UCF_FORCE_CONFFOLD=1 apt-get -y \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade
      rc=$?
      ;;
    dnf|yum)
      echo "  Pratinjau:"
      "$PKG" -q check-update | sed 's/^/    /'
      [ "${PIPESTATUS[0]}" -eq 100 ] || { ok "Semua paket sudah versi terbaru."; return 0; }
      ask_yn "Jalankan $PKG upgrade untuk paket di atas?" || { warn "Dibatalkan."; return 3; }
      "$PKG" upgrade -y; rc=$?
      ;;
    *) warn "Package manager tidak dikenali; dilewati."; return 3 ;;
  esac
  if [ "$rc" -ne 0 ]; then err "Upgrade sistem gagal (kode $rc). Tidak ada paket yang dihapus; cek output di atas."; return 1; fi
  ok "Upgrade sistem selesai."
  if [ -f /var/run/reboot-required ]; then
    warn "Server perlu REBOOT (kernel/library inti diperbarui): $(tr '\n' ' ' </var/run/reboot-required.pkgs 2>/dev/null)"
  elif command -v needs-restarting >/dev/null 2>&1 && ! needs-restarting -r >/dev/null 2>&1; then
    warn "Server perlu REBOOT (needs-restarting -r)."
  fi
  command -v needrestart >/dev/null 2>&1 && \
    warn "Layanan lain yang mungkin perlu restart: sudo needrestart -r l"
  return 0
}

finish_line() {
  local dur=$(( $(date +%s) - START_EPOCH ))
  printf '\n%s\n' "${D}Selesai   : $(date '+%Y-%m-%d %H:%M:%S %Z') (durasi ${dur} detik)${N}"
}

# --------------------------------------------------------------- main --------
main() {
  set -o pipefail
  while [ $# -gt 0 ]; do
    case "$1" in
      --check)          CHECK_ONLY=1 ;;
      --update)         A_PHP_UPD=1; A_NGX_UPD=1; FROM_FLAG=1 ;;
      --mitigate)       A_PHP_MIT=1; FROM_FLAG=1 ;;
      --nginx-no-http2) A_NGX_H2=1; FROM_FLAG=1 ;;
      --all)            A_PHP_UPD=1; A_NGX_UPD=1; A_PHP_MIT=1; FROM_FLAG=1 ;;
      --system-upgrade|--apt-upgrade) A_SYS=1; FROM_FLAG=1 ;;
      --skip-php)       SKIP_PHP=1 ;;
      --skip-nginx)     SKIP_NGX=1 ;;
      --skip-containers) SKIP_CTR=1 ;;
      --yes|-y)         ASSUME_YES=1 ;;
      --no-restart)     DO_RESTART=0 ;;
      -h|--help)        usage; exit 0 ;;
      *) err "Opsi tidak dikenal: $1"; usage; exit 2 ;;
    esac
    shift
  done
  [ "$CHECK_ONLY" -eq 1 ] && { A_PHP_UPD=0; A_PHP_MIT=0; A_NGX_UPD=0; A_NGX_H2=0; A_SYS=0; }

  printf '%s\n' "${B}${SCRIPT_NAME} v${SCRIPT_VERSION}${N} ${D}— PHP ${PHP_RELEASE_DATE} · nginx ${NGX_ADVISORY}${N}"
  printf '%s\n\n' "${D}Waktu cek : ${START_HUMAN}  ·  host: $(hostname 2>/dev/null || uname -n)${N}"
  trap 'finish_line' EXIT
  [ "$(uname -s)" = Linux ] || { err "Script ini hanya untuk Linux."; exit 2; }
  detect_tty; detect_pkg
  [ "$SKIP_PHP" -eq 0 ] && php_discover
  [ "$SKIP_NGX" -eq 0 ] && ngx_discover
  [ "$SKIP_CTR" -eq 0 ] && ctr_discover
  [ "$SKIP_PHP" -eq 0 ] && php_report
  [ "$SKIP_NGX" -eq 0 ] && ngx_report

  local i tok
  compute_candidates
  local found=$(( ${#E_BRANCH[@]} + ${#X_BIN[@]} ))
  local host_vul=$(( ${#php_mit[@]} + ${#ngx_vul[@]} ))

  if [ "$found" -eq 0 ]; then
    warn "Tidak ada PHP maupun nginx yang bisa dicek (di host maupun container)."
    [ "$CTR_DENIED" -eq 1 ] && warn "Container belum terbaca: ulangi dengan \"| sudo bash\"."
    warn "Jika proxy memakai software lain (Caddy, Traefik, HAProxy), script ini tidak mencakupnya."
  elif [ "$host_vul" -eq 0 ] && [ "$ctr_vul" -eq 0 ]; then
    ok "Semua PHP dan nginx yang terdeteksi sudah berisi patch terbaru."
    [ "$CTR_DENIED" -eq 1 ] && warn "Container belum terbaca: ulangi dengan \"| sudo bash\" untuk hasil lengkap."
  fi

  # Menu interaktif bila tidak ada aksi dari flag
  if [ "$CHECK_ONLY" -eq 0 ] && [ "$FROM_FLAG" -eq 0 ]; then
    if [ "$HAS_TTY" -eq 1 ]; then
      echo
      echo "Pilih aksi (boleh lebih dari satu, pisahkan spasi):"
      [ "${#php_upd[@]}" -gt 0 ] && echo "  1) Update PHP yang belum di-patch"
      [ "${#php_mit[@]}" -gt 0 ] && echo "  2) Mitigasi PHP (session.upload_progress.enabled = Off)"
      [ "${#ngx_vul[@]}" -gt 0 ] && echo "  3) Update nginx"
      [ "${#ngx_vul[@]}" -gt 0 ] && echo "  4) Mitigasi nginx: matikan HTTP/2 (menutup 2 dari 5 CVE)"
      [ -n "$PKG" ] && echo "  5) Update & upgrade SEMUA paket sistem ($PKG update && $PKG upgrade)"
      echo "  0) Keluar (hanya laporan)"
      for tok in $(ask_line "Pilihan [0]: "); do
        case "$tok" in 1) A_PHP_UPD=1 ;; 2) A_PHP_MIT=1 ;; 3) A_NGX_UPD=1 ;; 4) A_NGX_H2=1 ;; 5) A_SYS=1 ;; esac
      done
    elif [ "$host_vul" -gt 0 ]; then
      warn "Tidak ada terminal interaktif: hanya laporan. Gunakan --update/--mitigate dengan --yes."
    fi
  fi

  local any=$((A_PHP_UPD + A_PHP_MIT + A_NGX_UPD + A_NGX_H2 + A_SYS))
  if [ "$any" -eq 0 ]; then
    [ "${#ngx_vul[@]}" -gt 0 ] && ngx_advice
    ctr_advice
    if [ "$host_vul" -gt 0 ] || [ "$ctr_vul" -eq 1 ]; then exit 1; fi
    exit 0
  fi
  [ "$(id -u)" -eq 0 ] || { err "Aksi perubahan butuh root. Jalankan: ... | sudo bash"; exit 2; }
  [ "$HAS_TTY" -ne 1 ] && [ "$ASSUME_YES" -ne 1 ] && \
    warn "Tanpa terminal, konfirmasi otomatis ditolak. Tambahkan --yes untuk menjalankan aksi."

  # 0) Upgrade seluruh sistem lebih dulu; aksi berikutnya memakai status terbaru
  if [ "$A_SYS" -eq 1 ]; then
    echo; sys_upgrade
    echo; refresh_host
    compute_candidates
  fi

  # 1) Update PHP
  if [ "$A_PHP_UPD" -eq 1 ] && [ "${#php_upd[@]}" -gt 0 ]; then
    echo; info "PHP yang bisa di-update:"; choose php "${php_upd[@]}"
    for i in "${CHOSEN[@]}"; do echo; php_update "$i"; done
    php_mit=()
    for i in "${!E_BRANCH[@]}"; do
      [ -n "${E_CTR[$i]}" ] && continue
      local up; up="$("${E_BIN[$i]}" -v 2>/dev/null | head -n1 | awk '{print $2}' | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')"
      [ -n "$up" ] && E_STATUS[$i]="$(php_status "$up" "${E_BRANCH[$i]}")"
      case "${E_STATUS[$i]}" in VULNERABLE|EOL) php_mit+=("$i") ;; esac
    done
  elif [ "$A_PHP_UPD" -eq 1 ] && [ "$SKIP_PHP" -eq 0 ] && [ "${#php_mit[@]}" -gt 0 ]; then
    warn "Tidak ada versi PHP yang bisa di-update via package manager (sisanya EOL)."
  fi

  # 2) Mitigasi PHP
  if [ "$A_PHP_MIT" -eq 1 ] && [ "${#php_mit[@]}" -gt 0 ]; then
    echo; info "PHP yang perlu mitigasi:"; choose php "${php_mit[@]}"
    for i in "${CHOSEN[@]}"; do echo; php_mitigate "$i"; done
  fi

  # 3) Update nginx
  if [ "$A_NGX_UPD" -eq 1 ] && [ "${#ngx_vul[@]}" -gt 0 ]; then
    echo; info "nginx yang bisa di-update:"; choose ngx "${ngx_vul[@]}"
    for i in "${CHOSEN[@]}"; do echo; ngx_update "$i"; done
    ngx_vul=()
    for i in "${!X_BIN[@]}"; do
      [ -n "${X_CTR[$i]}" ] && continue
      local nu; nu="$("${X_BIN[$i]}" -v 2>&1 | grep -oE '/[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | tr -d /)"
      if [ -n "$nu" ] && [ "${X_STATUS[$i]}" != PLUS ]; then X_UP[$i]="$nu"; X_STATUS[$i]="$(ngx_status "$nu" 0)"; fi
      [ "${X_STATUS[$i]}" = PATCHED ] || ngx_vul+=("$i")
    done
  fi

  # 4) Mitigasi nginx (HTTP/2)
  if [ "$A_NGX_H2" -eq 1 ] && [ "${#ngx_vul[@]}" -gt 0 ]; then
    echo; info "nginx yang akan dimatikan HTTP/2-nya:"; choose ngx "${ngx_vul[@]}"
    for i in "${CHOSEN[@]}"; do echo; ngx_disable_http2 "$i"; done
  fi

  if [ "$any" -gt 0 ]; then
    echo; run_restarts
    echo; ngx_advice
    [ "$A_PHP_MIT" -eq 1 ] && {
      warn "Catatan: .htaccess (php_flag) atau konfigurasi per-situs di luar folder standar"
      warn "tidak dipindai. Pastikan tidak ada yang mengaktifkan kembali upload_progress."; }
  elif [ "${#ngx_vul[@]}" -gt 0 ]; then
    ngx_advice
  fi

  ctr_advice
  if [ "${#php_mit[@]}" -gt 0 ] || [ "${#ngx_vul[@]}" -gt 0 ] || [ "$ctr_vul" -eq 1 ]; then exit 1; fi
  exit 0
}

main "$@"
