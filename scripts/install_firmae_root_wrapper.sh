#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "install_firmae_root_wrapper.sh must run as root" >&2
    exit 2
fi

SOURCE_ROOT=${1:-"$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"}
SOURCE_FIRMAE=${FIRMAE_SOURCE:-"/home/lumu/tools/FirmAE"}
SOURCE_WRAPPER="$SOURCE_ROOT/scripts/firmae_root_wrapper.py"
SECURE_ROOT=/usr/local/lib/firmae-controller
ROOT_WRAPPER="$SECURE_ROOT/firmae-root-wrapper"
USER_WRAPPER=/home/lumu/tools/firmae-controller/firmae-wrapper
SUDOERS=/etc/sudoers.d/firmae-controller
TARGET_USER=lumu

reject_external_symlinks() {
    root_real=$(realpath -e "$1")
    link_list=$(mktemp)
    find "$1" -type l -print > "$link_list"
    while IFS= read -r link; do
        if ! link_target=$(realpath -e "$link"); then
            rm -f "$link_list"
            echo "broken symlink in FirmAE tree: $link" >&2
            return 1
        fi
        case "$link_target" in
            "$root_real"|"$root_real"/*) ;;
            *)
                rm -f "$link_list"
                echo "FirmAE symlink escapes its tree: $link -> $link_target" >&2
                return 1
                ;;
        esac
    done < "$link_list"
    rm -f "$link_list"
}

if [ ! -f "$SOURCE_WRAPPER" ]; then
    echo "missing wrapper source: $SOURCE_WRAPPER" >&2
    exit 2
fi
if [ ! -d "$SOURCE_FIRMAE" ] || [ ! -x "$SOURCE_FIRMAE/run.sh" ]; then
    echo "missing FirmAE execution tree: $SOURCE_FIRMAE" >&2
    exit 2
fi
reject_external_symlinks "$SOURCE_FIRMAE"

STAGE="$(mktemp -d "${SECURE_ROOT}.stage.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT HUP INT TERM
install -d -o root -g root -m 0755 "$STAGE/firmae-controller"
cp -a "$SOURCE_FIRMAE" "$STAGE/firmae-controller/FirmAE"
chown -R root:root "$STAGE/firmae-controller"
chmod -R go-w "$STAGE/firmae-controller"
reject_external_symlinks "$STAGE/firmae-controller/FirmAE"
install -o root -g root -m 0755 "$SOURCE_WRAPPER" \
    "$STAGE/firmae-controller/firmae-root-wrapper"

# Replace the previous secure snapshot only after the staged copy is complete.
# The snapshot and its ancestors are root-owned, so the sudoers target cannot
# be renamed or replaced by the unprivileged invoking user.
if [ -e "$SECURE_ROOT" ]; then
    OLD="$SECURE_ROOT.old.$$"
    mv "$SECURE_ROOT" "$OLD"
    if ! mv "$STAGE/firmae-controller" "$SECURE_ROOT"; then
        mv "$OLD" "$SECURE_ROOT"
        exit 1
    fi
    rm -rf "$OLD"
else
    mv "$STAGE/firmae-controller" "$SECURE_ROOT"
fi

install -d -o root -g root -m 0755 "$(dirname "$USER_WRAPPER")"
cat > "$USER_WRAPPER.tmp" <<'EOF'
#!/bin/sh
set -eu
exec /usr/bin/sudo -n /usr/local/lib/firmae-controller/firmae-root-wrapper "$@"
EOF
chown root:root "$USER_WRAPPER.tmp"
chmod 0755 "$USER_WRAPPER.tmp"
mv -f "$USER_WRAPPER.tmp" "$USER_WRAPPER"

printf '%s ALL=(root) NOPASSWD: %s\n' "$TARGET_USER" "$ROOT_WRAPPER" > \
    "$SUDOERS.tmp"
chown root:root "$SUDOERS.tmp"
chmod 0440 "$SUDOERS.tmp"
visudo -cf "$SUDOERS.tmp" >/dev/null
mv -f "$SUDOERS.tmp" "$SUDOERS"

echo "installed user entry: $USER_WRAPPER"
echo "secure root helper: $ROOT_WRAPPER"
echo "secure FirmAE snapshot: $SECURE_ROOT/FirmAE"
echo "sudoers rule: $SUDOERS"
