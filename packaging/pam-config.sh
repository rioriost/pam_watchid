# Definitions only. Release tooling embeds this library into each signed-package
# script; no privileged script sources an installed, replaceable helper.

fail() {
    printf '%s\n' "pam_watchid: $*" >&2
    exit 1
}

pam_init() {
    [ "$(/usr/bin/id -u)" = 0 ] || fail "Run this script as root."
    umask 077
    LC_ALL=C
    export LC_ALL
    base=/Library/Security/pam_watchid
    pam_dir=/private/etc/pam.d
    sudo_local=$pam_dir/sudo_local
    state_dir=/private/var/db/pam_watchid
    activation=$state_dir/activation
    pending=$state_dir/pending
    lock=$state_dir/lock
    receipt=io.github.rioriost.pam-watchid
    managed_block='# pam_watchid: begin managed
auth sufficient /Library/Security/pam_watchid/pam_watchid.so
# pam_watchid: end managed
'
    managed_length=$(printf '%s' "$managed_block" | /usr/bin/wc -c | /usr/bin/tr -d ' ')
    lock_owned=no
    candidate=
    candidate_owned=no
    candidate_identity=
}

pam_exists() {
    [ -e "$1" ] || [ -L "$1" ]
}

pam_metadata() {
    /usr/bin/stat -f '%u:%g:%Lp:%l:%f:%d:%i:%z:%m:%c' "$1" ||
        fail "Cannot inspect metadata: $1"
    pam_xattrs "$1"
}

pam_attributes() {
    /usr/bin/stat -f '%u:%g:%Lp:%l:%f' "$1" ||
        fail "Cannot inspect attributes: $1"
    pam_xattrs "$1"
}

pam_xattrs() {
    px_names=$(/usr/bin/xattr "$1") || fail "Cannot inspect extended attributes: $1"
    while IFS= read -r px_name; do
        case "$px_name" in
            ''|com.apple.macl|com.apple.provenance) ;;
            *) fail "Unsupported extended attribute $px_name on $1" ;;
        esac
    done <<EOF
$px_names
EOF
    for px_name in com.apple.macl com.apple.provenance; do
        if printf '%s\n' "$px_names" | /usr/bin/grep -Fxq "$px_name"; then
            px_hex=$(/usr/bin/xattr -px "$px_name" "$1") ||
                fail "Cannot read extended attribute $px_name on $1"
            px_hex=$(printf '%s' "$px_hex" | /usr/bin/tr -d '[:space:]' |
                /usr/bin/tr 'abcdef' 'ABCDEF')
            case "$px_hex" in *[!0-9A-F]*) fail "Invalid extended attribute encoding: $1" ;; esac
            [ "$((${#px_hex} % 2))" = 0 ] || fail "Truncated extended attribute encoding: $1"
            printf '%s=%s\n' "$px_name" "$px_hex"
        fi
    done
}

pam_preserved_xattrs() {
    sx_left=$(pam_xattrs "$1") || fail "Cannot compare extended attributes: $1"
    sx_right=$(pam_xattrs "$2") || fail "Cannot compare extended attributes: $2"
    [ "$sx_left" != "$sx_right" ] || return 0
    if printf '%s\n' "$sx_left" | /usr/bin/grep -q '^com.apple.provenance='; then
        return 1
    fi
    # macOS can attach provenance to a new copy of an attribute-free system file.
    sx_without_generated=$(printf '%s\n' "$sx_right" |
        /usr/bin/sed '/^com.apple.provenance=/d') || fail "Cannot compare copied attributes."
    [ "$sx_left" = "$sx_without_generated" ]
}

pam_metadata_matches() {
    mm_actual=$(pam_metadata "$1") || fail "Cannot recheck metadata: $1"
    [ "$mm_actual" = "$2" ]
}

pam_safe_path() {
    sp_path=$1
    [ ! -L "$sp_path" ] || fail "Refusing symbolic link: $sp_path"
    pam_exists "$sp_path" || return 0
    sp_owner=$(/usr/bin/stat -f '%u' "$sp_path") || fail "Cannot inspect $sp_path"
    sp_mode=$(/usr/bin/stat -f '%p' "$sp_path") || fail "Cannot inspect $sp_path"
    [ "$sp_owner" = 0 ] || fail "Path is not root-owned: $sp_path"
    case "$sp_mode" in ''|*[!0-7]*) fail "Invalid permissions: $sp_path" ;; esac
    [ "$((0$sp_mode & 06022))" = 0 ] ||
        fail "Path is set-ID or group/world writable: $sp_path"
    sp_acl=$(/bin/ls -lde "$sp_path") || fail "Cannot inspect ACL: $sp_path"
    if printf '%s\n' "$sp_acl" | /usr/bin/grep -Eq \
        '^[[:space:]]*[0-9]+:.* allow .*(write|append|add_file|add_subdirectory|delete|chown|writesecurity)'; then
        fail "Path has a writable ACL: $sp_path"
    fi
}

pam_safe_file() {
    pam_safe_path "$1"
    pam_exists "$1" || return 0
    [ -f "$1" ] && [ -r "$1" ] || fail "Not a readable regular file: $1"
    [ "$(/usr/bin/stat -f '%l' "$1")" = 1 ] || fail "Refusing hard-linked file: $1"
}

pam_mutable_file() {
    pam_safe_file "$1"
    pam_exists "$1" || return 0
    [ "$(/usr/bin/stat -f '%f' "$1")" = 0 ] || fail "Unsupported file flags: $1"
    mf_acl=$(/bin/ls -lde "$1") || fail "Cannot inspect ACL: $1"
    if printf '%s\n' "$mf_acl" | /usr/bin/grep -Eq '^[[:space:]]*[0-9]+:'; then
        fail "Cannot preserve extended ACL metadata: $1"
    fi
    mf_xattrs=$(pam_xattrs "$1") || fail "Cannot safely preserve extended attributes: $1"
}

pam_safe_directory() {
    pam_safe_path "$1"
    pam_exists "$1" || return 0
    [ -d "$1" ] || fail "Not a directory: $1"
}

pam_private_directory() {
    pam_safe_directory "$1"
    pam_exists "$1" || return 0
    [ "$(/usr/bin/stat -f '%Lp' "$1")" = 700 ] ||
        fail "Manager directory must have mode 700: $1"
    [ "$(/usr/bin/stat -f '%f' "$1")" = 0 ] || fail "Unsupported directory flags: $1"
    pd_acl=$(/bin/ls -lde "$1") || fail "Cannot inspect ACL: $1"
    if printf '%s\n' "$pd_acl" | /usr/bin/grep -Eq '^[[:space:]]*[0-9]+:'; then
        fail "Unsupported manager directory ACL: $1"
    fi
}

pam_paths() {
    for pp_directory in / /private /private/etc "$pam_dir" \
        /private/var /private/var/db /Library /Library/Security "$base" "$base/libexec"; do
        pam_safe_directory "$pp_directory"
    done
    [ -d "$pam_dir" ] || fail "Cannot inspect $pam_dir"
    pam_private_directory "$state_dir"
    pam_private_directory "$pending"
    for pp_file in "$base/pam_watchid.so" "$base/libexec/pam_watchid-helper" \
        "$base/LICENSE" "$base/uninstall.sh"; do
        pam_safe_file "$pp_file"
    done
    pam_mutable_file "$sudo_local"
    pam_mutable_file "$activation"
    if pam_exists "$activation"; then
        pa_value=$(/bin/cat "$activation") || fail "Cannot read activation state."
        case "$pa_value" in absent|present) ;;
            *) fail "Invalid activation state." ;;
        esac
        printf '%s\n' "$pa_value" | /usr/bin/cmp -s - "$activation" ||
            fail "Damaged activation state."
    fi
}

pam_classify() {
    owned=no
    activation_origin=
    if pam_exists "$activation"; then
        activation_origin=$(/bin/cat "$activation") || fail "Cannot read activation state."
    fi
    if pam_exists "$sudo_local"; then
        pc_prefix=$(/bin/dd if="$sudo_local" bs=1 count="$managed_length" 2>/dev/null &&
            printf x) || fail "Cannot inspect managed prefix."
        if [ "$pc_prefix" = "${managed_block}x" ]; then
            [ -n "$activation_origin" ] || fail "Managed block has no manager-owned activation state."
            owned=yes
        fi
    fi
}

pam_scan_references() {
    for ps_file in "$pam_dir"/* "$pam_dir"/.[!.]* "$pam_dir"/..?*; do
        pam_exists "$ps_file" || continue
        [ -z "$candidate" ] || [ "$ps_file" != "$candidate" ] || continue
        pam_safe_file "$ps_file"
        pam_text_policy "$ps_file"
        ps_skip=0
        if [ "$ps_file" = "$sudo_local" ] && [ "$owned" = yes ]; then ps_skip=3; fi
        if /usr/bin/awk -v skip="$ps_skip" '
            NR <= skip { next }
            /pam_watchid:/ { bad = 1 }
            /^[ \t]*#/ { next }
            /\\$/ { sub(/\\$/, ""); joined = joined $0; next }
            {
                line = joined $0
                joined = ""
                sub(/[ \t]+#.*/, "", line)
                if (line ~ /pam_watchid/) bad = 1
            }
            END {
                sub(/[ \t]+#.*/, "", joined)
                if (joined ~ /pam_watchid/) bad = 1
                if (bad) exit 42
            }
        ' "$ps_file"; then :; else
            ps_status=$?
            [ "$ps_status" != 42 ] || fail \
                "Unowned, duplicate, or damaged pam_watchid reference in $ps_file; deactivate it manually first."
            fail "Cannot parse PAM configuration: $ps_file"
        fi
    done
}

pam_text_policy() {
    ap_bad=$(set -o pipefail
        /usr/bin/tr -d '\011\012\040-\176\200-\377' < "$1" | /usr/bin/wc -c |
            /usr/bin/tr -d ' ') || fail "Cannot inspect policy text: $1"
    [ "$ap_bad" = 0 ] || fail "Unsupported control bytes in $1"
}

pam_policy() {
    pam_safe_file "$pam_dir/sudo"
    [ -f "$pam_dir/sudo" ] || fail "Missing main sudo PAM policy."
    pam_text_policy "$pam_dir/sudo"
    /usr/bin/awk '
        /^[ \t]*#/ || /^[ \t]*$/ { next }
        {
            sub(/[ \t]+#.*/, "")
            if ($0 ~ /[\\\047"\[\]#]/) { bad = 1; next }
            if ($1 != "auth") {
                if (($1 != "account" && $1 != "password" && $1 != "session") ||
                    ($2 != "required" && $2 != "requisite" &&
                     $2 != "sufficient" && $2 != "optional") || NF < 3) bad = 1
                next
            }
            if (NF < 3) bad = 1
            if ($2 == "include" && $3 == "sudo_local" && NF == 3) {
                includes++; seen = 1; next
            }
            if ($2 != "required" && $2 != "requisite" &&
                $2 != "sufficient" && $2 != "optional") bad = 1
            if (seen) {
                if (!fallback && !smartcard && NF == 3 && $2 == "sufficient" &&
                    ($3 == "pam_smartcard.so" || $3 == "/usr/lib/pam/pam_smartcard.so"))
                    smartcard = 1
                else if (!fallback && NF == 3 && $2 == "required" &&
                    ($3 == "pam_opendirectory.so" || $3 == "/usr/lib/pam/pam_opendirectory.so"))
                    fallback = 1
                else bad = 1
            }
        }
        END { if (bad || includes != 1 || !fallback) exit 1 }
    ' "$pam_dir/sudo" || fail "Main sudo policy must include sudo_local and retain its password fallback."
    pam_exists "$sudo_local" || return 0
    pam_text_policy "$sudo_local"
    pl_skip=0
    [ "$owned" = no ] || pl_skip=3
    /usr/bin/awk -v skip="$pl_skip" '
        NR <= skip { next }
        /^[ \t]*#/ || /^[ \t]*$/ { next }
        {
            sub(/[ \t]+#.*/, "")
            if ($0 ~ /[\\\047"\[\]#]/) { bad = 1; next }
            if ($1 == "auth") {
                if ($2 != "sufficient" || NF != 3 ||
                    ($3 != "pam_tid.so" && $3 != "/usr/lib/pam/pam_tid.so")) bad = 1
            } else if (($1 != "account" && $1 != "password" && $1 != "session") ||
                ($2 != "required" && $2 != "requisite" &&
                 $2 != "sufficient" && $2 != "optional") || NF < 3) bad = 1
        }
        END { if (bad) exit 1 }
    ' "$sudo_local" || fail "Unsupported sudo_local policy; required/requisite auth gates cannot be bypassed."
}

pam_guard() {
    pam_paths
    pam_classify
    pam_scan_references
}

pam_cleanup() {
    cleanup_status=$?
    trap - 0 HUP INT TERM
    if [ "$lock_owned" = yes ]; then
        if [ ! -L "$lock" ] && [ -d "$lock" ] &&
            [ "$(/usr/bin/stat -f '%d:%i' "$lock")" = "$lock_identity" ]; then
            if [ "$candidate_owned" = yes ] && [ -n "$candidate" ] && pam_exists "$candidate"; then
                if [ ! -L "$candidate" ] &&
                    [ "$(/usr/bin/stat -f '%d:%i' "$candidate")" = "$candidate_identity" ]; then
                    /bin/rm -- "$candidate" || cleanup_status=1
                else
                    printf '%s\n' "pam_watchid: Preserving changed candidate: $candidate" >&2
                    cleanup_status=1
                fi
            fi
            /bin/rmdir "$lock" || cleanup_status=1
        else
            printf '%s\n' "pam_watchid: Operation lock changed; refusing foreign cleanup." >&2
            cleanup_status=1
        fi
    fi
    exit "$cleanup_status"
}

pam_lock() {
    pam_paths
    if ! pam_exists "$state_dir"; then
        /bin/mkdir -m 700 "$state_dir" || fail "Cannot create manager state directory."
    fi
    pam_private_directory "$state_dir"
    /bin/mkdir -m 700 "$lock" || fail "Another operation holds $lock; do not remove a live lock."
    lock_identity=$(/usr/bin/stat -f '%d:%i' "$lock") || fail "Cannot identify operation lock."
    lock_owned=yes
    trap pam_cleanup 0
    trap 'exit 1' HUP INT TERM
}

pam_assert_lock() {
    pam_private_directory "$lock"
    [ "$lock_owned" = yes ] && [ ! -L "$lock" ] && [ -d "$lock" ] &&
        [ "$(/usr/bin/stat -f '%d:%i' "$lock")" = "$lock_identity" ] ||
        fail "Operation lock ownership changed."
}

pam_backup() {
    pam_assert_lock
    backup_id=$(/usr/bin/uuidgen) || fail "Cannot generate backup identifier."
    case "$backup_id" in ''|*[!A-Fa-f0-9-]*) fail "Invalid backup identifier." ;; esac
    backup_dir=$state_dir/backup.$backup_id
    /bin/mkdir -m 700 "$backup_dir" || fail "Cannot reserve a unique persistent backup."
    original_exists=no
    original_metadata=
    if pam_exists "$sudo_local"; then
        original_exists=yes
        original_metadata=$(pam_metadata "$sudo_local")
        /bin/cp "$sudo_local" "$backup_dir/sudo_local" || fail "Cannot back up sudo_local."
        /bin/chmod 600 "$backup_dir/sudo_local" || fail "Cannot protect backup."
        backup_attributes=$(pam_attributes "$sudo_local") ||
            fail "Cannot snapshot sudo_local attributes."
        printf '%s\n' "$backup_attributes" > "$backup_dir/attributes"
    else
        : > "$backup_dir/absent"
    fi
    main_metadata=$(pam_metadata "$pam_dir/sudo")
    /bin/cp "$pam_dir/sudo" "$backup_dir/sudo" || fail "Cannot snapshot main sudo policy."
    /bin/chmod 600 "$backup_dir/sudo" || fail "Cannot protect policy snapshot."
    original_activation=no
    activation_metadata=
    if pam_exists "$activation"; then
        original_activation=yes
        activation_metadata=$(pam_metadata "$activation")
        /bin/cp "$activation" "$backup_dir/activation" || fail "Cannot snapshot activation state."
        /bin/chmod 600 "$backup_dir/activation" || fail "Cannot protect activation snapshot."
    fi
    pam_recheck
}

pam_recheck() {
    pam_recheck_config
    if [ "$original_activation" = yes ]; then
        pam_mutable_file "$backup_dir/activation"
        pam_exists "$activation" &&
            pam_metadata_matches "$activation" "$activation_metadata" &&
            /usr/bin/cmp -s "$activation" "$backup_dir/activation" ||
            fail "Activation state changed concurrently."
    else
        ! pam_exists "$activation" || fail "Activation state appeared concurrently."
    fi
}

pam_recheck_config() {
    pam_assert_lock
    pam_guard
    pam_private_directory "$backup_dir"
    pam_mutable_file "$backup_dir/sudo"
    pam_metadata_matches "$pam_dir/sudo" "$main_metadata" &&
        /usr/bin/cmp -s "$pam_dir/sudo" "$backup_dir/sudo" ||
        fail "Main sudo policy changed concurrently."
    if [ "$original_exists" = yes ]; then
        pam_mutable_file "$backup_dir/sudo_local"
        pam_exists "$sudo_local" &&
            pam_metadata_matches "$sudo_local" "$original_metadata" &&
            /usr/bin/cmp -s "$sudo_local" "$backup_dir/sudo_local" ||
            fail "sudo_local changed concurrently."
    else
        ! pam_exists "$sudo_local" || fail "sudo_local appeared concurrently."
    fi
}

pam_new_candidate() {
    candidate=$pam_dir/.pam_watchid.$backup_id
    (set -C; : > "$candidate") || fail "Cannot reserve PAM candidate."
    candidate_owned=yes
    candidate_identity=$(/usr/bin/stat -f '%d:%i' "$candidate") ||
        fail "Cannot identify PAM candidate."
    if [ "$original_exists" = yes ]; then
        /bin/cp -p "$sudo_local" "$candidate" || fail "Cannot preserve original PAM metadata."
        [ "$(/usr/bin/stat -f '%d:%i' "$candidate")" = "$candidate_identity" ] ||
            fail "PAM candidate identity changed while copying metadata."
        pam_preserved_xattrs "$sudo_local" "$candidate" ||
            fail "PAM extended attributes were not preserved."
    fi
}

pam_candidate_attributes() {
    if [ "$original_exists" = yes ]; then
        ca_uid=$(/usr/bin/stat -f '%u' "$sudo_local")
        ca_gid=$(/usr/bin/stat -f '%g' "$sudo_local")
        ca_mode=$(/usr/bin/stat -f '%Lp' "$sudo_local")
    else
        ca_uid=0
        ca_gid=0
        ca_mode=644
    fi
    /usr/sbin/chown "$ca_uid:$ca_gid" "$candidate" &&
        /bin/chmod "$ca_mode" "$candidate" || fail "Cannot preserve PAM owner/mode."
    pam_mutable_file "$candidate"
    if [ "$original_exists" = yes ]; then
        pam_preserved_xattrs "$sudo_local" "$candidate" ||
            fail "PAM extended attributes changed while constructing candidate."
    fi
    candidate_metadata=$(pam_metadata "$candidate")
}

pam_check_candidate() {
    pam_mutable_file "$candidate"
    pam_metadata_matches "$candidate" "$candidate_metadata" ||
        fail "PAM candidate changed concurrently."
    /usr/bin/cmp -s "$candidate" "$backup_dir/candidate" ||
        fail "PAM candidate bytes changed concurrently."
}

pam_disabled_candidate() {
    desired_exists=$original_exists
    [ "$owned" = yes ] || return 0
    pam_new_candidate
    /bin/dd if="$sudo_local" of="$candidate" bs=1 skip="$managed_length" 2>/dev/null ||
        fail "Cannot extract original PAM bytes."
    if [ "$activation_origin" = absent ] && [ ! -s "$candidate" ]; then
        desired_exists=no
    fi
    pam_candidate_attributes
    /bin/cp "$candidate" "$backup_dir/candidate" || fail "Cannot snapshot PAM candidate."
    /bin/chmod 600 "$backup_dir/candidate" || fail "Cannot protect candidate snapshot."
}

pam_commit_disabled() {
    [ "$owned" = yes ] || return 0
    pam_check_candidate
    pam_recheck
    if [ "$desired_exists" = no ]; then
        /bin/rm -- "$sudo_local" || fail "Cannot remove manager-created empty sudo_local."
    else
        /bin/mv -f "$candidate" "$sudo_local" || fail "Cannot atomically deactivate PAM."
        candidate=
        candidate_owned=no
    fi
    /bin/rm -- "$activation" || fail "PAM deactivated, but activation state could not be cleared."
    owned=no
}

pam_pending_validate() {
    pam_private_directory "$pending"
    [ -d "$pending" ] || fail "No pending installation; run the package preinstall first."
    for pv_file in "$pending"/* "$pending"/.[!.]* "$pending"/..?*; do
        pam_exists "$pv_file" || continue
        case "${pv_file##*/}" in token|sudo_local|absent|attributes|activated-attributes) ;;
            *) fail "Unexpected pending transaction file: $pv_file" ;;
        esac
        pam_mutable_file "$pv_file"
        [ "$(/usr/bin/stat -f '%Lp' "$pv_file")" = 600 ] ||
            fail "Pending transaction files must have mode 600."
    done
    [ -f "$pending/token" ] || fail "Missing pending install token."
    if pam_exists "$pending/absent"; then
        [ ! -s "$pending/absent" ] && ! pam_exists "$pending/sudo_local" &&
            ! pam_exists "$pending/attributes" || fail "Damaged pending absence record."
    else
        [ -f "$pending/sudo_local" ] && [ -f "$pending/attributes" ] ||
            fail "Missing prepared PAM snapshot."
    fi
}

pam_pending_matches() {
    pam_pending_validate
    if pam_exists "$pending/absent"; then
        ! pam_exists "$sudo_local" || fail "Prepared sudo_local absence changed."
    else
        pam_mutable_file "$sudo_local"
        [ -f "$sudo_local" ] &&
            /usr/bin/cmp -s "$sudo_local" "$pending/sudo_local" ||
            fail "Prepared sudo_local bytes changed; refusing to adopt administrator edits."
        pending_attributes=$(pam_attributes "$sudo_local") ||
            fail "Cannot recheck prepared sudo_local attributes."
        printf '%s\n' "$pending_attributes" |
            /usr/bin/cmp -s - "$pending/attributes" ||
            fail "Prepared sudo_local metadata changed."
    fi
}

pam_clear_pending() {
    pam_pending_validate
    for cp_name in token sudo_local absent attributes activated-attributes; do
        if pam_exists "$pending/$cp_name"; then
            /bin/rm -- "$pending/$cp_name" || fail "Cannot clear pending transaction."
        fi
    done
    /bin/rmdir "$pending" || fail "Cannot remove completed transaction directory."
}

pam_prepare_install() {
    prepare_token=$1
    pam_guard
    pam_policy
    ! pam_exists "$pending" || fail "An installation is pending; use --cancel-install after inspecting it."
    [ "$owned" = yes ] || [ -z "$activation_origin" ] ||
        fail "Stale activation state; run the uninstaller with --disable first."
    pam_lock
    pam_guard
    pam_policy
    ! pam_exists "$pending" || fail "An installation is already pending."
    [ "$owned" = yes ] || [ -z "$activation_origin" ] ||
        fail "Activation state changed before preparation."
    pam_backup
    pam_disabled_candidate
    /bin/mkdir -m 700 "$backup_dir/pending" || fail "Cannot stage pending transaction."
    printf '%s\n' "$prepare_token" > "$backup_dir/pending/token"
    if [ "$desired_exists" = yes ]; then
        if [ "$owned" = yes ]; then prep_source=$candidate; else prep_source=$sudo_local; fi
        /bin/cp "$prep_source" "$backup_dir/pending/sudo_local" ||
            fail "Cannot record prepared PAM bytes."
        /bin/chmod 600 "$backup_dir/pending/sudo_local" || fail "Cannot protect transaction."
        prepared_attributes=$(pam_attributes "$prep_source") ||
            fail "Cannot snapshot prepared PAM attributes."
        printf '%s\n' "$prepared_attributes" > "$backup_dir/pending/attributes"
    else
        : > "$backup_dir/pending/absent"
    fi
    pam_recheck
    pam_policy
    [ -z "$candidate" ] || pam_check_candidate
    ! pam_exists "$pending" || fail "Pending transaction appeared concurrently."
    /bin/mv "$backup_dir/pending" "$pending" || fail "Cannot persist pending transaction."
    pam_commit_disabled
    pam_pending_matches
    printf '%s\n' "pam_watchid: Installation prepared; password fallback remains configured."
}

pam_verify_payload() {
    vp_module=$1
    vp_helper=$2
    for vp_digest in "$vp_module" "$vp_helper"; do
        [ "${#vp_digest}" = 64 ] || fail "Invalid embedded payload digest."
        case "$vp_digest" in *[!0-9a-f]*) fail "Invalid embedded payload digest." ;; esac
    done
    for vp_file in "$base/pam_watchid.so" "$base/libexec/pam_watchid-helper"; do
        pam_safe_file "$vp_file"
        [ -f "$vp_file" ] || fail "Missing installed payload: $vp_file"
        if [ "$vp_file" = "$base/libexec/pam_watchid-helper" ]; then
            [ -x "$vp_file" ] || fail "Installed helper is not executable: $vp_file"
        fi
        if [ "$vp_file" = "$base/pam_watchid.so" ]; then
            vp_expected=$vp_module
        else
            vp_expected=$vp_helper
        fi
        vp_actual=$(/usr/bin/shasum -a 256 "$vp_file") || fail "Cannot hash installed payload."
        [ "${vp_actual%% *}" = "$vp_expected" ] || fail "Installed payload SHA-256 mismatch: $vp_file"
        /usr/bin/codesign --verify --strict "$vp_file" ||
            fail "Installed payload signature verification failed: $vp_file"
    done
}

pam_complete_install() {
    complete_token=$1
    complete_module=$2
    complete_helper=$3
    pam_paths
    pam_lock
    pam_guard
    pam_policy
    pam_pending_validate
    printf '%s\n' "$complete_token" | /usr/bin/cmp -s - "$pending/token" ||
        fail "Postinstall does not match the pending version/architecture."
    pam_verify_payload "$complete_module" "$complete_helper"
    if [ "$owned" = yes ]; then
        pam_backup
        pam_new_candidate
        {
            printf '%s' "$managed_block"
            if [ -f "$pending/sudo_local" ]; then /bin/cat "$pending/sudo_local"; fi
        } > "$candidate" || fail "Cannot reconstruct completed transaction."
        if [ -f "$pending/absent" ]; then
            retry_origin=absent
        else
            retry_origin=present
        fi
        [ -f "$pending/activated-attributes" ] || fail "Missing activated metadata snapshot."
        retry_attributes=$(/bin/cat "$pending/activated-attributes") ||
            fail "Cannot read activated metadata."
        completed_attributes=$(pam_attributes "$sudo_local") ||
            fail "Cannot recheck activated PAM attributes."
        [ "$activation_origin" = "$retry_origin" ] &&
            [ "$completed_attributes" = "$retry_attributes" ] &&
            /usr/bin/cmp -s "$candidate" "$sudo_local" ||
            fail "Pending activated policy changed; refusing to adopt administrator edits."
        pam_recheck
        pam_clear_pending
        printf '%s\n' "pam_watchid: Verified activation already completed; pending transaction cleared."
        return 0
    fi
    [ "$owned" = no ] && [ -z "$activation_origin" ] ||
        fail "Unexpected activation during pending install; inspect the transaction."
    pam_pending_matches
    pam_backup
    pam_new_candidate
    {
        printf '%s' "$managed_block"
        if [ "$original_exists" = yes ]; then /bin/cat "$sudo_local"; fi
    } > "$candidate" || fail "Cannot construct managed PAM policy."
    pam_candidate_attributes
    /bin/cp "$candidate" "$backup_dir/candidate" || fail "Cannot snapshot activation candidate."
    /bin/chmod 600 "$backup_dir/candidate" || fail "Cannot protect candidate snapshot."
    activated_attributes=$(pam_attributes "$candidate") ||
        fail "Cannot snapshot activated PAM attributes."
    printf '%s\n' "$activated_attributes" > "$pending/activated-attributes"
    if [ "$original_exists" = yes ]; then new_origin=present; else new_origin=absent; fi
    printf '%s\n' "$new_origin" > "$backup_dir/activation.new"
    pam_mutable_file "$backup_dir/activation.new"
    new_activation_metadata=$(pam_metadata "$backup_dir/activation.new")
    pam_pending_matches
    pam_verify_payload "$complete_module" "$complete_helper"
    pam_check_candidate
    pam_recheck
    pam_policy
    pam_metadata_matches "$backup_dir/activation.new" "$new_activation_metadata" &&
        printf '%s\n' "$new_origin" | /usr/bin/cmp -s - "$backup_dir/activation.new" ||
        fail "Prepared activation state changed."
    /bin/mv "$backup_dir/activation.new" "$activation" || fail "Cannot persist activation state."
    pam_recheck_config
    pam_policy
    pam_pending_matches
    pam_check_candidate
    printf '%s\n' "$new_origin" | /usr/bin/cmp -s - "$activation" ||
        fail "Activation state changed before commit."
    printf '%s\n' "$activated_attributes" | /usr/bin/cmp -s - "$pending/activated-attributes" ||
        fail "Activated metadata snapshot changed before commit."
    /bin/mv -f "$candidate" "$sudo_local" || fail "Cannot atomically activate PAM; use --cancel-install."
    candidate=
    candidate_owned=no
    pam_clear_pending
    printf '%s\n' "pam_watchid: Verified payload activated; backup retained in $backup_dir"
}

pam_disable_locked() {
    pam_guard
    ! pam_exists "$pending" || fail "Installation is pending; ordinary deactivation/removal is refused."
    if [ "$owned" = yes ]; then
        pam_backup
        pam_disabled_candidate
        pam_commit_disabled
    elif pam_exists "$activation"; then
        pam_backup
        pam_recheck
        /bin/rm -- "$activation" || fail "Cannot clear already-deactivated activation state."
    fi
}

pam_cancel_install() {
    pam_guard
    pam_lock
    pam_guard
    [ "$owned" = no ] || fail "Cannot cancel while any managed module reference remains."
    pam_pending_matches
    pam_backup
    pam_pending_matches
    pam_recheck
    if pam_exists "$activation"; then
        /bin/rm -- "$activation" || fail "Cannot clear interrupted activation state."
    fi
    pam_clear_pending
    printf '%s\n' "pam_watchid: Pending installation cancelled; PAM and payload bytes were not changed."
}

pam_uninstall() {
    pam_guard
    ! pam_exists "$pending" || fail "Installation is pending; use --cancel-install first."
    pam_lock
    pam_guard
    ! pam_exists "$pending" || fail "Installation is pending; removal refused."
    pu_receipts=$(/usr/sbin/pkgutil --pkgs) || fail "Cannot inspect package receipts; nothing removed."
    pam_disable_locked
    pam_guard
    [ "$owned" = no ] || fail "PAM is still active."
    pam_assert_lock
    for pu_file in "$base/pam_watchid.so" "$base/libexec/pam_watchid-helper" \
        "$base/LICENSE" "$base/uninstall.sh"; do
        pam_safe_file "$pu_file"
        if pam_exists "$pu_file"; then
            /bin/rm -- "$pu_file" || fail "Cannot remove payload file: $pu_file"
        fi
    done
    if printf '%s\n' "$pu_receipts" | /usr/bin/grep -Fxq "$receipt"; then
        /usr/sbin/pkgutil --forget "$receipt" >/dev/null || fail "Cannot forget package receipt."
    fi
    for pu_directory in "$base/libexec" "$base"; do
        pam_exists "$pu_directory" || continue
        pu_remaining=$(/bin/ls -A "$pu_directory") || fail "Cannot inspect $pu_directory"
        if [ -n "$pu_remaining" ]; then
            printf '%s\n' "pam_watchid: Preserving additional files in $pu_directory" >&2
        else
            /bin/rmdir "$pu_directory" || fail "Cannot remove empty payload directory."
        fi
    done
    printf '%s\n' "pam_watchid: Payload removed; unrelated PAM bytes and persistent backups preserved."
}
