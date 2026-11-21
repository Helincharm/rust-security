isolation_error() {
    exit 70
}

test "$(id -u):$(id -g)" = '65532:65532' || isolation_error
grep -Eq '^CapEff:[[:space:]]+0+$' /proc/self/status || isolation_error
grep -Eq '^CapBnd:[[:space:]]+0+$' /proc/self/status || isolation_error
grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status || isolation_error
grep -Eq '^Seccomp:[[:space:]]+2$' /proc/self/status || isolation_error
set -- /sys/class/net/*
test "$#" = 1 && test "$1" = /sys/class/net/lo || isolation_error
awk '$5 == "/" && $6 ~ /^ro(,|$)/ { found = 1 } END { exit !found }' /proc/self/mountinfo || isolation_error
awk '$5 == "/work" && $6 ~ /(^|,)nosuid(,|$)/ && $6 ~ /(^|,)nodev(,|$)/ && $0 ~ / - tmpfs / { found = 1 } END { exit !found }' /proc/self/mountinfo || isolation_error
test "$(stat -f -c '%S %b' /work)" = '4096 16384' || isolation_error
test "$(stat -c '%u:%g:%a' /work)" = '65532:65532:700' || isolation_error
test "$(cat /sys/fs/cgroup/memory.max)" = 268435456 || isolation_error
test "$(cat /sys/fs/cgroup/memory.swap.max)" = 0 || isolation_error
test "$(cat /sys/fs/cgroup/cpu.max)" = '100000 100000' || isolation_error
test "$(cat /sys/fs/cgroup/pids.max)" = 64 || isolation_error
