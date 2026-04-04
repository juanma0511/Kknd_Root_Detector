#include <jni.h>
#include <android/log.h>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <sstream>
#include <fstream>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/inotify.h>
#include <dirent.h>
#include <errno.h>
#include <dlfcn.h>
#include <signal.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#ifndef __NR_statx
#define __NR_statx 291
#endif
#ifndef O_PATH
#define O_PATH 010000000
#endif

#define TAG "RootDetector"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

struct Detection { std::string name, desc; };
static std::vector<Detection> g_results;
static std::set<std::string> g_seen;

static void add(const char* id, const char* name, const std::string& desc) {
    if (g_seen.count(id)) return;
    g_seen.insert(id);
    g_results.push_back({name, desc});
    LOGI("[%s] %s", id, desc.c_str());
}

static bool fexists(const char* p) {
    struct stat s{};
    return stat(p, &s) == 0;
}

static bool fexists_or_noperm(const char* p) {
    struct stat s{};
    return stat(p, &s) == 0;
}

static std::string fread_str(const char* p) {
    int fd = open(p, O_RDONLY);
    if (fd < 0) return "";
    char buf[4096]{};
    read(fd, buf, sizeof(buf) - 1);
    close(fd);
    return buf;
}

static std::string prop_from_file(const char* file, const char* key) {
    std::ifstream f(file);
    if (!f) return "";
    std::string line, search = std::string(key) + "=";
    while (std::getline(f, line))
        if (line.find(search) == 0) return line.substr(search.size());
    return "";
}

static bool contains_ci(const std::string& h, const char* n) {
    std::string lh = h, ln = n;
    for (auto& c : lh) c = tolower(c);
    for (auto& c : ln) c = tolower(c);
    return lh.find(ln) != std::string::npos;
}

static bool contains_token_ci(const std::string& haystack, const char* needle) {
    if (!needle || !*needle) return false;
    std::string lh = haystack, ln = needle;
    for (auto& c : lh) c = (char)tolower(c);
    for (auto& c : ln) c = (char)tolower(c);
    size_t pos = lh.find(ln);
    while (pos != std::string::npos) {
        bool left_ok = pos == 0 || !(isalnum((unsigned char)lh[pos - 1]) || lh[pos - 1] == '_');
        size_t end = pos + ln.size();
        bool right_ok = end >= lh.size() || !(isalnum((unsigned char)lh[end]) || lh[end] == '_');
        if (left_ok && right_ok) return true;
        pos = lh.find(ln, pos + 1);
    }
    return false;
}

static std::vector<std::string> read_nul_file(const char* path) {
    std::vector<std::string> entries;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return entries;
    char buf[8192]{};
    ssize_t len = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (len <= 0) return entries;
    size_t start = 0;
    for (ssize_t i = 0; i < len; i++) {
        if (buf[i] == '\0') {
            if ((size_t)i > start) entries.emplace_back(buf + start, (size_t)i - start);
            start = (size_t)i + 1;
        }
    }
    if (start < (size_t)len) entries.emplace_back(buf + start, (size_t)len - start);
    return entries;
}

static pid_t find_pid_by_cmd_fragment(const char* needle) {
    DIR* dir = opendir("/proc");
    if (!dir) return -1;
    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        char* end;
        long pid = strtol(ent->d_name, &end, 10);
        if (*end) continue;
        char path[64];
        snprintf(path, sizeof(path), "/proc/%ld/cmdline", pid);
        std::string cmd = fread_str(path);
        if (!cmd.empty() && contains_ci(cmd, needle)) {
            closedir(dir);
            return (pid_t)pid;
        }
    }
    closedir(dir);
    return -1;
}

static void detectKernelsu() {
    errno = 0; prctl(0xDEAD, 0, 0, 0, 0);
    if (errno != EINVAL) {
        add("ksu_prctl", "KernelSU (prctl 0xDEAD)",
            "prctl(0xDEAD) errno!=EINVAL — KernelSU kernel hook confirmed");
        return;
    }
    errno = 0; prctl(PR_SET_MM, 0xDEAD, 0, 0, 0);
    if (errno != EINVAL && errno != EPERM)
        add("ksu_prctl2", "KernelSU Next (prctl PR_SET_MM)",
            "prctl(PR_SET_MM,0xDEAD) unexpected errno — KSU Next hook");
}

static void detectKernelsuKill() {
    errno = 0; kill(0x1314, 0);
    if (errno == 0)
        add("ksu_kill", "KernelSU (kill 0x1314)",
            "kill(0x1314,0) returned 0 — KernelSU intercepting kill() syscall");
}

static void detectKernelsuJbd2() {
    const char* ksu_nodes[] = {
        "/sys/module/kernelsu", "/sys/kernel/ksu",
        "/proc/kernelsu", "/sys/fs/kernelsu", nullptr
    };
    for (int i = 0; ksu_nodes[i]; i++) {
        if (fexists_or_noperm(ksu_nodes[i])) {
            add("ksu_sysfs", "KernelSU sysfs/proc Node",
                std::string("Exists: ") + ksu_nodes[i]);
            break;
        }
    }
}

static void detectMagiskSocket() {
    const char* names[] = {"magisk_service","magiskd","magisksu","zygisk_lp64","zygisk_lp32",nullptr};
    for (int i = 0; names[i]; i++) {
        int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (sock < 0) continue;
        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        size_t nlen = strlen(names[i]);
        memcpy(addr.sun_path + 1, names[i], nlen);
        socklen_t len = offsetof(struct sockaddr_un, sun_path) + 1 + nlen;
        struct timeval tv{0, 100000};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        int r = connect(sock, (struct sockaddr*)&addr, len);
        close(sock);
        if (r == 0) {
            add("magisk_sock", "Magisk Daemon Socket",
                std::string("Connected to abstract socket @") + names[i]);
            return;
        }
    }
}

static void detectZygisk() {
    const char* zlibs[] = {"libzygisk.so","libzygisk_loader.so","libriru.so","libriru_core.so",nullptr};
    for (int i = 0; zlibs[i]; i++) {
        void* h = dlopen(zlibs[i], RTLD_NOLOAD | RTLD_NOW);
        if (h) {
            dlclose(h);
            add("zygisk_dlopen", "Zygisk/Riru Lib Loaded",
                std::string("Already in linker ns: ") + zlibs[i]);
            return;
        }
    }

    std::ifstream maps("/proc/self/maps");
    if (!maps) return;
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(".so") == std::string::npos) continue;
        size_t sp = line.rfind(' ');
        if (sp == std::string::npos) continue;
        std::string path = line.substr(sp + 1);
        if (path.empty() || path[0] != '/') continue;
        if (path.find("/system/") == 0 || path.find("/apex/") == 0 ||
            path.find("/vendor/") == 0 || path.find("/data/app/") == 0) continue;
        if (contains_ci(path, "zygisk") || contains_ci(path, "riru")) {
            add("zygisk_maps", "Zygisk in Memory Maps",
                "Zygisk/Riru .so outside system paths: " + path.substr(0, 60));
            return;
        }
    }

    std::ifstream maps2("/proc/self/maps");
    int rwx = 0;
    while (std::getline(maps2, line)) {
        if (line.find("rwxp") == std::string::npos) continue;
        size_t sp = line.rfind(' ');
        if (sp == std::string::npos) continue;
        std::string pf = line.substr(sp + 1);
        if (!pf.empty() && pf[0] == '/') continue;
        if (pf.find("[stack") != std::string::npos) continue;
        if (pf.find("[anon:dalvik") != std::string::npos) continue;
        if (pf.find("[anon:ART") != std::string::npos) continue;
        if (pf.find("[anon:scudo") != std::string::npos) continue;
        if (pf.find("[anon:libc") != std::string::npos) continue;
        rwx++;
    }
    if (rwx > 20) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%d anon RWX pages >20 threshold", rwx);
        add("zygisk_rwx", "Zygisk Anon RWX Pages", buf);
    }
}

static void detectPtrace() {
    std::string status = fread_str("/proc/self/status");
    size_t pos = status.find("TracerPid:");
    if (pos != std::string::npos) {
        std::string val = status.substr(pos + 10);
        while (!val.empty() && (val[0] == ' ' || val[0] == '\t')) val = val.substr(1);
        int tpid = atoi(val.c_str());
        if (tpid > 0)
            add("ptrace_tracer", "Process Being Traced",
                "TracerPid=" + std::to_string(tpid) + " — Frida or debugger attached");
    }
}

static void detectSuBinary() {
    const char* bins[] = {"su","busybox","magisk","ksud","resetprop","apd",nullptr};
    const char* dirs[] = {"/sbin","/system/bin","/system/xbin","/data/local/bin",
                          "/data/local/xbin","/su/bin","/vendor/bin",nullptr};
    std::vector<std::string> found;
    for (int i = 0; dirs[i]; i++)
        for (int j = 0; bins[j]; j++) {
            char p[256];
            snprintf(p, sizeof(p), "%s/%s", dirs[i], bins[j]);
            if (fexists(p)) found.push_back(p);
        }
    if (!found.empty()) {
        std::string d = "Root binaries:";
        for (auto& p : found) d += " " + p;
        add("su_binary", "Root Binaries (native)", d);
    }
}

static void detectSulist() {
    const char* suspects[] = {"magiskd","ksud","frida-server","apd","zygisk-comp",nullptr};
    std::vector<std::string> found;
    DIR* d = opendir("/proc");
    if (!d) return;
    struct dirent* e;
    int checked = 0;
    while ((e = readdir(d)) != nullptr && checked < 512) {
        if (e->d_type != DT_DIR && e->d_type != DT_UNKNOWN) continue;
        char* end;
        strtol(e->d_name, &end, 10);
        if (*end) continue;
        checked++;
        char commpath[64];
        snprintf(commpath, sizeof(commpath), "/proc/%s/comm", e->d_name);
        int fd = open(commpath, O_RDONLY | O_NONBLOCK);
        if (fd < 0) continue;
        char comm[32]{};
        read(fd, comm, sizeof(comm) - 1);
        close(fd);
        for (int i = 0; suspects[i]; i++) {
            if (strncmp(comm, suspects[i], strlen(suspects[i])) == 0) {
                found.push_back(comm);
                break;
            }
        }
    }
    closedir(d);
    if (!found.empty()) {
        std::string d2 = "Root processes in /proc:";
        for (auto& p : found) d2 += " [" + p + "]";
        add("sulist", "Root Processes Running", d2);
    }
}

static void detectRootDaemonCmdline() {
    const char* suspects[] = {
        "magiskd", "ksud", "kernelsu", "apd", "zygisk",
        "lsposed", "lspd", "riru", "shamiko", "trickystore", "tricky_store",
        nullptr
    };
    std::vector<std::string> found;
    DIR* d = opendir("/proc");
    if (!d) return;
    struct dirent* e;
    int checked = 0;
    while ((e = readdir(d)) != nullptr && checked < 768) {
        if (e->d_type != DT_DIR && e->d_type != DT_UNKNOWN) continue;
        char* end;
        long pid = strtol(e->d_name, &end, 10);
        if (*end) continue;
        checked++;
        char cmdpath[64];
        snprintf(cmdpath, sizeof(cmdpath), "/proc/%ld/cmdline", pid);
        auto entries = read_nul_file(cmdpath);
        if (entries.empty()) continue;
        std::string combined;
        for (size_t i = 0; i < entries.size(); i++) {
            if (i) combined += " ";
            combined += entries[i];
        }
        for (int i = 0; suspects[i]; i++) {
            if (contains_token_ci(combined, suspects[i])) {
                found.push_back(std::string(suspects[i]) + " (pid " + std::to_string(pid) + ")");
                break;
            }
        }
    }
    closedir(d);
    if (!found.empty()) {
        std::string d2 = "Root daemons in cmdline:";
        int shown = 0;
        for (auto& p : found) { if (shown++ >= 4) break; d2 += " [" + p + "]"; }
        add("root_daemon_cmdline", "Root Daemon Cmdline", d2);
    }
}

static void detectRootUnixSockets() {
    std::ifstream sockets("/proc/net/unix");
    if (!sockets) return;
    const char* suspects[] = {
        "magisk", "zygisk", "ksud", "kernelsu", "apatch",
        "lsposed", "lspd", "riru", "shamiko", "trickystore", "tricky_store",
        nullptr
    };
    std::vector<std::string> found;
    std::string line;
    while (std::getline(sockets, line)) {
        for (int i = 0; suspects[i]; i++) {
            if (contains_token_ci(line, suspects[i])) {
                found.push_back(line);
                break;
            }
        }
    }
    if (!found.empty()) {
        std::string d = "Suspicious unix sockets:";
        int shown = 0;
        for (auto& f : found) {
            if (shown++ >= 3) break;
            d += " [" + f.substr(f.size() > 120 ? f.size() - 120 : 0) + "]";
        }
        add("root_unix_sockets", "Root Framework Unix Sockets", d);
    }
}

static void detectSuspiciousFiles() {
    const char* paths[] = {
        "/data/adb/magisk", "/data/adb/magisk.db", "/data/adb/modules",
        "/sbin/.magisk", "/system/addon.d/99-magisk.sh",
        "/dev/magisk_merge", "/dev/.magisk.unblock",
        "/data/adb/ksu", "/data/adb/ksud", "/dev/ksud", "/dev/ksu",
        "/sys/module/kernelsu", "/sys/kernel/ksu",
        
        "/data/adb/modules/playintegrityfix",
        "/data/adb/modules/PlayIntegrityFix",
        "/data/adb/modules/tricky_store",
        "/data/adb/modules/TrickyStore",
        "/data/adb/modules/lsposed",
        "/data/adb/modules/zygisk_lsposed",
        "/data/adb/modules/shamiko",
        "/data/adb/modules/Shamiko",
        "/data/adb/modules/susfs",
        "/data/adb/modules/safetynet-fix",
        "/data/adb/modules/HideMyApplist",
        "/system/app/Superuser.apk", "/system/xbin/daemonsu",
        nullptr
    };
    std::vector<std::string> found;
    for (int i = 0; paths[i]; i++)
        if (fexists_or_noperm(paths[i])) found.push_back(paths[i]);
    if (!found.empty()) {
        std::string d = "Root artifacts found:";
        for (auto& p : found) d += " " + p;
        add("suspicious_files", "Root Files Detected", d);
    }
}

static void detectSuspiciousPersistProps() {
    const char* prop_files[] = {"/data/property/persistent_properties", "/data/local.prop", nullptr};
    const char* bad_props[] = {"persist.sys.root_access","persist.magisk","persist.adb.root", nullptr};
    std::vector<std::string> found;
    for (int fi = 0; prop_files[fi]; fi++) {
        std::string content = fread_str(prop_files[fi]);
        if (content.empty()) continue;
        for (int pi = 0; bad_props[pi]; pi++)
            if (content.find(bad_props[pi]) != std::string::npos)
                found.push_back(std::string(bad_props[pi]) + " in " + prop_files[fi]);
    }
    char val[92]{};
    if (__system_property_get("persist.adb.root", val) > 0 && strcmp(val, "1") == 0)
        found.push_back("persist.adb.root=1");
    if (__system_property_get("ro.adb.secure", val) > 0 && strcmp(val, "0") == 0)
        found.push_back("ro.adb.secure=0");
    if (!found.empty()) {
        std::string d = "Suspicious properties:";
        for (auto& p : found) d += " [" + p + "]";
        add("persist_props", "Suspicious System Props", d);
    }
}

static void detectThirdPartyRom() {
    const char* prop_files[] = {
        "/system/build.prop", "/vendor/build.prop",
        "/system/vendor/build.prop", "/product/build.prop", nullptr
    };
    const struct { const char* key; const char* rom; } lineage_props[] = {
        {"ro.lineage.version","LineageOS"},
        {"ro.lineage.build.version","LineageOS"},
        {"ro.cm.version","CyanogenMod"},
        {"ro.crdroid.version","crDroid"},
        {"ro.corvus.version","CorvusOS"},
        {"ro.pixelexperience.version","PixelExperience"},
        {"ro.pe.version","PixelExperience"},
        {"ro.arrow.version","ArrowOS"},
        {"ro.potato.version","POSP"},
        {"ro.havoc.version","HavocOS"},
        {"ro.dot.version","DotOS"},
        {"ro.bliss.version","BlissROMs"},
        {"ro.omni.version","OmniROM"},
        {"ro.resurrection.version","ResurrectionRemix"},
        {"ro.aicp.version","AICP"},
        {"ro.evolution.version","EvolutionX"},
        {"ro.derp.version","DerpFest"},
        {"ro.spark.version","SparkOS"},
        {"ro.superioros.version","SuperiorOS"},
        {"ro.cherish.version","CherishOS"},
        {"ro.phhgsi.android.version","PHH-GSI"},
        {nullptr, nullptr}
    };
    std::vector<std::string> found;
    std::set<std::string> seen;
    for (int fi = 0; prop_files[fi]; fi++) {
        for (int pi = 0; lineage_props[pi].key; pi++) {
            if (seen.count(lineage_props[pi].key)) continue;
            std::string val = prop_from_file(prop_files[fi], lineage_props[pi].key);
            if (!val.empty()) {
                if (val.back() == '\n') val.pop_back();
                found.push_back(std::string(lineage_props[pi].rom) + "=" + val);
                seen.insert(lineage_props[pi].key);
            }
        }
    }
    char buf[256]{};
    __system_property_get("ro.build.flavor", buf);
    std::string flavor = buf;
    if (contains_ci(flavor, "lineage") || contains_ci(flavor, "crdroid") ||
        contains_ci(flavor, "pixel") || contains_ci(flavor, "arrow"))
        found.push_back("ro.build.flavor=" + flavor);

    char fp[256]{};
    __system_property_get("ro.build.fingerprint", fp);
    std::string fingerprint = fp;
    if (contains_ci(fingerprint, "lineage") || contains_ci(fingerprint, "crdroid") ||
        contains_ci(fingerprint, "pixelexperience") || contains_ci(fingerprint, "arrow") ||
        contains_ci(fingerprint, "evolution_x") || contains_ci(fingerprint, "derp"))
        found.push_back("Fingerprint: " + fingerprint.substr(0, 50));

    const char* lineage_files[] = {
        "/system/addon.d/50-lineage.sh", "/system/bin/lineage-setup",
        "/system/etc/lineage-release", "/system/etc/crdroid-version",
        nullptr
    };
    for (int i = 0; lineage_files[i]; i++)
        if (fexists(lineage_files[i]))
            found.push_back(std::string("File: ") + lineage_files[i]);

    if (!found.empty()) {
        std::string d = "Custom ROM detected:";
        for (size_t i = 0; i < found.size() && i < 4; i++) d += " [" + found[i] + "]";
        add("third_party_rom", "Custom/Third-Party ROM", d);
    }
}

static void detectKernelBuild() {
    struct utsname uts{};
    if (uname(&uts) != 0) return;
    std::string rel = uts.release, ver = uts.version;
    if (contains_ci(rel, "ksu") || contains_ci(rel, "kernelsu") ||
        contains_ci(rel, "ksunext") || contains_ci(rel, "sukisu"))
        add("kernel_ksu_str", "KernelSU in Kernel Build", "uname release: " + rel);

    const char* custom_kernels[] = {"arter97","sultan","blu_spark","elementsX",
        "Franco","NetHunter","kali",nullptr};
    for (int i = 0; custom_kernels[i]; i++) {
        if (contains_ci(rel, custom_kernels[i]) || contains_ci(ver, custom_kernels[i])) {
            add("custom_kernel", "Custom Kernel Detected",
                "Kernel: " + rel + " (matched: " + custom_kernels[i] + ")");
            break;
        }
    }

    std::string procver = fread_str("/proc/version");
    if (!procver.empty()) {
        const char* custom_hosts[] = {"archlinux","kali","popos","lineage","crdroid",nullptr};
        for (int i = 0; custom_hosts[i]; i++) {
            if (contains_ci(procver, custom_hosts[i])) {
                add("custom_kernel_host", "Custom Kernel Build Host",
                    "Build host: " + procver.substr(0, 80));
                break;
            }
        }
    }
}

static void detectKernelBlacklist() {
    std::string cmdline = fread_str("/proc/cmdline");
    bool orange = cmdline.find("verifiedbootstate=orange") != std::string::npos
               || cmdline.find("androidboot.verifiedbootstate=orange") != std::string::npos;
    bool unlocked = cmdline.find("androidboot.flash.locked=0") != std::string::npos;
    bool noverity = cmdline.find("androidboot.veritymode=disabled") != std::string::npos;
    bool selinux_perm = cmdline.find("androidboot.selinux=permissive") != std::string::npos;
    std::string d;
    if (orange)       d += "[verifiedbootstate=orange] ";
    if (unlocked)     d += "[flash.locked=0] ";
    if (noverity)     d += "[veritymode=disabled] ";
    if (selinux_perm) d += "[selinux=permissive] ";
    if (!d.empty()) add("kernel_cmdline", "Dangerous Kernel Boot Params", d);

    std::string enforce = fread_str("/sys/fs/selinux/enforce");
    while (!enforce.empty() && (enforce.back() == '\n' || enforce.back() == '\r'))
        enforce.pop_back();
    if (enforce == "0")
        add("selinux_perm", "SELinux Permissive", "/sys/fs/selinux/enforce=0");
}

static void detectApatch() {
    const char* paths[] = {"/data/adb/ap", "/data/adb/apd", "/dev/apatch", nullptr};
    for (int i = 0; paths[i]; i++) {
        if (fexists_or_noperm(paths[i])) {
            add("apatch", "APatch Detected", std::string("APatch artifact: ") + paths[i]);
            return;
        }
    }
    char val[92]{};
    if (__system_property_get("ro.apatch.version", val) > 0)
        add("apatch_prop", "APatch (system prop)", std::string("ro.apatch.version=") + val);
}

static void detectCgroupSupport() {
    std::string cgroup = fread_str("/proc/self/cgroup");
    if (!cgroup.empty()) {
        if (contains_ci(cgroup, "magisk") || contains_ci(cgroup, "ksu") ||
            contains_ci(cgroup, "su"))
            add("cgroup_anomaly", "Suspicious cgroup",
                "Process cgroup contains root indicator: " + cgroup.substr(0, 80));
    }
    if (fexists("/sys/fs/cgroup/freezer/magisk"))
        add("cgroup_magisk", "Magisk Freezer Cgroup", "/sys/fs/cgroup/freezer/magisk exists");
}

static void detectMountAnomalies() {
    std::ifstream mounts("/proc/mounts");
    if (!mounts) return;
    std::string line;
    bool has_magisk_tmpfs = false, has_debug_ramdisk = false;
    bool has_magisk_mirror = false, has_overlay_system = false;
    bool has_tmpfs_data = false;
    int bind_system_count = 0;
    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string dev, mp, fs, opts;
        iss >> dev >> mp >> fs >> opts;
        if (fs == "tmpfs" && mp == "/sbin") has_magisk_tmpfs = true;
        if (mp == "/debug_ramdisk") has_debug_ramdisk = true;
        if (mp.find("/.magisk") != std::string::npos) has_magisk_mirror = true;
        if (fs == "overlay" &&
            (mp == "/system" || mp == "/vendor" || mp == "/product" || mp == "/system_root") &&
            (contains_ci(line, "/data/adb") || contains_ci(line, ".magisk") ||
             contains_ci(line, "magisk") || contains_token_ci(line, "ksu") ||
             contains_ci(line, "kernelsu") || contains_ci(line, "apatch")))
            has_overlay_system = true;
        if (dev.find("/system") != std::string::npos && mp.find("/system") != std::string::npos &&
            dev != mp) bind_system_count++;
        if (fs == "tmpfs" && mp.find("/data/adb") != std::string::npos) {
            has_tmpfs_data = true;
            add("mount_tmpfs_data", "Suspicious tmpfs on /data/adb",
                "tmpfs on " + mp + " — Magisk/KSU using tmpfs to hide files");
        }
    }
    if (has_magisk_tmpfs)
        add("magisk_tmpfs", "Magisk tmpfs /sbin", "tmpfs on /sbin — old Magisk signature");
    if (has_debug_ramdisk && (has_magisk_tmpfs || has_magisk_mirror || has_overlay_system || has_tmpfs_data))
        add("magisk_debug_rd", "Magisk /debug_ramdisk", "/debug_ramdisk present with companion root staging traces");
    if (has_magisk_mirror)
        add("magisk_mirror", "Magisk Mirror Mount", "/.magisk path in /proc/mounts");
    if (has_overlay_system)
        add("overlay_system", "Magisk OverlayFS", "overlayfs on /system or /vendor");
    if (bind_system_count > 0)
        add("bind_mount_system", "Suspicious Bind Mounts",
            std::to_string(bind_system_count) + " bind mount(s) over system paths");
}

static void detectResetprop() {
    const char* rp_paths[] = {
        "/sbin/resetprop", "/system/bin/resetprop", "/system/xbin/resetprop",
        "/data/adb/resetprop", "/data/local/tmp/resetprop", nullptr
    };
    for (int i = 0; rp_paths[i]; i++) {
        if (fexists_or_noperm(rp_paths[i])) {
            add("resetprop", "resetprop Binary Found",
                std::string("Magisk resetprop at: ") + rp_paths[i]);
            return;
        }
    }
    struct PropCheck { const char* key; const char* file; } checks[] = {
        {"ro.build.tags", "/system/build.prop"},
        {"ro.build.tags", "/system/system/build.prop"},
        {"ro.build.fingerprint", "/system/build.prop"},
        {"ro.build.fingerprint", "/system/system/build.prop"},
        {"ro.vendor.build.fingerprint", "/vendor/build.prop"},
        {"ro.product.build.fingerprint", "/product/build.prop"},
        {"ro.product.device", "/system/build.prop"},
        {"ro.product.device", "/product/build.prop"},
        {"ro.debuggable", "/system/build.prop"},
        {"ro.secure", "/system/build.prop"},
        {"ro.build.type", "/system/build.prop"},
        {"ro.build.type", "/system/system/build.prop"},
        {"ro.boot.vbmeta.device_state", "/default.prop"},
        {"ro.boot.flash.locked", "/default.prop"},
        {"ro.boot.verifiedbootstate", "/default.prop"},
        {"ro.boot.vbmeta.device_state", "/vendor/default.prop"},
        {"ro.boot.flash.locked", "/vendor/default.prop"},
        {"ro.boot.verifiedbootstate", "/vendor/default.prop"},
        {nullptr, nullptr}
    };
    std::vector<std::string> mismatches;
    for (int i = 0; checks[i].key; i++) {
        char live[256]{};
        if (__system_property_get(checks[i].key, live) <= 0) continue;
        std::string file_val = prop_from_file(checks[i].file, checks[i].key);
        if (!file_val.empty() && file_val.back() == '\n') file_val.pop_back();
        if (!file_val.empty() && strcmp(live, file_val.c_str()) != 0) {
            mismatches.push_back(std::string(checks[i].key) + " system=['" + live + "'] file=['" + file_val + "']");
        }
    }
    char serial_live[256]{};
    char serial_boot[256]{};
    if (__system_property_get("ro.serialno", serial_live) > 0 &&
        __system_property_get("ro.boot.serialno", serial_boot) > 0 &&
        strcmp(serial_live, serial_boot) != 0) {
        mismatches.push_back(std::string("serial mismatch: ro.serialno=['") + serial_live + "'] ro.boot.serialno=['" + serial_boot + "']");
    }
    if (!mismatches.empty()) {
        std::string detail = "resetprop/property mismatches:";
        for (size_t i = 0; i < mismatches.size() && i < 4; i++) detail += " [" + mismatches[i] + "]";
        add("resetprop_mismatch", "Build Prop Mismatch (resetprop)", detail);
    }
}

static void detectLspHook() {
    std::ifstream maps("/proc/self/maps");
    if (!maps) return;
    std::string line;
    while (std::getline(maps, line)) {
        if (contains_ci(line, "lspd") || contains_ci(line, "lsposed") ||
            contains_ci(line, "edxp") || contains_ci(line, "sandhook") ||
            contains_ci(line, "whale") || contains_ci(line, "dobby")) {
            size_t sp = line.rfind(' ');
            std::string path = (sp != std::string::npos) ? line.substr(sp + 1) : line;
            if (path.find("/system/") == 0 || path.find("/apex/") == 0) continue;
            add("lsp_hook", "LSPosed/Xposed Hook in Memory",
                "Hook framework in maps: " + path.substr(0, 60));
            return;
        }
    }
    const char* lsp_paths[] = {
        "/data/adb/lspd", "/data/adb/lspatch",
        "/system/framework/XposedBridge.jar", nullptr
    };
    for (int i = 0; lsp_paths[i]; i++) {
        if (fexists_or_noperm(lsp_paths[i])) {
            add("lsp_files", "LSPosed Files Detected",
                std::string("LSPosed artifact: ") + lsp_paths[i]);
            return;
        }
    }
}

static void detectFrida() {
    int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock >= 0) {
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(27042);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        struct timeval tv{0, 100000};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0)
            add("frida_port", "Frida Server (port 27042)", "Frida server on 127.0.0.1:27042");
        close(sock);
    }
    std::ifstream maps("/proc/self/maps");
    if (!maps) return;
    std::string line;
    while (std::getline(maps, line)) {
        if (contains_ci(line, "frida-agent") || contains_ci(line, "frida-gadget")) {
            add("frida_gadget", "Frida Gadget Injected", "frida-agent/gadget in /proc/self/maps");
            return;
        }
    }
}

static void detectNativeBridge() {
    char val[256]{};
    __system_property_get("ro.dalvik.vm.native.bridge", val);
    if (strlen(val) > 0 && strcmp(val, "0") != 0)
        add("native_bridge", "Native Bridge Enabled",
            std::string("ro.dalvik.vm.native.bridge=") + val);
    if (fexists("/system/lib/libhoudini.so") || fexists("/system/lib64/libhoudini.so"))
        add("houdini", "Houdini Native Bridge", "libhoudini.so found — x86 emulating ARM");
}

static void detectAvbVersion() {
    char vbs[256]{};
    __system_property_get("ro.boot.verifiedbootstate", vbs);
    if (strcmp(vbs, "orange") == 0)
        add("avb_orange", "AVB State: Orange (Unlocked)",
            "ro.boot.verifiedbootstate=orange — bootloader unlocked");
    else if (strcmp(vbs, "yellow") == 0)
        add("avb_yellow", "AVB State: Yellow (Custom Key)",
            "ro.boot.verifiedbootstate=yellow — custom signing key");
    char vbm[256]{};
    __system_property_get("ro.boot.veritymode", vbm);
    if (strcmp(vbm, "disabled") == 0 || strcmp(vbm, "logging") == 0)
        add("avb_verity", "dm-verity Disabled",
            std::string("ro.boot.veritymode=") + vbm);
}

static void detectEnvAnomalies() {
    const char* path_env = getenv("PATH");
    if (path_env) {
        std::string path = path_env;
        const char* bad[] = {"/su/bin", "/data/local/bin", "/data/local/xbin", nullptr};
        for (int i = 0; bad[i]; i++) {
            if (path.find(bad[i]) != std::string::npos) {
                add("env_path", "Suspicious PATH", std::string("PATH contains: ") + bad[i]);
                break;
            }
        }
    }
    const char* ld = getenv("LD_PRELOAD");
    if (ld && strlen(ld) > 0)
        add("ld_preload", "LD_PRELOAD Set", std::string("LD_PRELOAD=") + ld);
    const char* ldlp = getenv("LD_LIBRARY_PATH");
    if (ldlp) {
        std::string lp = ldlp;
        if (lp.find("/data/") != std::string::npos || lp.find("/tmp/") != std::string::npos)
            add("ld_lib_path", "Suspicious LD_LIBRARY_PATH", std::string("LD_LIBRARY_PATH=") + lp);
    }
}

static void detectJniTableSource(JNIEnv* env) {
    void* find_class_ptr = (void*)env->functions->FindClass;
    Dl_info info{};
    if (dladdr(find_class_ptr, &info) && info.dli_fname) {
        std::string fname = info.dli_fname;
        if (fname.find("/system/") == std::string::npos &&
            fname.find("/apex/") == std::string::npos)
            add("jni_hook", "JNI Table Hooked",
                "FindClass points to: " + fname);
    }
}

static void detectBuildPropsNative() {
    const char* files[] = {"/system/build.prop", "/vendor/build.prop", nullptr};
    struct { const char* key; const char* bad; } checks[] = {
        {"ro.debuggable","1"}, {"ro.secure","0"},
        {"ro.build.tags","test-keys"}, {"ro.build.type","userdebug"},
        {"ro.build.type","eng"}, {nullptr, nullptr}
    };
    std::vector<std::string> found;
    std::set<std::string> seen;
    for (int fi = 0; files[fi]; fi++)
        for (int ci = 0; checks[ci].key; ci++) {
            if (seen.count(checks[ci].key)) continue;
            std::string v = prop_from_file(files[fi], checks[ci].key);
            if (!v.empty() && v.back() == '\n') v.pop_back();
            if (!v.empty() && v.find(checks[ci].bad) != std::string::npos) {
                found.push_back(std::string(checks[ci].key) + "=" + v);
                seen.insert(checks[ci].key);
            }
        }
    if (!found.empty()) {
        std::string d = "Dangerous props (direct file read):";
        for (auto& p : found) d += " [" + p + "]";
        add("build_props_native", "Dangerous Build Props (native)", d);
    }
}

static void detectMountLoophole() {
    std::ifstream mounts("/proc/mounts");
    if (!mounts) return;
    std::string line;
    std::vector<std::string> found;
    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string dev, mp, fs;
        iss >> dev >> mp >> fs;
        if (dev.find("/dev/loop") == 0) {
            found.push_back(dev + " -> " + mp + " [" + fs + "]");
        }
        if (mp.find("/proc/1/") != std::string::npos && mp != "/proc/1/ns") {
            found.push_back("Mount over /proc/1: " + mp);
        }
    }
    if (!found.empty()) {
        std::string d = "Loop/proc mounts (Magisk module hiding):";
        for (size_t i = 0; i < found.size() && i < 4; i++) d += " [" + found[i] + "]";
        add("mount_loophole", "Mount Loophole (loop device)", d);
    }
}

static void detectHiddenProcessGroups() {
    std::ifstream tasks_f("/proc/self/task");
    int proc_count = 0, task_count = 0;

    DIR* proc_d = opendir("/proc");
    if (proc_d) {
        struct dirent* e;
        while ((e = readdir(proc_d)) != nullptr) {
            char* end; strtol(e->d_name, &end, 10);
            if (!*end) proc_count++;
        }
        closedir(proc_d);
    }

    char cgroup[256]{};
    snprintf(cgroup, sizeof(cgroup), "/proc/self/cgroup");
    std::string cg = fread_str(cgroup);

    if (proc_count > 0) {
        int fd = open("/proc/self/status", O_RDONLY);
        if (fd >= 0) {
            char buf[1024]{};
            read(fd, buf, sizeof(buf) - 1);
            close(fd);
            std::string status = buf;
            size_t pos = status.find("Threads:");
            if (pos != std::string::npos) {
                int threads = atoi(status.c_str() + pos + 8);
                task_count = threads;
            }
        }
    }

    int fd_count = 0;
    int suspicious_fd_count = 0;
    std::vector<std::string> suspicious_targets;
    DIR* fd_d = opendir("/proc/self/fd");
    if (fd_d) {
        struct dirent* e;
        while ((e = readdir(fd_d)) != nullptr) {
            char* end; strtol(e->d_name, &end, 10);
            if (*end) continue;
            fd_count++;
            char path[64]{};
            char target[PATH_MAX]{};
            snprintf(path, sizeof(path), "/proc/self/fd/%s", e->d_name);
            ssize_t len = readlink(path, target, sizeof(target) - 1);
            if (len <= 0) continue;
            target[len] = '\0';
            std::string lower = target;
            for (auto& c : lower) c = (char)tolower(c);
            bool suspicious = contains_ci(lower, "/data/adb") ||
                contains_ci(lower, "/.magisk") ||
                contains_ci(lower, "/debug_ramdisk") ||
                contains_ci(lower, "magisk") ||
                contains_ci(lower, "zygisk") ||
                contains_ci(lower, "lsposed") ||
                contains_ci(lower, "riru") ||
                contains_ci(lower, "kernelsu") ||
                contains_token_ci(lower, "ksu") ||
                contains_ci(lower, "apatch");
            if (suspicious) {
                suspicious_fd_count++;
                if (suspicious_targets.size() < 3) suspicious_targets.emplace_back(target);
            }
        }
        closedir(fd_d);
    }

    if ((fd_count > 384 && suspicious_fd_count >= 2) || (fd_count > 512 && suspicious_fd_count >= 1)) {
        char buf[256];
        std::string detail = "Unusually high suspicious fd count: " + std::to_string(fd_count) +
            " with " + std::to_string(suspicious_fd_count) + " root-related targets";
        if (!suspicious_targets.empty()) {
            detail += " (" + suspicious_targets[0];
            for (size_t i = 1; i < suspicious_targets.size(); i++) detail += ", " + suspicious_targets[i];
            detail += ")";
        }
        snprintf(buf, sizeof(buf), "%s", detail.c_str());
        add("hidden_proc_fds", "High File Descriptor Count", buf);
    }

    std::string proc1_maps = fread_str("/proc/1/maps");
    if (!proc1_maps.empty() && (contains_ci(proc1_maps, "magisk") ||
        contains_ci(proc1_maps, "zygisk") || contains_ci(proc1_maps, "ksu"))) {
        add("hidden_proc_init", "Root Framework in init Maps",
            "Root framework found in /proc/1/maps (init process)");
    }
}

static void detectHwBreakpoints() {
    std::string status = fread_str("/proc/self/status");
    size_t pos = status.find("TracerPid:");
    if (pos != std::string::npos) {
        std::string val = status.substr(pos + 10);
        while (!val.empty() && (val[0] == ' ' || val[0] == '\t')) val = val.substr(1);
        int tpid = atoi(val.c_str());
        if (tpid > 0)
            add("hw_bp_tracer", "Process Traced (Ptrace/HW)",
                "TracerPid=" + std::to_string(tpid) + " — debugger or hardware breakpoint active");
    }

    std::string wchan = fread_str("/proc/self/wchan");
    while (!wchan.empty() && (wchan.back() == '\n' || wchan.back() == '\r'))
        wchan.pop_back();
    if (wchan == "ptrace_stop" || wchan == "wait_on_page_bit")
        add("hw_bp_wchan", "Ptrace Stop Detected",
            "/proc/self/wchan=" + wchan + " — process stopped by debugger");
}

static void detectAnonExec() {
    std::ifstream maps("/proc/self/maps");
    if (!maps) return;
    std::string line;
    int anon_exec = 0;
    std::vector<std::string> found;
    while (std::getline(maps, line)) {
        if (line.find("--xp") == std::string::npos && line.find("r-xp") == std::string::npos) continue;
        size_t sp = line.rfind(' ');
        if (sp == std::string::npos) continue;
        std::string path = line.substr(sp + 1);
        if (!path.empty() && path[0] == '/') continue;
        if (path.find("[vdso]") != std::string::npos || path.find("[vsyscall]") != std::string::npos) continue;
        if (path.find("[anon:dalvik") != std::string::npos) continue;
        if (path.find("[anon:ART") != std::string::npos) continue;
        if (path.find("[anon:scudo") != std::string::npos) continue;
        anon_exec++;
        if (anon_exec <= 3) found.push_back(line.substr(0, 60));
    }
    if (anon_exec > 3) {
        std::string d = "Anonymous executable mappings (" + std::to_string(anon_exec) + "):";
        for (auto& f : found) d += " [" + f.substr(0, 40) + "]";
        add("anon_exec", "Anonymous Executable Pages", d);
    }
}

static void detectEvilServices() {
    const char* evil_pkgs[] = {
        "tornaco.android.thanos",
        "tornaco.android.thanox",
        "github.tornaco.android.thanos",
        "github.tornaco.android.thanox",
        "com.omarea.vtools",
        "com.omarea.charge",
        "com.lbe.parallel.intl",
        "com.parallel.space.lite",
        "com.excelliance.dualaid",
        nullptr
    };
    std::string d;
    bool found = false;
    for (int i = 0; evil_pkgs[i]; i++) {
        char val[92]{};
        char prop[128];
        snprintf(prop, sizeof(prop), "ro.product.name");
        if (__system_property_get(prop, val) > 0 &&
            strstr(val, evil_pkgs[i]) != nullptr) {
            d += std::string(" [") + evil_pkgs[i] + "]";
            found = true;
        }
    }

    const char* thanox_paths[] = {
        "/data/system/thanos",
        "/data/system/thanox",
        nullptr
    };
    for (int i = 0; thanox_paths[i]; i++) {
        if (fexists(thanox_paths[i])) {
            d += std::string(" [") + thanox_paths[i] + "]";
            found = true;
        }
    }

    if (found)
        add("evil_services", "Thanox/Scene Process Manager", "Process manager detected:" + d);

    const char* scene_ports[] = {"27183", "27184"};
    for (auto& port_str : scene_ports) {
        int port = atoi(port_str);
        int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (sock < 0) continue;
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        struct timeval tv{0, 80000};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0)
            add("scene_port", "Scene Port Open",
                std::string("Scene/KernelSU manager port ") + port_str + " is open");
        close(sock);
    }
}

static void detectPty() {
    DIR* d = opendir("/proc/self/fd");
    if (!d) return;
    struct dirent* e;
    bool found = false;
    while ((e = readdir(d)) != nullptr) {
        if (e->d_name[0] == '.') continue;
        char link[512]{}, target[512]{};
        snprintf(link, sizeof(link), "/proc/self/fd/%s", e->d_name);
        ssize_t len = readlink(link, target, sizeof(target) - 1);
        if (len <= 0) continue;
        target[len] = '\0';
        if (strncmp(target, "/dev/pts/", 9) == 0 ||
            strncmp(target, "/dev/pty", 8) == 0) {
            found = true;
            break;
        }
    }
    closedir(d);
    if (found)
        add("pty_fd", "PTY File Descriptor Open",
            "Open /dev/pts/* fd — interactive terminal attached (Frida/ADB shell injection)");
}

static void detectLibraryOrder() {
    std::ifstream maps("/proc/self/maps");
    if (!maps) return;
    std::string line;
    std::vector<std::string> loaded;
    while (std::getline(maps, line)) {
        if (line.find(".so") == std::string::npos) continue;
        size_t sp = line.rfind(' ');
        if (sp == std::string::npos) continue;
        std::string path = line.substr(sp + 1);
        if (path.empty() || path[0] != '/') continue;
        if (path.find("/system/") != 0 && path.find("/apex/") != 0) {
            if (loaded.empty() || loaded.back() != path)
                loaded.push_back(path);
        }
    }

    std::vector<std::string> suspicious;
    for (auto& lib : loaded) {
        if (contains_ci(lib, "inject") || contains_ci(lib, "hook") ||
            contains_ci(lib, "patch") || contains_ci(lib, "xposed") ||
            contains_ci(lib, "zygisk") || contains_ci(lib, "riru") ||
            contains_ci(lib, "magisk")) {
            suspicious.push_back(lib);
        }
    }

    if (!suspicious.empty()) {
        std::string d = "Suspicious libs:";
        for (size_t i = 0; i < suspicious.size() && i < 3; i++) d += " [" + suspicious[i] + "]";
        add("lib_suspicious", "Hook/Inject Libs in Memory", d);
    }
}

static void detectSoTampering() {
    
    Dl_info info{};
    if (dladdr((void*)dlopen, &info) && info.dli_fname) {
        std::string libc_path = info.dli_fname;
        
        if (libc_path.find("/system/") == std::string::npos &&
            libc_path.find("/apex/") == std::string::npos &&
            libc_path.find("/vendor/") == std::string::npos &&
            libc_path.find("/bionic/") == std::string::npos) {
            add("so_tamper_libc", "libc/dlopen from Non-System Path",
                "dlopen is at: " + libc_path);
        }
    }
}

static void detectVirtualArch() {
    struct utsname uts{};
    if (uname(&uts) != 0) return;
    std::string machine = uts.machine;

    char prop_hw[256]{};
    __system_property_get("ro.hardware", prop_hw);

    const char* vm_indicators[] = {
        "vbox", "vmware", "qemu", "goldfish", "ranchu", "nox", "genymotion", nullptr
    };
    for (int i = 0; vm_indicators[i]; i++) {
        if (contains_ci(machine, vm_indicators[i]) ||
            contains_ci(prop_hw, vm_indicators[i])) {
            add("virtual_arch", "Virtual Architecture Detected",
                std::string("Hardware/machine matches VM: ") + prop_hw + "/" + machine);
            return;
        }
    }

    char prop_cpu[256]{};
    __system_property_get("ro.product.cpu.abi", prop_cpu);
    std::string cpu_abi = prop_cpu;

    char prop_cpu2[256]{};
    __system_property_get("ro.product.cpu.abilist", prop_cpu2);
    std::string abi_list = prop_cpu2;

    if (contains_ci(cpu_abi, "x86") && abi_list.find("arm") != std::string::npos)
        add("virtual_native_bridge", "x86 Device with ARM ABI List",
            "Native bridge active: cpu=" + cpu_abi + " abilist=" + abi_list);
}

static void detectFakeEnvironment() {
    char model[256]{}, manufacturer[256]{}, brand[256]{};
    __system_property_get("ro.product.model", model);
    __system_property_get("ro.product.manufacturer", manufacturer);
    __system_property_get("ro.product.brand", brand);

    const char* fake_models[] = {
        "google_sdk", "sdk_gphone", "Android SDK built",
        "generic", "emulator", "Genymotion",
        nullptr
    };
    for (int i = 0; fake_models[i]; i++) {
        if (contains_ci(model, fake_models[i]) ||
            contains_ci(manufacturer, fake_models[i])) {
            add("fake_env_model", "Fake/Emulator Device Model",
                std::string("model=") + model + " manufacturer=" + manufacturer);
            return;
        }
    }

    char timezone[256]{};
    __system_property_get("persist.sys.timezone", timezone);
    if (strlen(timezone) == 0 || strcmp(timezone, "UTC") == 0) {
        char country[256]{};
        __system_property_get("ro.product.locale", country);
        if (strlen(country) == 0)
            add("fake_env_tz", "Suspicious Timezone/Locale",
                "timezone=UTC and no product locale — likely emulator or wiped device");
    }
}

static void detectMagicMount() {
    std::ifstream mounts("/proc/mounts");
    if (!mounts) return;
    std::string line;
    int magic_count = 0;
    std::vector<std::string> suspicious_mounts;
    const char* legit[] = {
        "/system/etc/fonts", "/system/fonts", "/system/media",
        "/vendor/overlay", "/product/overlay", "/system/overlay", "/odm/overlay",
        nullptr
    };
    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string dev, mp, fs;
        iss >> dev >> mp >> fs;
        if (fs != "tmpfs" && fs != "overlay" && fs != "ext4" && fs != "f2fs") continue;
        if (mp.find("/system/") != 0 && mp.find("/vendor/") != 0 &&
            mp.find("/product/") != 0 && mp.find("/odm/") != 0) continue;
        bool skip = false;
        for (int i = 0; legit[i]; i++)
            if (mp.find(legit[i]) == 0) { skip = true; break; }
        if (skip) continue;
        bool root_marker = contains_ci(line, "/data/adb") ||
            contains_ci(line, "/.magisk") ||
            contains_ci(line, "magisk") ||
            contains_ci(line, "zygisk") ||
            contains_ci(line, "kernelsu") ||
            contains_token_ci(line, "ksu") ||
            contains_ci(line, "apatch") ||
            contains_ci(line, "debug_ramdisk");
        bool overlay_with_data = fs == "overlay" &&
            (contains_ci(line, "upperdir=/data/") || contains_ci(line, "workdir=/data/"));
        bool suspicious_tmpfs = fs == "tmpfs" && (contains_ci(line, "/data/adb") || contains_ci(line, "debug_ramdisk"));
        if (!(root_marker || overlay_with_data || suspicious_tmpfs)) continue;
        if (dev.find("/dev/block/") != std::string::npos && !overlay_with_data && !root_marker) continue;
        magic_count++;
        if (suspicious_mounts.size() < 3) suspicious_mounts.push_back(mp);
    }
    if (magic_count > 0) {
        char buf[160];
        std::string detail = std::to_string(magic_count) + " root-like mount path(s) in system partitions";
        if (!suspicious_mounts.empty()) {
            detail += " (" + suspicious_mounts[0];
            for (size_t i = 1; i < suspicious_mounts.size(); i++) detail += ", " + suspicious_mounts[i];
            detail += ")";
        }
        snprintf(buf, sizeof(buf), "%s", detail.c_str());
        add("magic_mount", "Magisk Magic Mount Detected", buf);
    }
}

static void detectProc1MountDiff() {
    auto read_mounts = [](const char* path) {
        std::set<std::string> result;
        std::ifstream f(path);
        std::string line;
        while (std::getline(f, line)) {
            std::istringstream iss(line);
            std::string dev, mp;
            iss >> dev >> mp;
            result.insert(mp);
        }
        return result;
    };

    auto self_mounts = read_mounts("/proc/self/mounts");
    auto init_mounts = read_mounts("/proc/1/mounts");

    std::vector<std::string> only_in_self;
    for (auto& mp : self_mounts) {
        if (init_mounts.find(mp) == init_mounts.end())
            only_in_self.push_back(mp);
    }

    
    const char* normal_mounts[] = {
        "/mnt/vendor/efs", "/mnt/vendor/persist", "/mnt/vendor/dsp",
        "/system_dlkm", "/system_ext", "/vendor_dlkm", "/odm_dlkm",
        "/mnt/product", "/mnt/odm", "/mnt/oem",
        "/data/vendor", "/data/misc/vold",
        "/vendor", "/odm", "/product",  
        nullptr
    };
    std::vector<std::string> suspicious;
    for (auto& mp : only_in_self) {
        bool is_normal = false;
        for (int ni = 0; normal_mounts[ni]; ni++) {
            if (mp == normal_mounts[ni] || mp.find(normal_mounts[ni]) == 0) {
                is_normal = true; break;
            }
        }
        if (is_normal) continue;
        if (mp.find("/data/adb") != std::string::npos ||
            mp.find("/.magisk") != std::string::npos ||
            mp.find("/sbin/.") != std::string::npos ||
            mp.find("/debug_ramdisk") != std::string::npos) {
            suspicious.push_back(mp);
        }
    }

    if (!suspicious.empty()) {
        std::string d = "Mounts in app but not in init (" + std::to_string(suspicious.size()) + "):";
        for (size_t i = 0; i < suspicious.size() && i < 3; i++) d += " [" + suspicious[i] + "]";
        add("proc1_mount_diff", "Mount Namespace Divergence",
            d + " — Magisk namespaces mounts to hide from init");
    }
}

static void detectMountConsistency() {
    auto read_mounts = [](const char* path) {
        std::map<std::string, std::pair<std::string, std::string>> result;
        std::ifstream f(path);
        std::string line;
        while (std::getline(f, line)) {
            std::istringstream iss(line);
            std::string dev, mp, fs;
            iss >> dev >> mp >> fs;
            if (!mp.empty()) result[mp] = {dev, fs};
        }
        return result;
    };

    auto is_sensitive = [](const std::string& mp) {
        const char* prefixes[] = {
            "/system", "/vendor", "/product", "/odm",
            "/system_ext", "/debug_ramdisk", "/.magisk",
            "/data/adb", "/sbin", nullptr
        };
        for (int i = 0; prefixes[i]; i++) {
            const std::string prefix = prefixes[i];
            if (mp == prefix || mp.find(prefix + "/") == 0) return true;
        }
        return false;
    };

    auto self_mounts = read_mounts("/proc/self/mounts");
    auto init_mounts = read_mounts("/proc/1/mounts");
    if (self_mounts.empty() || init_mounts.empty()) return;

    std::vector<std::string> details;
    for (const auto& entry : self_mounts) {
        const std::string& mp = entry.first;
        if (!is_sensitive(mp)) continue;
        const auto& self_pair = entry.second;
        auto it = init_mounts.find(mp);
        if (it == init_mounts.end()) {
            details.push_back(mp + " self-only=" + self_pair.first + ":" + self_pair.second);
            continue;
        }
        if (self_pair != it->second) {
            details.push_back(
                mp + " self=" + self_pair.first + ":" + self_pair.second +
                " init=" + it->second.first + ":" + it->second.second
            );
        }
    }

    if (!details.empty()) {
        std::string d = "Mount consistency mismatch (" + std::to_string(details.size()) + "):";
        for (size_t i = 0; i < details.size() && i < 4; i++) d += " [" + details[i] + "]";
        add("mount_consistency", "Mount Consistency Failure", d);
    }
}

static void detectZygoteEnvironment() {
    auto is_suspicious = [](const std::string& value) {
        return contains_ci(value, "magisk") ||
               contains_ci(value, "zygisk") ||
               contains_ci(value, "riru") ||
               contains_ci(value, "lsposed") ||
               contains_ci(value, "xposed") ||
               contains_ci(value, "edxp") ||
               contains_ci(value, "kernelsu") ||
               contains_ci(value, "ksu") ||
               contains_ci(value, "apatch") ||
               contains_ci(value, "frida") ||
               contains_ci(value, "dobby") ||
               contains_ci(value, "shadowhook") ||
               contains_ci(value, "sandhook");
    };

    std::vector<std::string> hits;
    for (const auto& entry : read_nul_file("/proc/self/environ")) {
        if (is_suspicious(entry)) hits.push_back("self:" + entry.substr(0, 80));
    }

    const char* vars[] = {
        "CLASSPATH", "LD_PRELOAD", "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES", "LD_AUDIT", "PATH", nullptr
    };
    for (int i = 0; vars[i]; i++) {
        const char* value = getenv(vars[i]);
        if (!value || !*value) continue;
        std::string entry = std::string(vars[i]) + "=" + value;
        if (is_suspicious(entry)) hits.push_back(entry.substr(0, 90));
    }

    pid_t zygote_pid = find_pid_by_cmd_fragment("zygote");
    if (zygote_pid > 0) {
        char env_path[64]{};
        snprintf(env_path, sizeof(env_path), "/proc/%d/environ", zygote_pid);
        for (const auto& entry : read_nul_file(env_path)) {
            if (is_suspicious(entry)) hits.push_back("zygote:" + entry.substr(0, 80));
        }

        char cmd_path[64]{};
        snprintf(cmd_path, sizeof(cmd_path), "/proc/%d/cmdline", zygote_pid);
        std::string cmd = fread_str(cmd_path);
        if (!cmd.empty() && is_suspicious(cmd)) hits.push_back("zygote_cmd:" + cmd.substr(0, 80));
    }

    if (!hits.empty()) {
        std::string d = "Injected environment traces:";
        for (size_t i = 0; i < hits.size() && i < 4; i++) d += " [" + hits[i] + "]";
        add("zygote_env", "Zygote/App Environment Injection", d);
    }
}

static void detectMaliciousHook() {
    const char* hook_libs[] = {
        "libdobby.so", "libshadowhook.so", "libsandhook.so", "libxposed_art.so",
        "liblsplant.so", "libsubstrate.so", "frida-gadget.so", "libfrida-gadget.so",
        "libepic.so", "libinlinehook.so", nullptr
    };
    for (int i = 0; hook_libs[i]; i++) {
        void* handle = dlopen(hook_libs[i], RTLD_NOLOAD | RTLD_NOW);
        if (handle) {
            dlclose(handle);
            add("hook_lib_loaded", "Hook Library Loaded", std::string("Loaded: ") + hook_libs[i]);
            return;
        }
    }

    std::ifstream maps("/proc/self/maps");
    if (maps) {
        std::string line;
        while (std::getline(maps, line)) {
            if (!(contains_ci(line, "dobby") || contains_ci(line, "shadowhook") ||
                  contains_ci(line, "sandhook") || contains_ci(line, "xposed") ||
                  contains_ci(line, "lsposed") || contains_ci(line, "substrate") ||
                  contains_ci(line, "frida") || contains_ci(line, "epic"))) {
                continue;
            }
            size_t sp = line.rfind(' ');
            std::string path = sp != std::string::npos ? line.substr(sp + 1) : line;
            if (path.find("/system/") == 0 || path.find("/apex/") == 0 || path.find("/vendor/") == 0) continue;
            add("hook_maps", "Hook Framework in Memory", path.substr(0, 90));
            return;
        }
    }

    const char* probe_names[] = {
        "open", "dlopen", "__system_property_get", "ptrace", "kill", "prctl", nullptr
    };
    for (int i = 0; probe_names[i]; i++) {
        void* sym = dlsym(RTLD_DEFAULT, probe_names[i]);
        if (!sym) continue;
        Dl_info info{};
        if (!dladdr(sym, &info) || !info.dli_fname) continue;
        std::string path = info.dli_fname;
        if (path.find("/apex/") == 0 || path.find("/system/") == 0 || path.find("/vendor/") == 0) continue;
        add("hook_origin", "Hooked Native API Source",
            std::string(probe_names[i]) + " resolved from " + path.substr(0, 90));
        return;
    }
}

static void detectKernelsuNextVariants() {
    
    
    const struct { int option; long arg2; const char* name; } probes[] = {
        { 0xDEAD,  0,       "prctl(0xDEAD,0)"       },
        { 0xDEAD,  0x1314,  "prctl(0xDEAD,0x1314)"  },
        { 0xBEEF,  0,       "prctl(0xBEEF,0)"        },
        { 0xCAFE,  0,       "prctl(0xCAFE,0)"        },
        
        { PR_SET_MM, 0xDEAD,   "prctl(PR_SET_MM,0xDEAD)"   },
        { PR_SET_MM, 0x114514, "prctl(PR_SET_MM,0x114514)"  },
    };
    for (auto& p : probes) {
        errno = 0;
        prctl(p.option, p.arg2, 0, 0, 0);
        if (errno != EINVAL && errno != EPERM && errno != ENOSYS) {
            add("ksu_next_prctl", "KernelSU Next (prctl variant)",
                std::string(p.name) + " errno=" + std::to_string(errno) + " (not EINVAL)");
            return;
        }
    }

    
    const pid_t magic_pids[] = { 0x1314, 0xDEAD, 0xBEEF, 0x114514 };
    for (auto& pid : magic_pids) {
        errno = 0;
        kill(pid, 0);
        if (errno == 0) {
            char buf[64];
            snprintf(buf, sizeof(buf), "kill(0x%x, 0) returned 0 — KSU Next hook", (unsigned)pid);
            add("ksu_next_kill", "KernelSU Next (kill magic)", buf);
            return;
        }
    }
}

static void detectKernelsuNextMaps() {
    std::ifstream maps("/proc/self/maps");
    if (!maps) return;
    std::string line;
    while (std::getline(maps, line)) {
        
        if (line.find("[ksu") != std::string::npos ||
            line.find("[ksunext") != std::string::npos ||
            line.find("ksu_") != std::string::npos) {
            add("ksu_maps", "KernelSU Next in maps", "KSU mapping: " + line.substr(0, 80));
            return;
        }
        
        if (line.find("susfs") != std::string::npos) {
            add("susfs_maps", "SUSFS in memory maps", line.substr(0, 80));
            return;
        }
    }
}

static void detectKernelsuKallsyms() {
    std::ifstream kallsyms("/proc/kallsyms");
    if (!kallsyms) return;
    std::string line;
    int count = 0;
    while (std::getline(kallsyms, line) && count < 50000) {
        count++;
        if (contains_ci(line, "ksu_") || contains_ci(line, "kernelsu") ||
            contains_ci(line, "ksunext") || contains_ci(line, "susfs")) {
            add("ksu_kallsyms", "KernelSU in /proc/kallsyms",
                "Kernel symbol: " + line.substr(0, 60));
            return;
        }
    }
}

static void detectPrimeKernel() {
    std::string ver = fread_str("/proc/version");
    
    if (contains_ci(ver, "PrimeKernel") || contains_ci(ver, "prime")) {
        add("prime_kernel", "PrimeKernel Detected",
            "Custom kernel with KernelSU Next: " + ver.substr(0, 80));
    }
    
    if (contains_ci(ver, "openela") || contains_ci(ver, "PixelKernel") ||
        contains_ci(ver, "sultan") || contains_ci(ver, "arter97")) {
        add("custom_kernel_ver", "Custom Kernel Build",
            "Non-OEM kernel: " + ver.substr(0, 80));
    }
}

static void detectKernelsuUidAnomaly() {
    uid_t uid = getuid();
    uid_t euid = geteuid();

    
    std::string status = fread_str("/proc/self/status");
    int uid_real = -1, euid_real = -1;
    size_t pos = status.find("Uid:");
    if (pos != std::string::npos) {
        sscanf(status.c_str() + pos + 4, "%d %d", &uid_real, &euid_real);
    }

    
    if (uid_real >= 0 && (uid_t)uid_real != uid) {
        char buf[80];
        snprintf(buf, sizeof(buf), "getuid()=%d but /proc/self/status Uid=%d — UID hook", uid, uid_real);
        add("uid_hook", "UID Syscall Hooked", buf);
    }

    
    if (uid == 0 || euid == 0) {
        add("uid_root_direct", "Running as Root",
            "getuid()/geteuid() returned 0");
    }
}

static void detectKernelsuStatusFields() {
    std::string status = fread_str("/proc/self/status");
    
    
    size_t pos = status.find("CapEff:");
    if (pos != std::string::npos) {
        std::string cap_str = status.substr(pos + 7);
        while (!cap_str.empty() && (cap_str[0] == ' ' || cap_str[0] == '	'))
            cap_str = cap_str.substr(1);
        
        unsigned long long caps = 0;
        sscanf(cap_str.c_str(), "%llx", &caps);
        
        
        if (caps > 0x0000000000000000ULL) {
            char buf[80];
            snprintf(buf, sizeof(buf), "CapEff=0x%llx (non-zero caps = elevated privileges)", caps);
            add("cap_elevated", "Elevated Linux Capabilities", buf);
        }
    }
}

static void detectKernelsuNetUnix() {
    std::ifstream net_unix("/proc/net/unix");
    if (!net_unix) return;
    std::string line;
    while (std::getline(net_unix, line)) {
        if (contains_ci(line, "ksu") || contains_ci(line, "ksunext") ||
            contains_ci(line, "magisk") || contains_ci(line, "zygisk")) {
            
            size_t last_space = line.rfind(' ');
            std::string sock_path = (last_space != std::string::npos)
                ? line.substr(last_space + 1) : line;
            add("ksu_net_unix", "Root Socket in /proc/net/unix",
                "Socket: " + sock_path.substr(0, 60));
            return;
        }
    }
}

static void detectInotify() {
    int ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ifd < 0) return;

    const char* paths[] = {
        "/data/adb",
        "/data/adb/ksu",
        "/data/adb/modules",
        nullptr
    };
    std::vector<std::string> found;
    for (int i = 0; paths[i]; i++) {
        int wd = inotify_add_watch(ifd, paths[i], IN_ACCESS);
        if (wd >= 0) {
            
            
            
            found.push_back(std::string(paths[i]) + " (inotify wd=" + std::to_string(wd) + ")");
            inotify_rm_watch(ifd, wd);
        }
    }
    close(ifd);

    if (!found.empty()) {
        std::string d = "inotify watch results:";
        for (auto& f : found) d += " " + f;
        add("inotify_adb", "Root Paths (inotify probe)", d);
    }
}

static void detectSyscallTiming() {
    const int SAMPLES = 50;
    long long times_dead[SAMPLES], times_safe[SAMPLES];

    struct timespec t1, t2;

    
    for (int i = 0; i < SAMPLES; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        prctl(0xDEAD, 0, 0, 0, 0);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        times_dead[i] = (t2.tv_sec - t1.tv_sec) * 1000000LL +
                        (t2.tv_nsec - t1.tv_nsec) / 1000LL;
    }

    
    for (int i = 0; i < SAMPLES; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        times_safe[i] = (t2.tv_sec - t1.tv_sec) * 1000000LL +
                        (t2.tv_nsec - t1.tv_nsec) / 1000LL;
    }

    
    auto median = [](long long* arr, int n) {
        for (int i = 0; i < n - 1; i++)
            for (int j = i + 1; j < n; j++)
                if (arr[i] > arr[j]) { long long t = arr[i]; arr[i] = arr[j]; arr[j] = t; }
        return arr[n / 2];
    };

    long long med_dead = median(times_dead, SAMPLES);
    long long med_safe = median(times_safe, SAMPLES);

    
    
    if (med_dead > med_safe * 3 && med_dead > 5) {
        char buf[120];
        snprintf(buf, sizeof(buf),
            "prctl(0xDEAD) median=%lldus vs prctl(safe) median=%lldus — %.1fx slower = hook",
            med_dead, med_safe, (double)med_dead / (double)(med_safe + 1));
        add("timing_hook", "Syscall Timing Hook Detected", buf);
    }
}

static void detectKallsymsDeep() {
    std::ifstream f("/proc/kallsyms");
    if (!f) return;
    std::string line;
    std::set<std::string> found;
    const char* ksu_syms[] = {
        "ksu_handle_", "ksu_allowlist", "ksu_uid_",
        "ksu_app_", "ksu_boot", "kernelsu_",
        "ksunext_", "susfs_", "sus_path",
        "ksu_sucompat", "su_compat",
        nullptr
    };
    int lines_read = 0;
    while (std::getline(f, line) && lines_read < 100000) {
        lines_read++;
        std::string lower = line;
        for (auto& c : lower) c = tolower(c);
        for (int i = 0; ksu_syms[i]; i++) {
            if (lower.find(ksu_syms[i]) != std::string::npos) {
                size_t last_space = line.rfind(' ');
                if (last_space != std::string::npos)
                    found.insert(line.substr(last_space + 1).substr(0, 40));
                break;
            }
        }
        if (found.size() >= 5) break;
    }
    if (!found.empty()) {
        std::string d = "KSU kernel symbols (" + std::to_string(found.size()) + "):";
        int shown = 0;
        for (auto& s : found) { if (shown++ >= 3) break; d += " [" + s + "]"; }
        add("kallsyms_deep", "KernelSU Kernel Symbols", d);
    }
}

static void detectUserCACerts() {
    
    
    const char* user_ca_dirs[] = {
        "/data/misc/user/0/cacerts-added",
        "/data/misc/keystore/user_0",
        nullptr
    };
    int cert_count = 0;
    for (int di = 0; user_ca_dirs[di]; di++) {
        DIR* d = opendir(user_ca_dirs[di]);
        if (!d) continue;
        struct dirent* e;
        while ((e = readdir(d)) != nullptr) {
            if (e->d_name[0] == '.') continue;
            cert_count++;
        }
        closedir(d);
    }
    if (cert_count > 0) {
        char buf[80];
        snprintf(buf, sizeof(buf),
            "%d user-installed CA certificate(s) — SSL proxy tool likely installed", cert_count);
        add("user_ca_certs", "User CA Certificates Installed", buf);
    }
}

static void detectProxyPorts() {
    const struct { int port; const char* name; } proxy_ports[] = {
        { 8080, "Burp Suite / mitmproxy" },
        { 8081, "mitmproxy web UI" },
        { 8888, "Charles Proxy / Fiddler" },
        { 9999, "Proxyman" },
        { 7777, "HTTPToolkit" },
        { 1337, "SSL Kill Switch proxy" },
        { 0, nullptr }
    };
    std::vector<std::string> found;
    for (int i = 0; proxy_ports[i].name; i++) {
        int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (sock < 0) continue;
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(proxy_ports[i].port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        struct timeval tv{0, 80000};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0)
            found.push_back(std::string(proxy_ports[i].name)
                + " (port " + std::to_string(proxy_ports[i].port) + ")");
        close(sock);
    }
    if (!found.empty()) {
        std::string d = "Proxy ports open:";
        for (auto& f : found) d += " [" + f + "]";
        add("proxy_ports", "SSL Proxy Port Detected", d);
    }
}

static void detectSystemProxy() {
    char http_proxy[256]{};
    char https_proxy[256]{};
    __system_property_get("http.proxy", http_proxy);
    __system_property_get("https.proxy", https_proxy);

    const char* proxy = strlen(http_proxy) > 0 ? http_proxy : https_proxy;
    if (strlen(proxy) > 0) {
        std::string p = proxy;
        
        if (p.find("127.0.0.1") != std::string::npos ||
            p.find("localhost") != std::string::npos ||
            p.find("10.0.") != std::string::npos) {
            add("sys_proxy", "System Proxy Configured",
                "http/https proxy set to: " + p + " — SSL interception possible");
        }
    }
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_juanma0511_rootdetector_detector_NativeChecks_runNativeChecks(JNIEnv* env, jobject) {
    g_results.clear();
    g_seen.clear();

    detectKernelsu();
    detectKernelsuKill();
    detectKernelsuJbd2();
    detectKernelsuNextVariants();
    detectKernelsuNextMaps();
    detectKernelsuKallsyms();
    detectPrimeKernel();
    detectKernelsuUidAnomaly();
    detectKernelsuStatusFields();
    detectKernelsuNetUnix();
    detectMagiskSocket();
    detectZygisk();
    detectPtrace();
    detectSuBinary();
    detectSulist();
    detectRootDaemonCmdline();
    detectRootUnixSockets();
    detectSuspiciousFiles();
    detectSuspiciousPersistProps();
    detectThirdPartyRom();
    detectKernelBuild();
    detectKernelBlacklist();
    detectApatch();
    detectCgroupSupport();
    detectMountAnomalies();
    detectResetprop();
    detectLspHook();
    detectFrida();
    detectNativeBridge();
    detectAvbVersion();
    detectEnvAnomalies();
    detectJniTableSource(env);
    detectBuildPropsNative();
    detectMountLoophole();
    detectHiddenProcessGroups();
    detectHwBreakpoints();
    detectAnonExec();
    detectEvilServices();
    detectPty();
    detectLibraryOrder();
    detectSoTampering();
    detectVirtualArch();
    detectFakeEnvironment();
    detectMagicMount();
    detectProc1MountDiff();
    detectMountConsistency();
    detectZygoteEnvironment();
    detectMaliciousHook();
    detectInotify();
    detectSyscallTiming();
    detectKallsymsDeep();
    detectUserCACerts();
    detectProxyPorts();
    detectSystemProxy();

    jclass sc = env->FindClass("java/lang/String");
    jobjectArray r = env->NewObjectArray((jsize)g_results.size(), sc, nullptr);
    for (size_t i = 0; i < g_results.size(); i++) {
        std::string e = g_results[i].name + "|" + g_results[i].desc;
        env->SetObjectArrayElement(r, (jsize)i, env->NewStringUTF(e.c_str()));
    }
    return r;
}
