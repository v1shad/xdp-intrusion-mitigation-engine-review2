#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <regex>
#include <fstream>
#include <csignal>
#include <unordered_set>
#include <map>
#include <mutex>
#include <optional>
#include <filesystem>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>

#include "event.h"
#include "storage.h"
#include "rule_engine.h"
#include "common.h"

using namespace std::chrono_literals;

static bool use_color = true;

std::optional<std::uint32_t> parse_ipv4(const std::string& text) {
    in_addr addr{};
    if (inet_pton(AF_INET, text.c_str(), &addr) != 1) return std::nullopt;
    return addr.s_addr;
}

std::string ip_to_string(std::uint32_t ip_net) {
    char buf[INET_ADDRSTRLEN]{};
    in_addr addr{.s_addr = ip_net};
    inet_ntop(AF_INET, &addr, buf, sizeof buf);
    return buf;
}

void add_iface_ips(std::unordered_set<std::uint32_t>& allow, const std::string& ifname) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) return;
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family == AF_INET && std::string(ifa->ifa_name) == ifname) {
            auto* sa = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
            allow.insert(sa->sin_addr.s_addr);
        }
    }
    freeifaddrs(ifaddr);
}

void add_gateway_ips(std::unordered_set<std::uint32_t>& allow) {
    std::ifstream in("/proc/net/route");
    std::string line;
    std::getline(in, line);
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string iface, dest, gw;
        if (iss >> iface >> dest >> gw) {
            if (dest == "00000000") {
                unsigned int gw_ip;
                if (std::sscanf(gw.c_str(), "%X", &gw_ip) == 1 && gw_ip != 0) {
                    allow.insert(gw_ip);
                }
            }
        }
    }
}

std::string sanitize_utf8(const std::string& input) {
    std::string out;
    out.reserve(std::min(input.size(), size_t(128)));
    for (size_t i = 0; i < input.size() && out.size() < 128; ) {
        unsigned char c = input[i];
        if (c < 0x80) {
            if (c < 0x20 || c == 0x7F) out += '?';
            else out += c;
            i++;
        } else if ((c & 0xE0) == 0xC0) {
            if (i + 1 < input.size() && (input[i+1] & 0xC0) == 0x80) {
                out += input.substr(i, 2); i += 2;
            } else { out += "\xEF\xBF\xBD"; i++; }
        } else if ((c & 0xF0) == 0xE0) {
            if (i + 2 < input.size() && (input[i+1] & 0xC0) == 0x80 && (input[i+2] & 0xC0) == 0x80) {
                out += input.substr(i, 3); i += 3;
            } else { out += "\xEF\xBF\xBD"; i++; }
        } else if ((c & 0xF8) == 0xF0) {
            if (i + 3 < input.size() && (input[i+1] & 0xC0) == 0x80 && (input[i+2] & 0xC0) == 0x80 && (input[i+3] & 0xC0) == 0x80) {
                out += input.substr(i, 4); i += 4;
            } else { out += "\xEF\xBF\xBD"; i++; }
        } else { out += "\xEF\xBF\xBD"; i++; }
    }
    return out;
}

std::string get_iso_time() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&ts.tv_sec));
    return std::string(buf);
}

void print_log(std::string tag, const std::string& msg, const std::string& color_code = "") {
    std::string reset = use_color ? "\x1b[0m" : "";
    std::string color = use_color ? color_code : "";
    while (tag.length() < 10) tag += " ";
    std::cout << get_iso_time() << " " << color << tag << reset << " " << msg << "\n";
}

void log_info(const std::string& msg) { print_log("[INFO]", msg); }
void log_warn(const std::string& msg) { print_log("[WARN]", msg, "\x1b[33m"); }

static std::atomic<bool> g_running{true};
extern "C" void on_signal(int) { g_running = false; }

using EventCallback = std::function<void(const Event&)>;

class SshDetector {
public:
    SshDetector(std::string path, EventCallback cb) : path_(std::move(path)), cb_(std::move(cb)) {}
    void run(std::stop_token st) {
        ino_t last_inode = 0;
        off_t last_size = 0;
        std::ifstream in;
        while (!st.stop_requested()) {
            struct stat st_buf;
            if (stat(path_.c_str(), &st_buf) != 0) {
                std::this_thread::sleep_for(1s);
                continue;
            }
            if (st_buf.st_ino != last_inode || st_buf.st_size < last_size || !in.is_open()) {
                if (in.is_open()) in.close();
                in.open(path_);
                if (!in) { std::this_thread::sleep_for(1s); continue; }
                if (st_buf.st_size < last_size || last_inode == 0) in.seekg(0, std::ios::end);
                last_inode = st_buf.st_ino;
            }
            std::string line;
            while (std::getline(in, line)) {
                handle_line(line);
                last_size = in.tellg();
            }
            last_size = st_buf.st_size;
            in.clear();
            std::this_thread::sleep_for(200ms);
        }
    }
private:
    void handle_line(const std::string& line) {
        static const std::regex re{R"(Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2)"};
        std::smatch m;
        if (!std::regex_search(line, m, re)) return;
        std::string user = sanitize_utf8(m[1].str());
        std::string ip_str = m[2].str();
        if (!parse_ipv4(ip_str)) return;
        Event e;
        e.ts_iso = get_iso_time();
        e.source = "ssh_log";
        e.type = "ssh_failed";
        e.src_ip = ip_str;
        e.user = user;
        e.severity = 3;
        if (cb_) cb_(e);
    }
    std::string path_;
    EventCallback cb_;
};

class XdpEngine {
public:
    XdpEngine(const std::string& obj_path, const std::string& iface) {
        unsigned int ifindex = if_nametoindex(iface.c_str());
        if (ifindex == 0) throw std::runtime_error("invalid interface");
        obj_ = bpf_object__open_file(obj_path.c_str(), nullptr);
        if (!obj_) throw std::runtime_error("failed to open bpf object");
        if (bpf_object__load(obj_)) throw std::runtime_error("failed to load bpf object");
        prog_ = bpf_object__find_program_by_name(obj_, "xdp_firewall");
        if (!prog_) throw std::runtime_error("failed to find xdp_firewall");
        link_ = bpf_program__attach_xdp(prog_, ifindex);
        if (!link_) throw std::runtime_error("failed to attach xdp");
    }
    ~XdpEngine() {
        if (link_) bpf_link__destroy(link_);
        if (obj_) bpf_object__close(obj_);
    }
    int allowed_fd() const { return bpf_map__fd(bpf_object__find_map_by_name(obj_, "allowed_ips")); }
    int blocked_fd() const { return bpf_map__fd(bpf_object__find_map_by_name(obj_, "blocked_ips")); }
    int stats_fd() const { return bpf_map__fd(bpf_object__find_map_by_name(obj_, "ip_stats")); }
    int events_fd() const { return bpf_map__fd(bpf_object__find_map_by_name(obj_, "events")); }
private:
    struct bpf_object* obj_{nullptr};
    struct bpf_program* prog_{nullptr};
    struct bpf_link* link_{nullptr};
};

class BlockList {
public:
    BlockList(int allow_fd, int block_fd, int stats_fd, const std::unordered_set<std::uint32_t>& allow)
        : allow_fd_(allow_fd), block_fd_(block_fd), stats_fd_(stats_fd) {
        for (auto ip : allow) allow_ip(ip);
    }
    void allow_ip(std::uint32_t ip) {
        std::uint8_t val = 1;
        bpf_map_update_elem(allow_fd_, &ip, &val, BPF_ANY);
        print_log("[ALLOWED]", ip_to_string(ip));
    }
    void unallow_ip(std::uint32_t ip) {
        bpf_map_delete_elem(allow_fd_, &ip);
        log_info("removed from allowlist: " + ip_to_string(ip));
    }
    bool block(std::uint32_t ip, std::chrono::seconds ttl, bool detect_only, bool manual = false) {
        if (detect_only) return false;
        std::uint8_t allowed;
        if (bpf_map_lookup_elem(allow_fd_, &ip, &allowed) == 0) return false;
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        
        struct block_record rec;
        rec.hits = 0;
        rec.expires_at_ns = (static_cast<uint64_t>(ts.tv_sec) + ttl.count()) * 1000000000ULL + ts.tv_nsec;

        if (bpf_map_update_elem(block_fd_, &ip, &rec, manual ? BPF_ANY : BPF_NOEXIST) == 0) {
            std::string reason = manual ? "manual" : "automatic";
            print_log("[BLOCKED]", ip_to_string(ip) + " ttl=" + std::to_string(ttl.count()) + "s " + reason, "\x1b[31m");
            return true;
        }
        return false;
    }
    void unblock(std::uint32_t ip) {
        if (bpf_map_delete_elem(block_fd_, &ip) == 0) {
            print_log("[EXPIRED]", ip_to_string(ip) + " (manual unblock)");
        }
    }
    void cleanup_expired() {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        std::uint64_t now_ns = static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;
        std::uint32_t key = 0, next_key;
        while (bpf_map_get_next_key(block_fd_, &key, &next_key) == 0) {
            struct block_record rec;
            if (bpf_map_lookup_elem(block_fd_, &next_key, &rec) == 0 && rec.expires_at_ns > 0 && now_ns >= rec.expires_at_ns) {
                bpf_map_delete_elem(block_fd_, &next_key);
                bpf_map_delete_elem(stats_fd_, &next_key);
                print_log("[EXPIRED]", ip_to_string(next_key) + " (ttl elapsed)");
            }
            key = next_key;
        }
    }
    void print_blocked() const {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        std::uint64_t now_ns = static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;
        std::uint32_t key = 0, next_key;
        int count = 0;
        while (bpf_map_get_next_key(block_fd_, &key, &next_key) == 0) {
            struct block_record rec;
            if (bpf_map_lookup_elem(block_fd_, &next_key, &rec) == 0) {
                if (rec.expires_at_ns == 0) {
                    log_info(ip_to_string(next_key) + " expires in NEVER");
                } else {
                    int left = rec.expires_at_ns > now_ns ? static_cast<int>((rec.expires_at_ns - now_ns) / 1000000000ULL) : 0;
                    log_info(ip_to_string(next_key) + " expires in " + std::to_string(left) + "s");
                }
                count++;
            }
            key = next_key;
        }
        if (count == 0) log_info("blocklist is empty");
    }
    void print_stats() const {
        std::uint32_t key = 0, passed = 0;
        bpf_map_lookup_elem(stats_fd_, &key, &passed);
        std::uint32_t dropped = 0, next_key = 0;
        key = 0;
        while (bpf_map_get_next_key(stats_fd_, &key, &next_key) == 0) {
            if (next_key == 0) { key = next_key; continue; }
            std::uint32_t val = 0;
            if (bpf_map_lookup_elem(stats_fd_, &next_key, &val) == 0) dropped += val;
            key = next_key;
        }
        log_info("Packets passed: " + std::to_string(passed) + ", dropped: " + std::to_string(dropped));
    }
private:
    int allow_fd_, block_fd_, stats_fd_;
};

struct DropState {
    std::chrono::steady_clock::time_point last_print;
    uint64_t last_count = 0;
};
static std::map<std::string, DropState> g_drop_states;
static std::mutex g_drop_mu;

static int handle_event(void* /*ctx*/, void *data, size_t size) {
    if (size < sizeof(struct drop_event)) return 0;
    auto* ev = static_cast<struct drop_event*>(data);
    std::string ip = ip_to_string(ev->src_ip);
    
    std::lock_guard<std::mutex> lock(g_drop_mu);
    auto now = std::chrono::steady_clock::now();
    auto& state = g_drop_states[ip];
    uint64_t current_drops = ev->total_hits;
    if (current_drops > state.last_count) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - state.last_print).count();
        if (elapsed >= 2) {
            uint64_t diff = current_drops - state.last_count;
            uint64_t rate = elapsed > 0 ? diff / elapsed : diff;
            print_log("[DROPPING]", ip + " total=" + std::to_string(current_drops) + " rate=" + std::to_string(rate) + "/s");
            state.last_print = now;
            state.last_count = current_drops;
        }
    }
    return 0;
}

bool check_process(const std::string& name) {
    DIR* dir = opendir("/proc");
    if (!dir) return false;
    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (!isdigit(ent->d_name[0])) continue;
        std::string path = std::string("/proc/") + ent->d_name + "/comm";
        std::ifstream f(path);
        std::string comm;
        if (f >> comm && comm == name) {
            closedir(dir);
            return true;
        }
    }
    closedir(dir);
    return false;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: sudo " << argv[0] << " <iface> [--allow IP]... [--ttl S] [--threshold N] [--window S] [--dry-run] [--log PATH]\n";
        return 1;
    }
    std::string iface = argv[1];
    std::unordered_set<std::uint32_t> allow{*parse_ipv4("127.0.0.1")};
    add_iface_ips(allow, iface);
    add_gateway_ips(allow);

    int ttl = 60;
    int threshold = 5;
    int window = 60;
    bool dry_run = false;
    std::string logfile;
    if (access("/var/log/secure", R_OK) == 0) logfile = "/var/log/secure";
    else logfile = "/var/log/auth.log";
    
    use_color = isatty(STDOUT_FILENO);

    for (int i = 2; i < argc; i++) {
        std::string_view arg{argv[i]};
        if (arg == "--allow" && i + 1 < argc) {
            if (auto ip = parse_ipv4(argv[++i])) allow.insert(*ip);
        } else if (arg == "--dry-run") {
            dry_run = true;
        } else if (arg == "--ttl" && i + 1 < argc) {
            ttl = std::stoi(argv[++i]);
        } else if (arg == "--threshold" && i + 1 < argc) {
            threshold = std::stoi(argv[++i]);
        } else if (arg == "--window" && i + 1 < argc) {
            window = std::stoi(argv[++i]);
        } else if (arg == "--log" && i + 1 < argc) {
            logfile = argv[++i];
        }
    }
    ttl = std::min(std::max(ttl, 1), 600);

    bool all_pass = true;
    auto check_fail = [&](const std::string& msg) {
        std::cerr << "FAIL: " << msg << "\n";
        all_pass = false;
    };

    if (getuid() != 0) check_fail("Not running as root. Fix: use sudo");
    else std::cout << "PASS: Running as root\n";

    struct utsname buffer;
    if (uname(&buffer) == 0) std::cout << "PASS: Kernel " << buffer.release << "\n";
    else check_fail("uname failed");
    
    if (access("/sys/kernel/btf/vmlinux", R_OK) == 0) std::cout << "PASS: BTF file found\n";
    else check_fail("BTF file missing. Fix: install kernel headers");

    unsigned int ifindex = if_nametoindex(iface.c_str());
    if (ifindex > 0) std::cout << "PASS: Interface " << iface << " exists\n";
    else check_fail("Interface " + iface + " not found");

    if (check_process("sshd")) std::cout << "PASS: sshd is running\n";
    else check_fail("sshd not running. Fix: sudo systemctl start sshd");

    if (check_process("rsyslogd")) std::cout << "PASS: rsyslogd is running\n";
    else std::cout << "WARN: rsyslogd not running (journal-only setups do not populate /var/log by default)\n";

    if (access(logfile.c_str(), R_OK) == 0) std::cout << "PASS: " << logfile << " readable\n";
    else check_fail(logfile + " not readable. Fix: ensure rsyslog is logging auth authpriv to it");

    auto check_ssh_conf = [&](const std::string& p) {
        std::ifstream f(p);
        std::string line;
        while (std::getline(f, line)) {
            if (line.find("PasswordAuthentication") != std::string::npos && line[0] != '#') return line;
        }
        return std::string("");
    };
    std::string pwd_auth = check_ssh_conf("/etc/ssh/sshd_config");
    if (pwd_auth.empty()) {
        for (const auto& entry : std::filesystem::directory_iterator("/etc/ssh/sshd_config.d")) {
            pwd_auth = check_ssh_conf(entry.path());
            if (!pwd_auth.empty()) break;
        }
    }
    if (pwd_auth.find("yes") != std::string::npos) std::cout << "PASS: " << pwd_auth << "\n";
    else std::cout << "WARN: PasswordAuth not explicitly 'yes'. Failed password lines will not appear in logs if disabled!\n";

    if (ifindex > 0) {
        __u32 prog_id = 0;
        if (bpf_xdp_query_id(ifindex, 0, &prog_id) == 0 && prog_id > 0) {
            check_fail("XDP program already attached (ID: " + std::to_string(prog_id) + "). Fix: sudo ip link set dev " + iface + " xdp off");
        } else {
            std::cout << "PASS: No existing XDP program attached to " << iface << "\n";
        }
    }

    if (!all_pass) return 1;

    std::cout << "=== ENGINE STARTUP BANNER ===\n";
    std::cout << "Interface: " << iface << "\n";
    std::cout << "XDP Mode:  Auto\n";
    std::cout << "Log Path:  " << logfile << "\n";
    std::cout << "TTL:       " << ttl << "s\n";
    std::cout << "Threshold: " << threshold << "\n";
    std::cout << "Window:    " << window << "s\n";
    std::cout << "Allowed:   ";
    for (auto ip : allow) std::cout << ip_to_string(ip) << " ";
    std::cout << "\n=============================\n";
    
    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    try {
        Storage storage{"engine.db"};
        RuleEngine rule_engine{"rules.yaml"};
        if (threshold > 0 || window > 0) rule_engine.override_rules(threshold, window);

        std::string bpf_obj = "xdp_prog.bpf.o";
        char proc_exe[256];
        ssize_t len = readlink("/proc/self/exe", proc_exe, sizeof(proc_exe)-1);
        if (len != -1) {
            proc_exe[len] = '\0';
            std::string exe_path(proc_exe);
            size_t last_slash = exe_path.find_last_of('/');
            if (last_slash != std::string::npos) {
                std::string bpf_path = exe_path.substr(0, last_slash) + "/xdp_prog.bpf.o";
                if (access(bpf_path.c_str(), R_OK) == 0) bpf_obj = bpf_path;
            }
        }

        XdpEngine engine{bpf_obj, iface};
        BlockList blocklist{engine.allowed_fd(), engine.blocked_fd(), engine.stats_fd(), allow};
        
        std::jthread cleanup_poller{[&](std::stop_token st) {
            while (!st.stop_requested()) {
                blocklist.cleanup_expired();
                std::this_thread::sleep_for(1s);
            }
        }};

        EventCallback on_event = [&](const Event& e) {
            storage.insert_event(e);
            auto alerts = rule_engine.process(e);
            
            int n = rule_engine.get_count("ssh_failed", e.src_ip);
            int thresh = rule_engine.get_threshold("ssh_failed");
            std::string auth_col = (n >= thresh - 1) ? "\x1b[33m" : "";
            if (e.source == "ssh_log") print_log("[AUTH]", "SSH failure from " + e.src_ip + " (" + std::to_string(n) + "/" + std::to_string(thresh) + ")", auth_col);
            
            for (const auto& a : alerts) {
                if (dry_run) {
                    print_log("[DETECTED]", a.src_ip + " crossed the threshold (would block)", "\x1b[34m");
                    ActionRecord act{a.ts_iso, a.src_ip, "detected", a.rule};
                    storage.insert_action(act);
                } else {
                    if (auto ip = parse_ipv4(a.src_ip)) {
                        if (blocklist.block(*ip, std::chrono::seconds(ttl), false, false)) {
                            ActionRecord act{a.ts_iso, a.src_ip, "block", a.rule};
                            storage.insert_action(act);
                        }
                    }
                }
            }
        };

        SshDetector detector{logfile, on_event};
        std::jthread watcher{[&detector](std::stop_token st) {
            try { detector.run(st); } catch (const std::exception& e) { log_warn(std::string{"tailer: "} + e.what()); }
        }};

        struct ring_buffer* rb = ring_buffer__new(engine.events_fd(), handle_event, nullptr, nullptr);
        if (!rb) throw std::runtime_error("failed to create ring buffer");
        std::jthread rb_poller{[&rb](std::stop_token st) {
            try { while (!st.stop_requested()) ring_buffer__poll(rb, 100); }
            catch (const std::exception& e) { log_warn(std::string{"ringbuf: "} + e.what()); }
        }};

        std::string line;
        while (g_running && std::getline(std::cin, line)) {
            std::istringstream iss{line};
            std::string cmd, arg;
            iss >> cmd >> arg;
            if (cmd == "quit") break;
            else if (cmd == "list")  blocklist.print_blocked();
            else if (cmd == "stats") blocklist.print_stats();
            else if (cmd == "alerts") storage.print_last_alerts(10);
            else if (cmd == "block" || cmd == "unblock" || cmd == "allow" || cmd == "unallow") {
                if (auto ip = parse_ipv4(arg)) {
                    if (cmd == "block") blocklist.block(*ip, std::chrono::seconds(ttl), false, true);
                    else if (cmd == "unblock") blocklist.unblock(*ip);
                    else if (cmd == "allow") blocklist.allow_ip(*ip);
                    else if (cmd == "unallow") blocklist.unallow_ip(*ip);
                } else log_warn("invalid IPv4 address");
            } else if (!cmd.empty()) log_warn("unknown command");
        }
        log_info("shutting down, detaching XDP");
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
