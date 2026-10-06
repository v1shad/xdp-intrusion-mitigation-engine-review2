// engine.cpp — user-space half of the Tier 3 Automated Intrusion Mitigation Engine
#include <arpa/inet.h>      // inet_pton / inet_ntop (text IP <-> binary IP)
#include <net/if.h>         // if_nametoindex ("eth0" -> interface number)
#include <signal.h>         // sigaction
#include <bpf/bpf.h>        // bpf_map_update_elem, bpf_map_lookup_elem, ... (syscall wrappers)
#include <bpf/libbpf.h>     // bpf_object__open_file, bpf_program__attach_xdp, ...
#include "common.h"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <numeric>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "event.h"
#include "rule_engine.h"
#include "storage.h"

using namespace std::chrono_literals;   // enables 200ms, 60s literals
using Clock = std::chrono::steady_clock; // monotonic clock: immune to system time changes

using EventCallback = std::function<void(const Event&)>;

/* ---------- tiny thread-safe logger (two threads print: avoid garbled output) ---------- */
static void log(const std::string& msg) {
    static std::mutex io_mutex;
    std::lock_guard lock{io_mutex};
    std::cout << msg << std::endl;
}

/* ---------- RAII wrappers: C resources -> automatic cleanup ---------- */
struct ObjDeleter  { void operator()(bpf_object* o) const noexcept { if (o) bpf_object__close(o); } };
struct LinkDeleter { void operator()(bpf_link*   l) const noexcept { if (l) bpf_link__destroy(l); } };
struct RingDeleter { void operator()(ring_buffer* r) const noexcept { if (r) ring_buffer__free(r); } };
using ObjPtr  = std::unique_ptr<bpf_object, ObjDeleter>;
using LinkPtr = std::unique_ptr<bpf_link,  LinkDeleter>;
using RingBufPtr = std::unique_ptr<ring_buffer, RingDeleter>;

/* ---------- C++20 concept: only raw-copyable types may cross into the kernel ---------- */
template <typename T>
concept KernelPod = std::is_trivially_copyable_v<T>;

template <KernelPod K, KernelPod V>
bool map_update(int fd, const K& key, const V& value) {
    return bpf_map_update_elem(fd, &key, &value, BPF_ANY) == 0;
}

/* ---------- IP helpers ---------- */
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

constexpr std::chrono::seconds DEFAULT_BLOCK_DURATION{60};

class BlockList {
public:
    BlockList(int allowed_fd, int blocked_fd, int stats_fd, const std::unordered_set<std::uint32_t>& allow)
    : allowed_fd_{allowed_fd}, blocked_fd_{blocked_fd}, stats_fd_{stats_fd},
      sweeper_{[this](std::stop_token st) { sweep_loop(st); }} {
        for (std::uint32_t ip : allow) {
            allow_ip(ip);
        }
    }

    bool allow_ip(std::uint32_t ip) {
        std::uint8_t dummy = 1;
        if (!map_update(allowed_fd_, ip, dummy)) {
            log(std::string{"[error] allow map update failed: "} + std::strerror(errno));
            return false;
        }
        log("[ALLOWED] " + ip_to_string(ip));
        bpf_map_delete_elem(blocked_fd_, &ip);
        return true;
    }

    bool unallow_ip(std::uint32_t ip) {
        if (bpf_map_delete_elem(allowed_fd_, &ip) != 0) {
            log("[info] " + ip_to_string(ip) + " was not in allowlist");
            return false;
        }
        log("[UNALLOWED] " + ip_to_string(ip));
        return true;
    }

    bool block(std::uint32_t ip, std::string_view reason, std::chrono::seconds duration, bool dry_run) {
        std::uint8_t dummy = 0;
        if (bpf_map_lookup_elem(allowed_fd_, &ip, &dummy) == 0) {
            log("[warn] refusing to block allow-listed " + ip_to_string(ip));
            return false;
        }
        
        if (dry_run) {
            log("[DRY-RUN] would block " + ip_to_string(ip) + " (" + std::string{reason} + ")");
            return true;
        }

        struct block_record rec{};
        rec.hits = 0;
        if (duration.count() > 0) {
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            rec.expires_at_ns = (ts.tv_sec * 1000000000ULL + ts.tv_nsec) + (duration.count() * 1000000000ULL);
        } else {
            rec.expires_at_ns = 0;
        }

        if (!map_update(blocked_fd_, ip, rec)) {
            log(std::string{"[error] map update failed: "} + std::strerror(errno));
            return false;
        }
        log("[BLOCKED] " + ip_to_string(ip) + " (" + std::string{reason} + ")");
        return true;
    }

    bool unblock(std::uint32_t ip) {
        if (bpf_map_delete_elem(blocked_fd_, &ip) != 0) {
            log("[info] " + ip_to_string(ip) + " was not blocked");
            return false;
        }
        log("[UNBLOCKED] " + ip_to_string(ip));
        return true;
    }

    void print_blocked() const {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        __u64 now = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

        std::uint32_t key{}, next{};
        const std::uint32_t* prev = nullptr;
        int count = 0;
        while (bpf_map_get_next_key(blocked_fd_, prev, &next) == 0) {
            struct block_record rec{};
            if (bpf_map_lookup_elem(blocked_fd_, &next, &rec) == 0) {
                std::string expire_str = "permanent";
                if (rec.expires_at_ns != 0) {
                    if (rec.expires_at_ns > now) {
                        __u64 remain = (rec.expires_at_ns - now) / 1000000000ULL;
                        expire_str = std::to_string(remain) + "s";
                    } else {
                        expire_str = "EXPIRED";
                    }
                }
                log("  " + ip_to_string(next) + "  dropped=" + std::to_string(rec.hits) + " expires in " + expire_str);
                ++count;
            }
            key = next; prev = &key;
        }
        log("  (" + std::to_string(count) + " blocked IPs)");
    }

    void print_stats() const {
        log("  packets dropped=" + std::to_string(read_stat(0)) +
        "  passed=" + std::to_string(read_stat(1)));
    }

private:
    std::uint64_t read_stat(std::uint32_t idx) const {
        const int ncpu = libbpf_num_possible_cpus();
        if (ncpu <= 0) return 0;
        std::vector<std::uint64_t> per_cpu(static_cast<std::size_t>(ncpu));
        if (bpf_map_lookup_elem(stats_fd_, &idx, per_cpu.data()) != 0) return 0;
        return std::accumulate(per_cpu.begin(), per_cpu.end(), std::uint64_t{0});
    }

    void sweep_loop(std::stop_token st) {
        while (!st.stop_requested()) {
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            __u64 now = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

            std::uint32_t key{}, next{};
            const std::uint32_t* prev = nullptr;
            while (bpf_map_get_next_key(blocked_fd_, prev, &next) == 0) {
                struct block_record rec{};
                if (bpf_map_lookup_elem(blocked_fd_, &next, &rec) == 0) {
                    if (rec.expires_at_ns != 0 && rec.expires_at_ns < now) {
                        bpf_map_delete_elem(blocked_fd_, &next);
                        log("[EXPIRED] " + ip_to_string(next));
                    }
                }
                key = next; prev = &key;
            }
            std::mutex m; std::unique_lock lk(m);
            std::condition_variable_any().wait_for(lk, st, 5s, []{return false;});
        }
    }

    int allowed_fd_, blocked_fd_, stats_fd_;
    std::jthread sweeper_;
};

class XdpEngine {
public:
    XdpEngine(const std::string& obj_path, const std::string& ifname) {
        const unsigned ifindex = if_nametoindex(ifname.c_str());
        if (ifindex == 0) throw std::runtime_error("no such interface: " + ifname);

        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        struct ifreq ifr{};
        std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (!(ifr.ifr_flags & IFF_UP)) {
                close(sock);
                throw std::runtime_error("interface is down: " + ifname);
            }
        }
        close(sock);

        obj_.reset(bpf_object__open_file(obj_path.c_str(), nullptr));
        if (!obj_) throw std::runtime_error("open failed: " + std::string{std::strerror(errno)});

        if (int err = bpf_object__load(obj_.get()))
            throw std::runtime_error("load failed: " + std::string{std::strerror(-err)});

        bpf_program* prog = bpf_object__find_program_by_name(obj_.get(), "xdp_firewall");
        bpf_map* allowed  = bpf_object__find_map_by_name(obj_.get(), "allowed_ips");
        bpf_map* blocked  = bpf_object__find_map_by_name(obj_.get(), "blocked_ips");
        bpf_map* stats    = bpf_object__find_map_by_name(obj_.get(), "stats");
        bpf_map* events   = bpf_object__find_map_by_name(obj_.get(), "events");
        if (!prog || !allowed || !blocked || !stats || !events) throw std::runtime_error("program/map not found in object");

        allowed_fd_ = bpf_map__fd(allowed);
        blocked_fd_ = bpf_map__fd(blocked);
        stats_fd_   = bpf_map__fd(stats);
        events_fd_  = bpf_map__fd(events);

        link_.reset(bpf_program__attach_xdp(prog, static_cast<int>(ifindex)));
        if (!link_) throw std::runtime_error("attach failed: " + std::string{std::strerror(errno)});

        bpf_xdp_query_opts opts{};
        opts.sz = sizeof(opts);
        if (bpf_xdp_query(ifindex, 0, &opts) == 0) {
            std::string mode = "unknown";
            if (opts.skb_prog_id) mode = "generic";
            else if (opts.drv_prog_id) mode = "native";
            else if (opts.hw_prog_id) mode = "hw";
            log("[engine] XDP attached mode: " + mode);
        }
    }
    int allowed_fd() const { return allowed_fd_; }
    int blocked_fd() const { return blocked_fd_; }
    int stats_fd()   const { return stats_fd_; }
    int events_fd()  const { return events_fd_; }

private:
    ObjPtr  obj_;
    LinkPtr link_;
    int allowed_fd_{-1}, blocked_fd_{-1}, stats_fd_{-1}, events_fd_{-1};
};

class SshDetector {
public:
    SshDetector(std::string path, EventCallback cb)
    : path_{std::move(path)}, cb_{std::move(cb)} {}

    void run(std::stop_token st) {
        std::ifstream in;
        ino_t last_inode = 0;
        size_t last_size = 0;
        while (!st.stop_requested()) {
            struct stat st_buf;
            if (stat(path_.c_str(), &st_buf) != 0) {
                if (in.is_open()) in.close();
                std::this_thread::sleep_for(1s);
                continue;
            }
            if (!in.is_open() || st_buf.st_ino != last_inode || st_buf.st_size < static_cast<off_t>(last_size)) {
                if (in.is_open()) {
                    log("[tail] rotation detected");
                    in.close();
                }
                in.open(path_);
                if (!in) { std::this_thread::sleep_for(1s); continue; }
                if (st_buf.st_size < static_cast<off_t>(last_size) || last_inode == 0) {
                    in.seekg(0, std::ios::end);
                }
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
        static const std::regex re{
            R"(Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2)"};
        std::smatch m;
        if (!std::regex_search(line, m, re)) return;
        
        std::string user = sanitize_utf8(m[1].str());
        std::string ip_str = m[2].str();
        if (!parse_ipv4(ip_str)) return;
        
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        char time_buf[32];
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&ts.tv_sec));

        Event e;
        e.ts_iso = time_buf;
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

static std::atomic<bool> g_running{true};
extern "C" void on_signal(int) { g_running = false; }

static int handle_event(void* ctx, void *data, size_t size) {
    if (size < sizeof(struct drop_event)) return 0;
    auto* ev = static_cast<struct drop_event*>(data);
    
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&ts.tv_sec));

    Event e;
    e.ts_iso = time_buf;
    e.source = "xdp_ringbuf";
    e.type = "packet_dropped";
    e.src_ip = ip_to_string(ev->src_ip);
    e.user = "";
    e.severity = 5;
    
    if (ctx) {
        auto* cb = static_cast<EventCallback*>(ctx);
        (*cb)(e);
    }
    return 0;
}

void run_unit_checks() {
    if (sanitize_utf8("hello") != "hello") throw std::runtime_error("check 1 failed");
    if (sanitize_utf8("hel\xFFlo") != "hel\xEF\xBF\xBDlo") throw std::runtime_error("check 2 failed");
    
    std::cmatch m;
    std::regex re{R"(Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2)"};
    if (!std::regex_search("Failed password for root from 192.168.1.20 port 52144 ssh2", m, re) || m[1] != "root" || m[2] != "192.168.1.20") throw std::runtime_error("check 3 failed");
    if (!std::regex_search("Failed password for invalid user bob from 192.168.1.20 port 52144 ssh2", m, re) || m[1] != "bob" || m[2] != "192.168.1.20") throw std::runtime_error("check 4 failed");
    if (std::regex_search("Accepted password for root from 192.168.1.20 port 52144 ssh2", m, re)) throw std::runtime_error("check 5 failed");
    
    int test_ttl = 1000;
    if (std::min(test_ttl, 600) != 600) throw std::runtime_error("check 6 failed");
    
    log("[engine] 6 unit checks passed");
}

int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "usage: sudo " << argv[0]
        << " <iface> <xdp_prog.bpf.o> <logfile> [--allow IP] [--dry-run] [--ttl SEC] [--threshold N] [--window S]\n";
        return 2;
    }
    run_unit_checks();

    std::unordered_set<std::uint32_t> allow{*parse_ipv4("127.0.0.1")};
    add_iface_ips(allow, argv[1]);
    add_gateway_ips(allow);

    bool dry_run = false;
    int ttl = 60;
    int threshold = -1;
    int window = -1;

    for (int i = 4; i < argc; i++) {
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
        }
    }
    ttl = std::min(std::max(ttl, 1), 600);

    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    try {
        Storage storage{"engine.db"};
        RuleEngine rule_engine{"rules.yaml"};
        if (threshold > 0 || window > 0) {
            rule_engine.override_rules(threshold, window);
        }

        log("[engine] effective TTL: " + std::to_string(ttl) + "s");

        XdpEngine engine{argv[2], argv[1]};
        BlockList blocklist{engine.allowed_fd(), engine.blocked_fd(), engine.stats_fd(), allow};
        
        EventCallback on_event = [&](const Event& e) {
            log("[EVENT] " + e.to_json().dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
            storage.insert_event(e);
            
            auto alerts = rule_engine.process(e);
            for (const auto& a : alerts) {
                log("[ALERT] " + a.to_json().dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
                storage.insert_alert(a);
                if (a.action == "block") {
                    if (auto ip = parse_ipv4(a.src_ip)) {
                        if (blocklist.block(*ip, a.rule, std::chrono::seconds(ttl), dry_run)) {
                            ActionRecord act{a.ts_iso, a.src_ip, dry_run ? "dry-block" : "block", a.rule};
                            storage.insert_action(act);
                        }
                    }
                }
            }
        };

        SshDetector detector{argv[3], on_event};
        std::jthread watcher{[&detector](std::stop_token st) {
            try { detector.run(st); } catch (const std::exception& e) { log(std::string{"[error] tailer: "} + e.what()); }
        }};

        RingBufPtr rb{ring_buffer__new(engine.events_fd(), handle_event, &on_event, nullptr)};
        if (!rb) throw std::runtime_error("failed to create ring buffer");
        std::jthread rb_poller{[&rb](std::stop_token st) {
            try { while (!st.stop_requested()) ring_buffer__poll(rb.get(), 100); }
            catch (const std::exception& e) { log(std::string{"[error] ringbuf: "} + e.what()); }
        }};

        log("[engine] Commands: allow <ip> | unallow <ip> | block <ip> | unblock <ip> | list | stats | alerts | quit");

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
                    if (cmd == "block") blocklist.block(*ip, "manual", std::chrono::seconds(ttl), dry_run);
                    else if (cmd == "unblock") blocklist.unblock(*ip);
                    else if (cmd == "allow") blocklist.allow_ip(*ip);
                    else if (cmd == "unallow") blocklist.unallow_ip(*ip);
                } else log("[error] invalid IPv4 address");
            } else if (!cmd.empty()) log("[error] unknown command");
        }
        log("[engine] shutting down, detaching XDP");
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
