#include "rule_engine.h"
#include <arpa/inet.h>
#include <iostream>

RuleEngine::RuleEngine(const std::string& yaml_path) {
    YAML::Node config = YAML::LoadFile(yaml_path);
    for (const auto& node : config) {
        RuleDef r;
        r.name = node["name"].as<std::string>();
        r.match_type = node["match_type"].as<std::string>();
        r.threshold = node["threshold"].as<std::size_t>();
        r.window = std::chrono::seconds(node["window_seconds"].as<int>());
        r.severity = node["severity"].as<std::string>();
        r.mitre = node["mitre"].as<std::string>();
        r.action = node["action"].as<std::string>();
        r.block_seconds = node["block_seconds"].as<int>();
        rules_.push_back(r);
    }
}

void RuleEngine::override_rules(int threshold, int window_seconds) {
    for (auto& r : rules_) {
        if (threshold > 0) r.threshold = threshold;
        if (window_seconds > 0) r.window = std::chrono::seconds(window_seconds);
    }
}

static bool is_valid_ip(const std::string& ip) {
    struct in_addr addr;
    return inet_pton(AF_INET, ip.c_str(), &addr) == 1;
}

std::vector<Alert> RuleEngine::process(const Event& e) {
    std::vector<Alert> generated_alerts;
    if (!is_valid_ip(e.src_ip)) return generated_alerts;

    auto now = std::chrono::steady_clock::now();

    for (const auto& rule : rules_) {
        if (rule.match_type == e.type) {
            auto& ip_map = windows_[rule.name];
            auto& attempts = ip_map[e.src_ip];
            attempts.push_back(now);

            while (!attempts.empty() && now - attempts.front() > rule.window) {
                attempts.pop_front();
            }

            if (attempts.size() >= rule.threshold) {
                Alert a;
                a.rule = rule.name;
                a.src_ip = e.src_ip;
                a.severity = rule.severity;
                a.mitre = rule.mitre;
                a.action = rule.action;
                a.block_seconds = rule.block_seconds;
                a.ts_iso = e.ts_iso;
                generated_alerts.push_back(a);
                ip_map.erase(e.src_ip);
            }
        }
    }
    return generated_alerts;
}

std::size_t RuleEngine::get_count(const std::string& match_type, const std::string& src_ip) const {
    for (const auto& r : rules_) {
        if (r.match_type == match_type) {
            auto it1 = windows_.find(r.name);
            if (it1 != windows_.end()) {
                auto it2 = it1->second.find(src_ip);
                if (it2 != it1->second.end()) {
                    return it2->second.size();
                }
            }
        }
    }
    return 0;
}

std::size_t RuleEngine::get_threshold(const std::string& match_type) const {
    for (const auto& r : rules_) {
        if (r.match_type == match_type) return r.threshold;
    }
    return 5;
}
