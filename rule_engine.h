#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include <string>
#include <vector>
#include <chrono>
#include <unordered_map>
#include <deque>
#include <yaml-cpp/yaml.h>
#include "event.h"
#include <nlohmann/json.hpp>

struct Alert {
    std::string rule;
    std::string src_ip;
    std::string severity;
    std::string mitre;
    std::string action;
    int block_seconds;
    std::string ts_iso;

    nlohmann::json to_json() const {
        return nlohmann::json{
            {"rule", rule},
            {"src_ip", src_ip},
            {"severity", severity},
            {"mitre", mitre},
            {"action", action},
            {"block_seconds", block_seconds},
            {"ts_iso", ts_iso}
        };
    }
};

struct RuleDef {
    std::string name;
    std::string match_type;
    std::size_t threshold;
    std::chrono::seconds window;
    std::string severity;
    std::string mitre;
    std::string action;
    int block_seconds;
};

class RuleEngine {
public:
    explicit RuleEngine(const std::string& yaml_path);
    std::vector<Alert> process(const Event& e);
    void override_rules(int threshold, int window_seconds);
    std::size_t get_count(const std::string& match_type, const std::string& src_ip) const;
    std::size_t get_threshold(const std::string& match_type) const;

private:
    std::vector<RuleDef> rules_;
    std::unordered_map<std::string, std::unordered_map<std::string, std::deque<std::chrono::steady_clock::time_point>>> windows_;
};

#endif
