#ifndef LOADER_H
#define LOADER_H
#include <fstream>

#include "json.hpp"
#include "Logger.hpp"


class Manager {
public:
    static nlohmann::json createJsonConfig(std::string type, std::string method, std::string password, std::string host, uint16_t port) {
        return {
            { "log", {
                { "level", "info" },
                { "output", "stderr" }
            }},
            { "inbounds", {{
                { "type", "mixed" },
                { "listen", "127.0.0.1" },
                { "listen_port", 2080 },
                { "tag", "mixed-in" }
                }}},
            { "outbounds", {{
                { "type", type },
                { "server", host },
                { "server_port", port },
                { "method", method },
                { "password", password },
            }}}
        };
    }

    static nlohmann::json createJsonConfigUsername(std::string type, std::string username, std::string password, std::string host, uint16_t port) {
        return {
            { "log", {
                { "level", "info" },
                { "output", "stderr" }
            }},
            { "inbounds", {{
                { "type", "mixed" },
                { "listen", "127.0.0.1" },
                { "listen_port", 2080 },
                { "tag", "mixed-in" }
            }}},
            { "outbounds", {{
                { "type", type },
                { "server", host },
                { "server_port", port },
                { "username", username },
                { "password", password },
            }}}
        };
    }

    static nlohmann::json createJsonConfigVless(
        const std::string& uuid,
        const std::string& host,
        uint16_t port,
        const std::string& flow,
        const std::string& network,
        const nlohmann::json& tls,
        const std::string& packet_encoding,
        const nlohmann::json& multiplex,
        const nlohmann::json& transport
        ) {
        return {
            { "log", {
                { "level", "info" },
                { "output", "stderr" }
            }},
            { "inbounds", {{
                { "type", "mixed" },
                { "listen", "127.0.0.1" },
                { "listen_port", 2080 },
                { "tag", "mixed-in" }
            }}},
            { "outbounds", {{
                { "type", "vless" },
                { "tag", "vless-out" },
                { "server", host },
                { "server_port", port },
                { "uuid", uuid },
                { "flow", flow },
                { "network", network },
                { "tls", tls },
                { "packet_encoding", packet_encoding },
                { "multiplex", multiplex },
                { "transport", transport }
            }}}
        };
    }

    static nlohmann::json createJsonConfigVmess(
        const std::string& uuid,
        const std::string& host,
        uint16_t port,
        const std::string& security,
        int alter_id,
        bool global_padding,
        bool authenticated_length,
        const std::string& network,
        const nlohmann::json& tls,
        const std::string& packet_encoding,
        const nlohmann::json& transport,
        const nlohmann::json& multiplex
        ) {
        return {
            { "log", {
                { "level", "info" },
                { "output", "stderr" }
            }},
            { "inbounds", {{
                { "type", "mixed" },
                { "listen", "127.0.0.1" },
                { "listen_port", 2080 },
                { "tag", "mixed-in" }
            }}},
            { "outbounds", {{
                { "type", "vmess" },
                { "tag", "vmess-out" },
                { "server", host },
                { "server_port", port },
                { "uuid", uuid },
                { "security", security },
                { "alter_id", alter_id },
                { "global_padding", global_padding },
                { "authenticated_length", authenticated_length },
                { "network", network },
                { "tls", tls },
                { "packet_encoding", packet_encoding },
                { "transport", transport },
                { "multiplex", multiplex }
            }}}
        };
    }

    static nlohmann::json createJsonConfigHysteria2(
    const std::string& host,
    uint16_t port,
    const std::string& password,
    const nlohmann::json& tls,
    int up_mbps,
    int down_mbps,
    const nlohmann::json& obfs,
    const std::string& network,
    const std::string& hop_interval,
    bool brutal_debug = false
    ) {
        nlohmann::json cfg = {
            { "log", {
                { "level", "info" },
                { "output", "stderr" }
            }},
            { "inbounds", {{
                { "type", "mixed" },
                { "listen", "127.0.0.1" },
                { "listen_port", 2080 },
                { "tag", "mixed-in" }
            }}},
            { "outbounds", {{
                { "type", "hysteria2" },
                { "tag",  "hy2-out" },
                { "server", host },
                { "server_port", port },
                { "tls", tls }
            }}}
        };

        auto& o = cfg["outbounds"][0];

        // Не пишем пустые/нулевые поля — это важно.
        if (!password.empty())        o["password"] = password;
        if (up_mbps > 0)              o["up_mbps"] = up_mbps;
        if (down_mbps > 0)            o["down_mbps"] = down_mbps;
        if (!obfs.empty())            o["obfs"] = obfs;           // {"type":"salamander","password":"..."}
        if (!network.empty())         o["network"] = network;     // "tcp" | "udp" (опционально)
        if (!hop_interval.empty())    o["hop_interval"] = hop_interval; // "30s" и т.п.
        if (brutal_debug)             o["brutal_debug"] = true;

        return cfg;
    }

    static nlohmann::json createJsonConfigTrojan(
        const std::string& password,
        const std::string& host,
        uint16_t port,
        const nlohmann::json& tls,
        const nlohmann::json& multiplex
    ) {
        nlohmann::json cfg = {
            { "log", {
                { "level", "info" },
                { "output", "stderr" }
            }},
            { "inbounds", {{
                { "type", "mixed" },
                { "listen", "127.0.0.1" },
                { "listen_port", 2080 },
                { "tag", "mixed-in" }
            }}},
            { "outbounds", {{
                { "type", "trojan" },
                { "tag", "trojan-out" },
                { "server", host },
                { "server_port", port },
                { "password", password },
                { "tls", tls },
                { "multiplex", multiplex }
            }}}
        };

        // **Не добавляем поле transport**, оно здесь не нужно

        return cfg;
    }

    static nlohmann::json createJsonConfigTuic(
    const std::string& password,
    const std::string& host,
    uint16_t port,
    const nlohmann::json& tls,
    const nlohmann::json& transport,
    const nlohmann::json& multiplex
    ) {
        return {
            { "log", {
                { "level", "info" },
                { "output", "stderr" }
            }},
            { "inbounds", {{
                { "type", "mixed" },
                { "listen", "127.0.0.1" },
                { "listen_port", 2080 },
                { "tag", "mixed-in" }
            }}},
            { "outbounds", {{
                { "type", "tuic" },
                { "tag", "tuic-out" },
                { "server", host },
                { "server_port", port },
                { "password", password },
                { "tls", tls },
                { "transport", transport },
                { "multiplex", multiplex }
            }}}
        };
    }

    static void saveFile(nlohmann::json json, const std::string& filename) {
        std::ofstream file("proxies/" + filename + ".json");
        if (!file.is_open()) {
            throw std::runtime_error("Cannot create config file: " + filename + ".json");
        }

        Logger* logger = Logger::of("SAVEFILE");
        json.erase("ps");
        logger->info(json.dump().c_str());

        file << json.dump(4);
        file.close();
    }

    static void createConfigNamesFile() {
        std::ofstream file("config/names.json");

        if (!file.is_open()) {
            throw std::runtime_error("Cannot create name config file");
        }

        nlohmann::json json = nlohmann::json::object();

        file << json.dump();

        file.close();
    }

    static std::ifstream getReadJsonFile() {
        std::ifstream ifs("config/names.json");

        if (!ifs.is_open()) {
            throw std::runtime_error("Cannot open name config file");
        }

        return ifs;
    }

    static std::ofstream getWriteJsonFile() {
        std::ofstream ofs("config/names.json");

        if (!ofs.is_open()) {
            throw std::runtime_error("Cannot open name config file");
        }

        return ofs;
    }

    static nlohmann::json getJsonConfig() {
        std::ifstream ifs = getReadJsonFile();

        nlohmann::json json = nlohmann::json::parse(ifs);
        ifs.close();

        return json;
    }

    static void addConfigName(std::string& server, std::string& name) {
        nlohmann::json json = getJsonConfig();
        json[server] = name;

        std::ofstream file("config/names.json");

        if (!file.is_open()) {
            throw std::runtime_error("Cannot open name config file");
        }

        file << json.dump(4);
        file.close();
    }


};



#endif //LOADER_H
