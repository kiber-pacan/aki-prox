//
// Created by down on 21.06.2025.
//

#ifndef PARSER_H
#define PARSER_H

#include <iostream>
#include <string>
#include <vector>
#include <Logger.hpp>
#include "base64/base64.h"
#include "Manager.hpp"

#include "json.hpp"

struct Parser {
    inline static std::vector<std::string> types = {
            "vmess",
            "vless",
            "ss",
            "hy2",
            "trojan",
            "http",
            "socks5"
        };

    inline static Logger* logger = Logger::of("ProxyParser");

    static std::vector<std::pair<nlohmann::json, std::string>> parse(const std::string& input) {
        size_t pos = std::string::npos;
        std::vector<std::string> proxies;
        size_t i = 0;

        std::stringstream ss(input);
        std::string proxy;

        while (ss >> proxy) {
            proxies.push_back(proxy);
        }

        std::vector<std::pair<nlohmann::json, std::string>> parsed;

        for (const std::string& proxy : proxies) {
            for (std::string type : types) {
                type += "://";
                pos = proxy.find(type);

                if (pos != std::string::npos){
                    pos += type.length();
                    break;
                }
                i += 1;
            }

            switch (i) {
                case 0: parsed.emplace_back(parse_vmess(proxy.substr(pos))); break;
                case 1: parsed.emplace_back(parse_vless(proxy.substr(pos))); break;
                case 2: parsed.emplace_back(parse_ss(proxy.substr(pos))); break;
                case 3: parsed.emplace_back(parse_hysteria2(proxy.substr(pos))); break;
                case 4: parsed.emplace_back(parse_trojan(proxy.substr(pos))); break;
                case 5: parsed.emplace_back(parse_http(proxy.substr(pos))); break;
                case 6: parsed.emplace_back(parse_socks(proxy.substr(pos))); break;
                default: parsed.emplace_back();
            }
        }

        logger->info(parsed.size());

        return parsed;
    }

    private:

    static std::string decodeUTF(const std::string &src) {
        std::string ret;
        char ch;
        int i, ii;
        for (i = 0; i < src.length(); i++) {
            if (src[i] == '%') {
                sscanf(src.substr(i + 1, 2).c_str(), "%x", &ii);
                ch = static_cast<char>(ii);
                ret += ch;
                i += 2;
            }
            else if (src[i] == '+') {
                ret += ' ';
            }
            else {
                ret += src[i];
            }
        }
        return ret;
    }

    static std::vector<std::string> separate(char* str, const char* sep) {
        std::vector<std::string> vec;
        char* token = std::strtok(str, sep);

        while (token != nullptr) {
            vec.emplace_back(token);
            token = std::strtok(nullptr, sep);
        }

        return vec;
    }

    static nlohmann::json jsonFromVec(std::vector<std::string> vec) {
        nlohmann::json json;
        for (std::string item : vec) {
            std::pair<const char*, const char*> pair;

            pair.first = std::strtok(item.data(), "=");

            auto token = std::strtok(nullptr, "=");
            pair.second = token == nullptr ? "" : token;

            json[pair.first] = pair.second;
        }

        return json;
    }

    static std::pair<nlohmann::json, std::string> parse_vmessJson(nlohmann::json vmess, std::string name) {
        std::string uuid = vmess.value("uuid", "");
        std::string host = vmess.value("server", "");
        uint16_t port = static_cast<uint16_t>(std::stoi(vmess.value("port", "0")));
        std::string security = vmess.value("scy", "auto");
        int alter_id = vmess.value("aid", 0);
        bool global_padding = false;
        bool authenticated_length = true;
        std::string network = vmess.value("net", "tcp");

        nlohmann::json tls = nlohmann::json::object();
        std::string tls_field = vmess.value("tls", "");
        if (tls_field == "tls") {
            tls["enabled"] = true;
        } else {
            tls["enabled"] = false;
        }

        std::string packet_encoding = "";

        nlohmann::json transport = nlohmann::json::object();
        if (network == "ws") {
            transport["type"] = "ws";
            transport["path"] = vmess.value("path", "");
            std::string ws_host = vmess.value("host", "");
            if (!ws_host.empty()) {
                transport["host"] = ws_host;
            }
        }

        nlohmann::json multiplex = nlohmann::json::object();

        return {Manager::createJsonConfigVmess(
            uuid,
            host,
            port,
            security,
            alter_id,
            global_padding,
            authenticated_length,
            network,
            tls,
            packet_encoding,
            transport,
            multiplex
        ), decodeUTF(name)};
    }

    static std::pair<nlohmann::json, std::string> parse_vmess(const std::string& proxy) {
        size_t middle = proxy.find('@');

        if (middle != std::string::npos) return parse_vmessRaw(proxy);

        std::string decoded = base64_decode(proxy);
        nlohmann::json vmess = nlohmann::json::parse(decoded);

        std::string name = vmess.value("ps", "");
        if (vmess.contains("ps")) {
            vmess.erase("ps");
        }

        return parse_vmessJson(vmess, decodeUTF(name));
    }

    static std::pair<nlohmann::json, std::string> parse_vmessRaw(const std::string& proxy) {
        size_t middle = proxy.find('@');

        std::string first = proxy.substr(0, middle);
        std::string second = proxy.substr(middle + 1);

        size_t sep2 = second.find(':');
        size_t hashtag = second.find('#');
        size_t question = second.find('?');

        // Setting proxy parameters
        std::string host = second.substr(0, sep2);
        std::string port = second.substr(sep2 + 1, hashtag - host.length() - 1);
        if (question) port = port.substr(0, port.find('?'));
        std::string name = second.substr(hashtag + 1);

        std::vector<std::string> options = separate(second.substr(question + 1, hashtag - host.length() - port.length() - 2).data(), "&");

        nlohmann::json rawVmess = jsonFromVec(options);

        rawVmess["server"] = host;
        rawVmess["port"] = port;
        rawVmess["uuid"] = first;

        logger->info(rawVmess.dump().c_str());

        return parse_vmessJson(rawVmess, decodeUTF(name));
    }

    static std::pair<nlohmann::json, std::string> parse_vless(const std::string& proxy) {
        size_t middle = proxy.find('@');
        std::string uuid = proxy.substr(0, middle);
        std::string second = proxy.substr(middle + 1);

        size_t sep2 = second.find(':');
        size_t hashtag = second.find('#');
        size_t question = second.find('?');

        std::string host = second.substr(0, sep2);
        std::string port = second.substr(sep2 + 1, hashtag - host.length() - 1);
        if (question != std::string::npos)
            port = port.substr(0, port.find('?'));

        std::string name = second.substr(hashtag + 1);

        nlohmann::json params;
        if (question != std::string::npos) {
            std::string q = second.substr(question + 1, hashtag - question - 1);
            std::vector<std::string> options = separate(q.data(), "&");
            params = jsonFromVec(options);
        }

        // flow, network (из ссылки это "type"), packetEncoding
        std::string flow = params.value("flow", "");
        std::string network = params.value("type", "tcp");
        std::string packet_encoding = params.value("packetEncoding", "");

        auto add_if_not_empty = [](nlohmann::json& j, const char* key, const std::string& val) {
            if (!val.empty()) j[key] = val;
        };
        auto lower = [](std::string s) {
            for (auto &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return s;
        };

        nlohmann::json tls;
        const std::string security = params.value("security", "");
        tls["enabled"] = !security.empty();
        tls["disable_sni"] = false;
        add_if_not_empty(tls, "server_name", params.value("sni", ""));
        tls["insecure"] = false;

        if (params.contains("fp")) {
            nlohmann::json utls;
            utls["enabled"] = true;
            add_if_not_empty(utls, "fingerprint", params.value("fp", ""));
            tls["utls"] = utls;
        }

        if (security == "reality") {
            nlohmann::json reality;
            reality["enabled"] = true;
            add_if_not_empty(reality, "public_key", params.value("pbk", ""));
            add_if_not_empty(reality, "short_id",   params.value("sid", ""));
            tls["reality"] = reality;
        }

        nlohmann::json transport = nlohmann::json::object();
        std::string t = lower(network);

        if (t == "ws" || t == "websocket") {
            transport["type"] = "websocket";
            add_if_not_empty(transport, "path", params.value("path", ""));
            if (params.contains("host")) {
                nlohmann::json headers = nlohmann::json::object();
                headers["Host"] = params.value("host", "");
                transport["headers"] = headers;
            }
        } else if (t == "http" || t == "h2" || t == "h2c") {
            transport["type"] = "http";
            add_if_not_empty(transport, "path", params.value("path", ""));
            add_if_not_empty(transport, "host", params.value("host", ""));
        } else if (t == "grpc") {
            transport["type"] = "grpc";
            add_if_not_empty(transport, "service_name", params.value("serviceName", ""));
        } else if (t == "quic") {
            transport["type"] = "quic";
        } else if (t == "httpupgrade" || t == "hup") {
            transport["type"] = "httpupgrade";
            add_if_not_empty(transport, "path", params.value("path", ""));
            add_if_not_empty(transport, "host", params.value("host", ""));
        } else {
        }

        nlohmann::json multiplex = nlohmann::json::object();

        return {
            Manager::createJsonConfigVless(
                uuid,
                host,
                static_cast<uint16_t>(std::stoul(port)),
                flow,
                network,
                tls,
                packet_encoding,
                multiplex,
                transport
            ),
            decodeUTF(name)
        };
    }

    static std::pair<nlohmann::json, std::string> parse_ss(const std::string& proxy) {
        size_t middle = proxy.find('@');

        std::string first = proxy.substr(0, middle);
        std::string second = proxy.substr(middle + 1);

        size_t sep1 = first.find(':');
        size_t sep2 = second.find(':');
        size_t hashtag = second.find('#');

        // Decode first half if needed
        bool coded = sep1 == std::string::npos;
        if (coded) {
            first = base64_decode(first);
            sep1 = first.find(':');
        }

        // Setting proxy parameters
        std::string method = first.substr(0, sep1);
        std::string password = first.substr(sep1 + 1);
        std::string host = second.substr(0, sep2);
        std::string port = second.substr(sep2 + 1, hashtag - host.length() - 1);
        std::string name = second.substr(hashtag + 1);

        return std::pair{
            Manager::createJsonConfig("shadowsocks", method, password, host, std::stoul(port)),
            decodeUTF(name)
            };
    }

    static std::pair<nlohmann::json, std::string> parse_hysteria2(const std::string& proxy) {
        size_t at = proxy.find('@');
        std::string auth = "";
        std::string rest = proxy;
        if (at != std::string::npos) {
            auth = decodeUTF(proxy.substr(0, at));
            rest = proxy.substr(at + 1);
        }

        size_t hashtag  = rest.find('#');
        std::string before_name = (hashtag == std::string::npos) ? rest : rest.substr(0, hashtag);
        std::string name        = (hashtag == std::string::npos) ? ""   : rest.substr(hashtag + 1);

        size_t qpos   = before_name.find('?');
        std::string authority = (qpos == std::string::npos) ? before_name : before_name.substr(0, qpos);
        std::string query     = (qpos == std::string::npos) ? ""          : before_name.substr(qpos + 1);

        size_t colon = authority.find(':');
        std::string host = (colon == std::string::npos) ? authority : authority.substr(0, colon);
        std::string port_str = (colon == std::string::npos) ? "" : authority.substr(colon + 1);
        uint16_t port = static_cast<uint16_t>(std::stoul(port_str.empty() ? "443" : port_str));

        nlohmann::json params;
        if (!query.empty()) {
            std::vector<std::string> options = separate(query.data(), "&");
            params = jsonFromVec(options);
        }

        auto add_if_not_empty = [](nlohmann::json& j, const char* k, const std::string& v) {
            if (!v.empty()) j[k] = v;
        };
        auto to_lower = [](std::string s) {
            for (auto &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return s;
        };
        auto truthy = [&](const std::string& v) {
            std::string x = to_lower(v);
            return (x == "1" || x == "true" || x == "yes");
        };
        auto to_int = [](const std::string& s) -> int {
            try { return s.empty() ? 0 : std::stoi(s); } catch (...) { return 0; }
        };

        nlohmann::json tls;
        tls["enabled"] = true;
        add_if_not_empty(tls, "server_name", params.value("sni", ""));
        if (params.contains("insecure")) {
            tls["insecure"] = truthy(params.value("insecure", ""));
        }

        if (params.contains("alpn")) {
            std::string al = params.value("alpn", "");
            if (!al.empty()) {
                nlohmann::json arr = nlohmann::json::array();
                for (auto &p : separate(al.data(), ",")) if (!p.empty()) arr.push_back(p);
                if (!arr.empty()) tls["alpn"] = arr;
            }
        }

        nlohmann::json obfs = nlohmann::json::object();
        std::string obfs_type = to_lower(params.value("obfs", ""));
        if (obfs_type == "salamander") {
            obfs["type"] = "salamander";
            add_if_not_empty(obfs, "password", params.value("obfs-password", ""));
        }

        int up_mbps   = to_int(params.value("up_mbps", params.value("upmbps", params.value("up", ""))));
        int down_mbps = to_int(params.value("down_mbps", params.value("downmbps", params.value("down", ""))));
        std::string hop_interval = params.value("hop_interval", params.value("hop-interval", ""));
        std::string network = to_lower(params.value("network", params.value("mode", ""))); // "tcp"/"udp" (опционально)

        return {
            Manager::createJsonConfigHysteria2(
                host,
                port,
                auth,
                tls,
                up_mbps,
                down_mbps,
                obfs,
                network,
                hop_interval,
                /*brutal_debug*/ false
            ),
            decodeUTF(name)
        };
    }

    static std::pair<nlohmann::json, std::string> parse_trojan(const std::string& proxy) {
        size_t middle = proxy.find('@');
        std::string first = proxy.substr(0, middle);
        std::string second = proxy.substr(middle + 1);

        size_t sep = second.find(':');
        size_t hashtag = second.find('#');
        size_t question = second.find('?');

        std::string host = second.substr(0, sep);
        std::string port = second.substr(sep + 1, hashtag - sep - 1);
        std::string name = (hashtag == std::string::npos) ? "" : second.substr(hashtag + 1);

        nlohmann::json params;
        if (question != std::string::npos) {
            std::string q = second.substr(question + 1, hashtag - question - 1);
            std::vector<std::string> options = separate(q.data(), "&");
            params = jsonFromVec(options);
        }

        nlohmann::json tls;
        tls["enabled"] = true;
        tls["disable_sni"] = false;
        tls["insecure"] = false;
        if (params.contains("sni")) tls["server_name"] = params.value("sni", "");

        nlohmann::json multiplex = nlohmann::json::object();

        return {
            Manager::createJsonConfigTrojan(
                first,
                host,
                static_cast<uint16_t>(std::stoul(port)),
                tls,
                multiplex
            ),
            decodeUTF(name)
        };
    }

    static std::pair<nlohmann::json, std::string> parse_http(const std::string& proxy) {
        size_t middle = proxy.find('@');

        std::string first = proxy.substr(0, middle);
        std::string second = proxy.substr(middle + 1);

        size_t sep1 = first.find(':');
        size_t sep2 = second.find(':');
        size_t hashtag = second.find('#');

        // Decode first half if needed
        bool coded = sep1 == std::string::npos;
        if (coded) {
            first = base64_decode(first);
            sep1 = first.find(':');
        }

        // Setting proxy parameters
        std::string username = first.substr(0, sep1);
        std::string password = first.substr(sep1 + 1);
        std::string host = second.substr(0, sep2);
        std::string port = second.substr(sep2 + 1, hashtag - host.length() - 1);
        std::string name = second.substr(hashtag + 1);

        return std::pair{
            Manager::createJsonConfig("socks5", username, password, host, std::stoul(port)),
            decodeUTF(name)
            };
    }

    static std::pair<nlohmann::json, std::string> parse_socks(const std::string& proxy) {
        size_t middle = proxy.find('@');

        std::string first = proxy.substr(0, middle);
        std::string second = proxy.substr(middle + 1);

        size_t sep1 = first.find(':');
        size_t sep2 = second.find(':');
        size_t hashtag = second.find('#');

        // Decode first half if needed
        bool coded = sep1 == std::string::npos;
        if (coded) {
            first = base64_decode(first);
            sep1 = first.find(':');
        }

        // Setting proxy parameters
        std::string username = first.substr(0, sep1);
        std::string password = first.substr(sep1 + 1);
        std::string host = second.substr(0, sep2);
        std::string port = second.substr(sep2 + 1, hashtag - host.length() - 1);
        std::string name = second.substr(hashtag + 1);

        return std::pair{
            Manager::createJsonConfig("http", username, password, host, std::stoul(port)),
            decodeUTF(name)
            };
    }
};

#endif //PARSER_H
