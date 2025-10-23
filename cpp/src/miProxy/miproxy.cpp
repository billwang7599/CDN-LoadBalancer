#include <spdlog/spdlog.h>
#include <cxxopts.hpp>
#include <pugixml.hpp>
#include <boost/regex.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include <iostream>
#include <algorithm>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "../common/LoadBalancerProtocol.h"

constexpr int MAX_CLIENTS = 500;
constexpr int READ_BUFFER_SIZE = 8192;

struct HttpMessage {
    std::string version;
    std::map<std::string, std::string> headers;
    std::string body;

    // Request fields
    std::string method;
    std::string path;

    // Response fields
    std::string status_code;
    std::string status_message;

    size_t get_content_length() const {
        if (headers.contains("content-length")) {
            return std::stoul(headers.at("content-length"));
        }
        return 0;
    }

    std::string get_header(const std::string& name) const {
        if (headers.contains(name)) {
            return headers.at(name);
        }
        return "";
    }

    void set_header(const std::string& name, const std::string& value) {
        headers[name] = value;
    }
};

struct ClientConnection {
    int client_socket = 0;
    int server_socket = 0;
    std::string server_hostname;
    int server_port = 0;
    std::string client_read_buffer;
    std::string server_read_buffer;

    bool has_pending_manifest = false;
    bool processed_first_manifest_response = false;
    std::string pending_video_name;

    bool is_valid() const {
        return client_socket > 0 && server_socket > 0;
    }

    void reset() {
        client_socket = 0;
        server_socket = 0;
        server_hostname.clear();
        server_port = 0;
        client_read_buffer.clear();
        server_read_buffer.clear();
        has_pending_manifest = false;
        processed_first_manifest_response = false;
        pending_video_name.clear();
    }
};

std::string to_lowercase(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::string remove_whitespace(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

int send_all(int sockfd, const std::string& data) {
    size_t total_sent = 0;
    size_t data_size = data.length();
    const char* data_ptr = data.c_str();

    while (total_sent < data_size) {
        ssize_t n = send(sockfd, data_ptr + total_sent, data_size - total_sent, 0);
        if (n <= 0) {
            return n;
        }
        total_sent += n;
    }

    return total_sent;
}

std::map<std::string, std::string> parse_headers(const std::string& header_text) {
    std::map<std::string, std::string> headers;
    std::istringstream stream(header_text);
    std::string line;

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = to_lowercase(remove_whitespace(line.substr(0, colon)));
            std::string value = remove_whitespace(line.substr(colon + 1));
            headers[name] = value;
        }
    }
    return headers;
}

std::optional<HttpMessage> parse_http_request(const std::string& data) {
    size_t line_end = data.find("\r\n");
    if (line_end == std::string::npos) return std::nullopt;

    std::string request_line = data.substr(0, line_end);
    boost::regex pattern("^([A-Z]+)\\s+(\\S+)\\s+(HTTP/\\d\\.\\d)"); // method, path,  version
    boost::smatch match;

    if (!boost::regex_match(request_line, match, pattern)) return std::nullopt;

    HttpMessage msg;
    msg.method = match[1].str();
    msg.path = match[2].str();
    msg.version = match[3].str();

    size_t headers_start = line_end + 2;
    size_t headers_end = data.find("\r\n\r\n");
    if (headers_end == std::string::npos) return std::nullopt;

    std::string header_text = data.substr(headers_start, headers_end - headers_start);
    msg.headers = parse_headers(header_text);

    return msg;
}

std::optional<HttpMessage> parse_http_response(const std::string& data) {
    size_t line_end = data.find("\r\n");
    if (line_end == std::string::npos) return std::nullopt;

    std::string status_line = data.substr(0, line_end);
    boost::regex pattern("^(HTTP/\\d\\.\\d)\\s+(\\d{3})\\s+(.*)"); // version status message
    boost::smatch match;

    if (!boost::regex_match(status_line, match, pattern)) return std::nullopt;

    HttpMessage msg;
    msg.version = match[1].str();
    msg.status_code = match[2].str();
    msg.status_message = match[3].str();

    size_t headers_start = line_end + 2;
    size_t headers_end = data.find("\r\n\r\n");
    if (headers_end == std::string::npos) return std::nullopt;

    std::string header_text = data.substr(headers_start, headers_end - headers_start);
    msg.headers = parse_headers(header_text);

    return msg;
}

std::string serialize_http_request(const HttpMessage& msg) {
    std::ostringstream ss;
    ss << msg.method << " " << msg.path << " " << msg.version << "\r\n";

    for (const auto& [name, value] : msg.headers) {
        ss << name << ": " << value << "\r\n";
    }
    ss << "\r\n";

    if (!msg.body.empty()) {
        ss << msg.body;
    }

    return ss.str();
}

std::string serialize_http_response(const HttpMessage& msg) {
    std::ostringstream ss;
    ss << msg.version << " " << msg.status_code << " " << msg.status_message << "\r\n";

    for (const auto& [name, value] : msg.headers) {
        ss << name << ": " << value << "\r\n";
    }
    ss << "\r\n";

    if (!msg.body.empty()) {
        ss << msg.body;
    }

    return ss.str();
}

bool is_manifest_request(const std::string& path) {
    return path.length() >= 4 && path.compare(path.length() - 4, 4, ".mpd") == 0;
}

bool is_video_segment_request(const std::string& path) {
    if (path.length() < 4 || path.compare(path.length() - 4, 4, ".m4s") != 0) {
        return false;
    }
    boost::regex pattern(".*/video/vid-\\d+-seg-\\d+\\.m4s$");
    return boost::regex_match(path, pattern);
}

std::string extract_video_name(const std::string& path) {
    boost::regex pattern(".*/videos/([^/]+)/.*");
    boost::smatch match;
    if (boost::regex_match(path, match, pattern)) {
        return match[1].str();
    }
    return "";
}

std::string modify_path_to_nolist(const std::string& path) {
    std::string result = path;
    size_t pos = result.find("vid.mpd");
    if (pos != std::string::npos) {
        result.replace(pos, 7, "vid-no-list.mpd");
    }
    return result;
}

int select_bitrate(double throughput_kbps, const std::vector<int>& available_bitrates) {
    if (available_bitrates.empty()) return -1;

    double max_supported = throughput_kbps / 1.5;
    int selected = available_bitrates.front();

    for (int bitrate : available_bitrates) {
        if (bitrate <= max_supported) {
            selected = bitrate;
        }
    }

    return selected;
}

std::string modify_segment_path_bitrate(const std::string& path, int new_bitrate) {
    boost::regex pattern("(.*/video/vid-)\\d+(-seg-\\d+\\.m4s)$");
    boost::smatch match;
    if (boost::regex_match(path, match, pattern)) {
        return match[1].str() + std::to_string(new_bitrate) + match[2].str();
    }
    return path;
}

std::optional<std::vector<int>> parse_manifest_xml(const std::string& xml_content) {
    pugi::xml_document doc;
    if (!doc.load_string(xml_content.c_str())) return std::nullopt;

    std::vector<int> bitrates;
    pugi::xpath_node_set video_sets = doc.select_nodes("//AdaptationSet[@mimeType='video/mp4']");
    for (const auto& node : video_sets) {
        pugi::xpath_node_set representations = node.node().select_nodes(".//Representation");
        for (const auto& repr : representations) {
            int bandwidth = repr.node().attribute("bandwidth").as_int();
            if (bandwidth > 0) {
                bitrates.push_back(bandwidth);
            }
        }
    }

    if (bitrates.empty()) return std::nullopt;
    return bitrates;
}

bool update_client_throughput(const HttpMessage& msg,
                              std::map<std::string, double>& throughput_map,
                              double alpha,
                              std::string& uuid_out,
                              size_t& size_out,
                              long long& duration_out,
                              double& instant_tput_out,
                              double& avg_tput_out) {
    std::string uuid = msg.get_header("x-489-uuid");
    std::string size_str = msg.get_header("x-fragment-size");
    std::string start_str = msg.get_header("x-timestamp-start");
    std::string end_str = msg.get_header("x-timestamp-end");

    if (uuid.empty() || size_str.empty() || start_str.empty() || end_str.empty()) {
        return false;
    }

    size_t fragment_size = std::stoul(size_str);
    long long start_time = std::stoll(start_str);
    long long end_time = std::stoll(end_str);
    long long duration_ms = end_time - start_time;

    if (duration_ms <= 0) return false;

    double elapsed_sec = duration_ms / 1000.0;
    double current_tput = (fragment_size * 8.0) / (elapsed_sec * 1000.0); // Kbps

    double current_avg = throughput_map[uuid];
    double new_avg = alpha * current_tput + (1.0 - alpha) * current_avg;
    throughput_map[uuid] = new_avg;

    uuid_out = uuid;
    size_out = fragment_size;
    duration_out = duration_ms;
    instant_tput_out = current_tput;
    avg_tput_out = new_avg;

    return true;
}

int create_listening_socket(int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, 10) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

int connect_to_server(const std::string& hostname, int port) {
    struct addrinfo hints = {}, *result;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port);
    int status = getaddrinfo(hostname.c_str(), port_str.c_str(), &hints, &result);
    if (status != 0) {
        spdlog::error("getaddrinfo: {}", gai_strerror(status));
        return -1;
    }

    int sockfd = -1;
    for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0) continue;

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }

        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(result);
    return sockfd;
}

std::pair<std::string, int> query_load_balancer(const std::string& lb_host, int lb_port, in_addr_t client_addr) {
    int sockfd = connect_to_server(lb_host, lb_port);
    if (sockfd < 0) return {"", -1};

    uint16_t request_id = (rand() % 65535) + 1;

    LoadBalancerRequest request;
    request.client_addr = client_addr;
    request.request_id = htons(request_id);

    size_t total_sent = 0;
    const char* request_ptr = reinterpret_cast<const char*>(&request);

    while (total_sent < sizeof(request)) {
        ssize_t n = send(sockfd, request_ptr + total_sent,
                        sizeof(request) - total_sent, 0);
        if (n <= 0) {
            close(sockfd);
            return {"", -1};
        }
        total_sent += n;
    }

    LoadBalancerResponse response;
    size_t total_received = 0;
    char* response_ptr = reinterpret_cast<char*>(&response);

    while (total_received < sizeof(response)) {
        ssize_t n = recv(sockfd, response_ptr + total_received,
                        sizeof(response) - total_received, 0);
        if (n <= 0) {
            close(sockfd);
            return {"", -1};
        }
        total_received += n;
    }

    close(sockfd);

    if (ntohs(response.request_id) != request_id) {
        return {"", -1};
    }

    struct in_addr addr;
    addr.s_addr = response.videoserver_addr;
    std::string server_ip = inet_ntoa(addr);
    int server_port = ntohs(response.videoserver_port);

    return {server_ip, server_port};
}

void process_manifest_request(ClientConnection& conn, const HttpMessage& request, std::map<std::string, std::vector<int>>& manifests) {
    std::string video_name = extract_video_name(request.path);
    std::string uuid = request.get_header("x-489-uuid");
    if (uuid.empty()) uuid = "unknown";

    spdlog::info("Manifest requested by {} forwarded to {}:{} for {}", uuid, conn.server_hostname, conn.server_port, request.path);

    bool is_first_request = !video_name.empty() && !manifests.contains(video_name);

    if (is_first_request) {
        conn.has_pending_manifest = true;
        conn.pending_video_name = video_name;

        HttpMessage original_req = request;
        HttpMessage nolist_req = request;
        nolist_req.path = modify_path_to_nolist(request.path);

        send_all(conn.server_socket, serialize_http_request(original_req));
        send_all(conn.server_socket, serialize_http_request(nolist_req));

        spdlog::debug("Pipelined manifest requests for first-time video: {}", video_name);
    } else {
        // Just send vid-no-list.mpd for client
        HttpMessage nolist_req = request;
        nolist_req.path = modify_path_to_nolist(request.path);
        send_all(conn.server_socket, serialize_http_request(nolist_req));

        spdlog::debug("Sent vid-no-list.mpd for cached video: {}", video_name);
    }
}

void process_segment_request(ClientConnection& conn, const HttpMessage& request, const std::map<std::string, std::vector<int>>& manifests, std::map<std::string, double>& throughput, double alpha) {
    // std::string uuid;
    // size_t size;
    // long long duration;
    // double instant_tput;
    // double avg_tput;

    // if (update_client_throughput(request, throughput, alpha, uuid, size, duration, instant_tput, avg_tput)) {
    //     spdlog::info("Client {} finished receiving a segment of size {} bytes in {} ms. "
    //                 "Throughput: {} Kbps. Avg Throughput: {} Kbps",
    //                 uuid, size, duration, static_cast<int>(instant_tput),
    //                 static_cast<int>(avg_tput));
    // }

    std::string uuid = request.get_header("x-489-uuid");
    std::string video_name = extract_video_name(request.path);

    HttpMessage modified_req = request;
    //std::cout<<"[debug] 1" << std::endl;

    if (!uuid.empty() && !video_name.empty() && manifests.contains(video_name)) {
        double client_tput = throughput.contains(uuid) ? throughput.at(uuid) : 0.0;

        const auto& bitrates = manifests.at(video_name);
        int selected_bitrate = select_bitrate(client_tput, bitrates);

        modified_req.path = modify_segment_path_bitrate(request.path, selected_bitrate);
        //std::cout << "HIIIII" << selected_bitrate << " " << video_name << std::endl;
        spdlog::info("Segment requested by {} forwarded to {}:{} as {} at bitrate {} Kbps",
                    uuid, conn.server_hostname, conn.server_port,
                    modified_req.path, selected_bitrate);
    }

    send_all(conn.server_socket, serialize_http_request(modified_req));
}

void process_fragment_received(ClientConnection& conn, const HttpMessage& request, std::map<std::string, double>& throughput, double alpha) {
    std::string uuid;
    size_t size;
    long long duration;
    double instant_tput;
    double avg_tput;

    if (update_client_throughput(request, throughput, alpha, uuid, size, duration, instant_tput, avg_tput)) {
        spdlog::info("Client {} finished receiving a segment of size {} bytes in {} ms. "
                    "Throughput: {} Kbps. Avg Throughput: {} Kbps",
                    uuid, size, duration, static_cast<int>(instant_tput),
                    static_cast<int>(avg_tput));
    }

    HttpMessage response;
    response.version = "HTTP/1.1";
    response.status_code = "200";
    response.status_message = "OK";
    response.set_header("Content-Length", "0");

    send_all(conn.client_socket, serialize_http_response(response));
}

void process_client_request(ClientConnection& conn,
                            const HttpMessage& request,
                            std::map<std::string, std::vector<int>>& manifests,
                            std::map<std::string, double>& throughput,
                            double alpha) {
    if (request.method == "GET" && is_manifest_request(request.path)) {
        process_manifest_request(conn, request, manifests);
    } else if (request.method == "GET" && is_video_segment_request(request.path)) {
        //std::cout << "[debug] 2" << request.path << std::endl;
        process_segment_request(conn, request, manifests, throughput, alpha);
    } else if (request.method == "POST" && request.path == "/on-fragment-received") {
        process_fragment_received(conn, request, throughput, alpha);
    } else {
        // Forward other requests
        send_all(conn.server_socket, serialize_http_request(request));
    }
}

bool process_buffered_requests(ClientConnection& conn,
                               std::map<std::string, std::vector<int>>& manifests,
                               std::map<std::string, double>& throughput,
                               double alpha) {
    bool processed_any = false;

    while (true) {
        size_t header_end = conn.client_read_buffer.find("\r\n\r\n");
        if (header_end == std::string::npos) break;

        std::string header_data = conn.client_read_buffer.substr(0, header_end + 4);

        auto request = parse_http_request(header_data);
        if (!request) {
            break;
        }

        size_t content_length = request->get_content_length();
        size_t total_size = header_end + 4 + content_length;

        if (conn.client_read_buffer.size() < total_size) {
            break;
        }

        if (content_length > 0) {
            request->body = conn.client_read_buffer.substr(header_end + 4, content_length);
        }

        process_client_request(conn, *request, manifests, throughput, alpha);
        processed_any = true;

        conn.client_read_buffer = conn.client_read_buffer.substr(total_size);
    }

    return processed_any;
}

bool process_buffered_responses(ClientConnection& conn,
                                std::map<std::string, std::vector<int>>& manifests) {
    bool processed_any = false;

    while (true) {
        size_t header_end = conn.server_read_buffer.find("\r\n\r\n");
        if (header_end == std::string::npos) break;

        std::string header_data = conn.server_read_buffer.substr(0, header_end + 4);

        auto response = parse_http_response(header_data);
        if (!response) {
            break;
        }

        size_t content_length = response->get_content_length();
        size_t total_size = header_end + 4 + content_length;

        if (conn.server_read_buffer.size() < total_size) {
            break;
        }

        if (content_length > 0) {
            response->body = conn.server_read_buffer.substr(header_end + 4, content_length);
        }

        send_all(conn.client_socket, serialize_http_response(*response));
        processed_any = true;

        conn.server_read_buffer = conn.server_read_buffer.substr(total_size);
    }

    return processed_any;
}

bool process_buffered_manifest_responses(ClientConnection& conn, std::map<std::string, std::vector<int>>& manifests) {
    // first response
    if (!conn.processed_first_manifest_response) {
        size_t first_header_end = conn.server_read_buffer.find("\r\n\r\n");
        if (first_header_end == std::string::npos) return false;

        std::string first_header_data = conn.server_read_buffer.substr(0, first_header_end + 4);
        auto first_response = parse_http_response(first_header_data);
        if (!first_response) return false;

        size_t first_content_length = first_response->get_content_length();
        size_t first_total_size = first_header_end + 4 + first_content_length;

        if (conn.server_read_buffer.size() < first_total_size) return false;

        if (first_content_length > 0) {
            first_response->body = conn.server_read_buffer.substr(first_header_end + 4, first_content_length);
        }

        if (auto bitrates = parse_manifest_xml(first_response->body)) {
            manifests[conn.pending_video_name] = *bitrates;
            spdlog::debug("Stored bitrates for '{}': {} values",
                         conn.pending_video_name, bitrates->size());
        }

        conn.server_read_buffer = conn.server_read_buffer.substr(first_total_size);
        conn.processed_first_manifest_response = true;
    }

    // second response
    size_t second_header_end = conn.server_read_buffer.find("\r\n\r\n");
    if (second_header_end == std::string::npos) return false;

    std::string second_header_data = conn.server_read_buffer.substr(0, second_header_end + 4);
    auto second_response = parse_http_response(second_header_data);
    if (!second_response) return false;

    size_t second_content_length = second_response->get_content_length();
    size_t second_total_size = second_header_end + 4 + second_content_length;

    if (conn.server_read_buffer.size() < second_total_size) return false;

    if (second_content_length > 0) {
        second_response->body = conn.server_read_buffer.substr(second_header_end + 4, second_content_length);
    }

    send_all(conn.client_socket, serialize_http_response(*second_response));

    conn.server_read_buffer = conn.server_read_buffer.substr(second_total_size);

    conn.has_pending_manifest = false;
    conn.processed_first_manifest_response = false;
    conn.pending_video_name.clear();

    return true;
}

int main(int argc, char* argv[]) {
    cxxopts::Options options("miProxy", "miProxy");
    options.add_options()
        ("b,balance", "Enable load balancing", cxxopts::value<bool>()->default_value("false"))
        ("l,listen-port", "HTTP Proxy port", cxxopts::value<int>())
        ("h,hostname", "Video server or load balancer hostname", cxxopts::value<std::string>())
        ("p,port", "Video server or load balancer port", cxxopts::value<int>())
        ("a,alpha", "alpha", cxxopts::value<double>());

    auto result = options.parse(argc, argv);

    bool use_load_balancer = result["balance"].as<bool>();
    int listen_port = result["listen-port"].as<int>();
    std::string hostname = result["hostname"].as<std::string>();
    int port = result["port"].as<int>();
    double alpha = result["alpha"].as<double>();

    if (listen_port < 1024 || listen_port > 65535) {
        spdlog::error("Listen port must be in [1024, 65535]");
        return 1;
    }
    if (port < 1024 || port > 65535) {
        spdlog::error("Video server or load balancer port must be in [1024, 65535]");
        return 1;
    }
    if (alpha < 0.0 || alpha > 1.0) {
        spdlog::error("Alpha must be in [0.0, 1.0]");
        return 1;
    }

    std::vector<ClientConnection> connections(MAX_CLIENTS);
    std::map<std::string, std::vector<int>> manifests;
    std::map<std::string, double> throughput;

    int listen_sock = create_listening_socket(listen_port);
    spdlog::info("miProxy started");

    fd_set readfds;
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);

    while (true) {
        FD_ZERO(&readfds);
        FD_SET(listen_sock, &readfds);

        for (auto& conn : connections) {
            if (conn.client_socket > 0) FD_SET(conn.client_socket, &readfds);
            if (conn.server_socket > 0) FD_SET(conn.server_socket, &readfds);
        }

        int activity = select(FD_SETSIZE, &readfds, nullptr, nullptr, nullptr);
        if (activity < 0) {
            spdlog::error("select error: {}", strerror(errno));
            continue;
        }

        // server socket
        if (FD_ISSET(listen_sock, &readfds)) {
            int client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &addrlen);
            if (client_sock < 0) {
                spdlog::error("accept error: {}", strerror(errno));
                continue;
            }

            spdlog::info("New client socket connected with {}:{} on sockfd {}",
                        inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port),
                        client_sock);

            std::string server_host;
            int server_port;

            if (use_load_balancer) {
                auto result = query_load_balancer(hostname, port, client_addr.sin_addr.s_addr);
                server_host = result.first;
                server_port = result.second;
            } else {
                server_host = hostname;
                server_port = port;
            }

            if (server_host.empty() || server_port <= 0) {
                spdlog::error("Failed to get server assignment");
                close(client_sock);
                continue;
            }

            int server_sock = connect_to_server(server_host, server_port);
            if (server_sock < 0) {
                spdlog::error("Failed to connect to server {}:{}", server_host, server_port);
                close(client_sock);
                continue;
            }

            for (auto& conn : connections) {
                if (!conn.is_valid()) {
                    conn.client_socket = client_sock;
                    conn.server_socket = server_sock;
                    conn.server_hostname = server_host;
                    conn.server_port = server_port;
                    break;
                }
            }
        }

        // client/video server sockets
        for (auto& conn : connections) {
            if (!conn.is_valid()) continue;

            // video server
            if (FD_ISSET(conn.server_socket, &readfds)) {
                char buffer[READ_BUFFER_SIZE];
                int n = recv(conn.server_socket, buffer, sizeof(buffer), 0);

                if (n <= 0) {
                    spdlog::debug("Server disconnected");
                    close(conn.server_socket);
                    conn.server_socket = 0;
                } else {
                    conn.server_read_buffer.append(buffer, n);

                    if (conn.has_pending_manifest) {
                        process_buffered_manifest_responses(conn, manifests);
                    } else {
                        process_buffered_responses(conn, manifests);
                    }
                }
            }

            // client
            if (FD_ISSET(conn.client_socket, &readfds)) {
                char buffer[READ_BUFFER_SIZE];
                int n = recv(conn.client_socket, buffer, sizeof(buffer), 0);

                if (n <= 0) {
                    spdlog::info("Client socket sockfd {} disconnected", conn.client_socket);
                    close(conn.client_socket);
                    if (conn.server_socket > 0) close(conn.server_socket);
                    conn.reset();
                } else {
                    conn.client_read_buffer.append(buffer, n);
                    process_buffered_requests(conn, manifests, throughput, alpha);
                }
            }
        }
    }

    return 0;
}
