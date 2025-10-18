#include "../common/LoadBalancerProtocol.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "../../../deps/cxxopts/include/cxxopts.hpp"
#include <iostream>
#include "../../../deps/spdlog/include/spdlog/spdlog.h"
#include <fstream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <queue>

using namespace std;

struct Server {
    in_addr_t ip;
    uint16_t port = 8000;
};

struct Compare {
    bool operator()(const std::pair<int, int>& a, const std::pair<int, int>& b) const {
        return a.second > b.second;
    }
};

class LoadBalancer {
protected:
    int sockfd;
    string port;
    virtual LoadBalancerResponse processRequest(LoadBalancerRequest* req) = 0;

public:
    LoadBalancer(string port) : port(port) {}

    virtual ~LoadBalancer() = default;

    virtual void getServers(string filePath) = 0;
    void init() {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE; // Accept connections on any IP

        string host = "0.0.0.0"; // Accept connections from any interface

        int ret = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
        if (ret != 0) {
            std::cerr << "Error getting address info: " << gai_strerror(ret) << std::endl;
            exit(1);
        }

        this->sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (this->sockfd == -1) {
            std::cerr << "Error creating socket" << std::endl;
            freeaddrinfo(res);
            exit(1);
        }

        int yes = 1;
        if (setsockopt(this->sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
            std::cerr << "Error setting socket options" << std::endl;
            freeaddrinfo(res);
            close(this->sockfd);
            exit(1);
        }

        if (::bind(this->sockfd, res->ai_addr, res->ai_addrlen) == -1) {
            std::cerr << "Error binding socket" << std::endl;
            freeaddrinfo(res);
            close(this->sockfd);
            exit(1);
        }

        freeaddrinfo(res);
        spdlog::info("Load balancer started on port {}", port);
    }

    void run() {
        struct sockaddr_storage their_addr;
        socklen_t addr_size = sizeof(their_addr);

        if (listen(sockfd, 10) == -1) {
            cerr << "Error listening" << endl;
            exit(1);
        }

        while (true) {
            int clientfd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size);
            if (clientfd == -1) {
                cerr << "Error accepting client" << endl;
                continue;
            }
            cout << "accepted connection" << endl;

            char buffer[sizeof(LoadBalancerRequest)];
            size_t total_read = 0;
            while (total_read < sizeof(buffer)) {
                ssize_t bytes_read = read(clientfd, buffer + total_read, sizeof(buffer) - total_read);
                if (bytes_read <= 0) {
                    if (bytes_read == 0) {
                        cout << "Client disconnected." << endl;
                    } else {
                        cerr << "Read failed" << endl;
                    }
                    close(clientfd);
                    break;
                }
                total_read += bytes_read;
            }
            if (total_read != sizeof(LoadBalancerRequest)) {
                cerr << "Error: Received an incomplete request." << endl;
                close(clientfd);
                continue;
            }

            LoadBalancerRequest req;
            memcpy(&req, buffer, sizeof(req));
            char ip_string_buffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &req.client_addr, ip_string_buffer, INET_ADDRSTRLEN);
            string ip_str(ip_string_buffer);
            spdlog::info("Received request for client {} with request ID {}", ip_str, req.request_id);
            try {
                LoadBalancerResponse res = this->processRequest(&req);
                if (send(clientfd, &res, sizeof(LoadBalancerResponse), 0) == -1){
                    spdlog::info("Failed to fulfill request ID {}", req.request_id);
                    break;
                }
                char ip_string_buffer[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &res.videoserver_addr, ip_string_buffer, INET_ADDRSTRLEN);
                string ip_str(ip_string_buffer);
                spdlog::info("Responded to request ID {} with server {}:{}", res.request_id, ip_str, ntohs(res.videoserver_port));
            } catch (const char* e) {
                spdlog::info("Failed to fulfill request ID {}", req.request_id);
            }


            close(clientfd);
        }
    }
};

class LoadBalancerRoundRobin : public LoadBalancer {
    vector<Server> servers;
    size_t rrIndex = 0;

    void getServers(string filePath) override {
        ifstream inputFile(filePath);
        if (!inputFile.is_open()) {
            std::cerr << "Error: Could not open file " << filePath << std::endl;
            exit(1);
        }

        std::string key;
        int num_servers;
        inputFile >> key >> num_servers;
        if (key != "NUM_SERVERS:") {
            std::cerr << "Error: Invalid file format. Expected 'NUM_SERVERS:'" << std::endl;
            exit(1);
        }

        for (int i = 0; i < num_servers; ++i) {
            string ip;
            uint16_t port;
            inputFile >> ip >> port;
            if (inputFile.fail()) {
                std::cerr << "Error: Problem reading server #" << i + 1 << std::endl;
                exit(1);
            }
            servers.push_back(Server{inet_addr(ip.c_str()), port});
        }
        inputFile.close();
    }

    LoadBalancerResponse processRequest(LoadBalancerRequest* req) override {
        // maybe also check active connections?
        const Server& server = servers[rrIndex];
        rrIndex = (rrIndex + 1) % servers.size();
        return LoadBalancerResponse{server.ip, htons(server.port), req->request_id};
    }
public:
    LoadBalancerRoundRobin(string port) : LoadBalancer(port) {}

    virtual ~LoadBalancerRoundRobin() = default;
};

class LoadBalancerGeo : public LoadBalancer {
    // mapping of server - connections
    // mapping of server - connections
    map<int, Server> node_mapping; // server/client index to it's IP
    vector<vector<pair<int, int>>> edges; // (node, weight)
    vector<int> serverIds;
    vector<int> clientIds;
public:
    LoadBalancerGeo(string port) : LoadBalancer(port) {}

    virtual ~LoadBalancerGeo() = default;

    void getServers(string filePath) override {
        ifstream inputFile(filePath);
        if (!inputFile.is_open()) {
            std::cerr << "Error: Could not open file " << filePath << std::endl;
            exit(1);
        }

        std::string key;
        int num_nodes;
        inputFile >> key >> num_nodes;
        if (key != "NUM_NODES:") {
            std::cerr << "Error: Invalid file format. Expected 'NUM_NODES:'" << std::endl;
            exit(1);
        }

        for (int i = 0; i < num_nodes; ++i) {
            string type, ip;
            inputFile >> type >> ip;
            if (inputFile.fail()) {
                std::cerr << "Error: Problem reading node #" << i + 1 << std::endl;
                exit(1);
            }
            if (type == "SERVER") serverIds.push_back(i);
            else if (type == "CLIENT") clientIds.push_back(i);
            node_mapping[i] = Server{inet_addr(ip.c_str())};
            edges.emplace_back();
        }

        int num_links;
        inputFile >> key >> num_links;
        if (key != "NUM_LINKS:") {
            std::cerr << "Error: Invalid file format. Expected 'NUM_LINKS:'" << std::endl;
            exit(1);
        }

        for (int i = 0; i < num_links; ++i) {
            int from, to, weight;
            inputFile >> from >> to >> weight;
            if (inputFile.fail()) {
                std::cerr << "Error: Problem reading link #" << i + 1 << std::endl;
                exit(1);
            }
            edges[from].emplace_back(to, weight);
        }
        inputFile.close();
    }

    LoadBalancerResponse processRequest(LoadBalancerRequest* req) override {
        // Leave blank for user implementation
        // run djistras to find ip
        // port is 8000
        priority_queue<pair<int, int>, vector<pair<int, int>>, Compare> queue; // node weight
        map<int, int> shortest; // node: weight
        in_addr_t client_ip = req->client_addr;

        for (const int& cId: clientIds){
            if (node_mapping[cId].ip == client_ip){
                queue.push({cId, 0});
                break;
            }
        }

        if (queue.empty()) {
            throw "client not found";
        }

        while (!queue.empty()) {
            pair<int,int> top = queue.top();
            queue.pop();
            if (!shortest.count(top.first)) {
                shortest[top.first] = top.second;
            }
            for (const auto& node_weighting: edges[top.first]) {
                if (!shortest.count(node_weighting.first)) {
                    queue.push({node_weighting.first, node_weighting.second + top.second});
                }
            }
        }
        Server* min = nullptr;
        int minCost = -1;
        for (const int& id : serverIds) {
            if (shortest.count(id) && (minCost == -1 || shortest[id] < minCost)) {
                minCost = shortest[id];
                min = &node_mapping[id];
            }
        }
        if (minCost == -1) {
            throw "server not found";
        }
        return LoadBalancerResponse{min->ip, htons(min->port), req->request_id};
    }
};

int main(int argc, char** argv){
    cxxopts::Options options("loadBalancer", "Load balancer with geo and round-robin modes");

    options.add_options()
        ("p,port", "Port of the load balancer", cxxopts::value<string>())
        ("g,geo", "Run in geo mode", cxxopts::value<bool>()->default_value("false"))
        ("r,rr", "Run in round-robin mode", cxxopts::value<bool>()->default_value("false"))
        ("s,servers", "Path to file containing server info", cxxopts::value<std::string>())
        ("h,help", "Print usage");

    auto result = options.parse(argc, argv);

    if (result.count("help")) {
        cout << options.help() << endl;
        return 0;
    }

    if (!result.count("port") || !result.count("servers")) {
        cerr << "Error: --port and --servers are required." << endl;
        cout << options.help() << endl;
        return 1;
    }

    if (!result.count("geo") and !result.count("rr")) {
        cerr << "Error: --geo or --rr are required." << endl;
        return 1;
    }

    if (result.count("geo") and result.count("rr")) {
        cerr << "Error: --geo and --rr can't both be specified." << endl;
        return 1;
    }

    string port = result["port"].as<string>();
    int port_num = stoi(port);
    if (port_num < 1024 || port_num > 65535) {
        cerr << "Error: port must be between [1024, 65535]" << endl;
        return 1;
    }

    string serversFile = result["servers"].as<string>();
    bool geoMode = result["geo"].as<bool>();
    LoadBalancer* lb;
    if (geoMode) {
        lb = new LoadBalancerGeo(port);
    } else {
        lb = new LoadBalancerRoundRobin(port);
    }

    lb->getServers(serversFile);
    lb->init();
    lb->run();

    delete lb;

    return 0;
}
