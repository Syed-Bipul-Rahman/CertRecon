// Thin RAII wrapper around libcurl for JSON POST requests.
#pragma once

#include <string>

namespace http {

struct Response {
    long status = 0;
    std::string body;
    std::string error;  // non-empty on transport failure
};

// Call once at program start / end (not thread-safe).
void global_init();
void global_cleanup();

class Client {
public:
    explicit Client(long timeout_secs);
    ~Client();
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    Response post_json(const std::string& url, const std::string& payload);

private:
    void* curl_;  // CURL*
    long timeout_secs_;
};

}  // namespace http
