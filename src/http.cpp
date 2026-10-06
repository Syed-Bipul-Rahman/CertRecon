#include "http.hpp"

#include <curl/curl.h>

#include <stdexcept>

#include "version.hpp"

namespace http {

namespace {

size_t write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

}  // namespace

void global_init() { curl_global_init(CURL_GLOBAL_DEFAULT); }
void global_cleanup() { curl_global_cleanup(); }

Client::Client(long timeout_secs) : curl_(curl_easy_init()), timeout_secs_(timeout_secs) {
    if (!curl_) throw std::runtime_error("failed to initialise libcurl");
}

Client::~Client() { curl_easy_cleanup(static_cast<CURL*>(curl_)); }

Response Client::post_json(const std::string& url, const std::string& payload) {
    CURL* c = static_cast<CURL*>(curl_);
    Response res;

    curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_reset(c);
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_POST, 1L);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, static_cast<long>(payload.size()));
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(c, CURLOPT_USERAGENT, "certrecon/" CERTRECON_VERSION);
    curl_easy_setopt(c, CURLOPT_ACCEPT_ENCODING, "");  // allow gzip/deflate/br
    curl_easy_setopt(c, CURLOPT_TIMEOUT, timeout_secs_);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);  // required for multithreaded use
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &res.body);

    CURLcode rc = curl_easy_perform(c);
    if (rc != CURLE_OK) {
        res.error = curl_easy_strerror(rc);
    } else {
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &res.status);
    }
    curl_slist_free_all(headers);
    return res;
}

}  // namespace http
