#include "techfp.hpp"

#include <algorithm>
#include <cctype>

namespace techfp {

namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Where a rule looks for its needle.
enum Where { HDR, BODY, COOKIE };

struct Rule {
    Where where;
    const char* key;     // header name (lowercased) for HDR; ignored otherwise
    const char* needle;  // lowercased substring to find
};

struct Sig {
    const char* name;
    std::vector<Rule> any;  // OR semantics: any matching rule flags the tech
};

// A compact, high-signal signature set (headers / cookies / body markers).
const std::vector<Sig>& signatures() {
    static const std::vector<Sig> sigs = {
        // --- servers / proxies (header-driven; versions grabbed separately) ---
        {"nginx", {{HDR, "server", "nginx"}}},
        {"Apache", {{HDR, "server", "apache"}}},
        {"IIS", {{HDR, "server", "microsoft-iis"}}},
        {"OpenResty", {{HDR, "server", "openresty"}}},
        {"LiteSpeed", {{HDR, "server", "litespeed"}}},
        {"Caddy", {{HDR, "server", "caddy"}}},
        {"Tomcat", {{HDR, "server", "apache-coyote"}, {HDR, "server", "tomcat"}}},
        {"Jetty", {{HDR, "server", "jetty"}}},
        {"Gunicorn", {{HDR, "server", "gunicorn"}}},
        {"Werkzeug", {{HDR, "server", "werkzeug"}}},
        {"Kestrel", {{HDR, "server", "kestrel"}}},
        {"Envoy", {{HDR, "server", "envoy"}}},
        {"Varnish", {{HDR, "via", "varnish"}, {HDR, "x-varnish", ""}}},
        {"HAProxy", {{HDR, "server", "haproxy"}}},

        // --- CDNs / edge ---
        {"Cloudflare", {{HDR, "server", "cloudflare"}, {HDR, "cf-ray", ""}}},
        {"Amazon CloudFront", {{HDR, "x-amz-cf-id", ""}, {HDR, "server", "cloudfront"}}},
        {"Fastly", {{HDR, "x-served-by", "cache-"}, {HDR, "x-fastly-request-id", ""}}},
        {"Akamai", {{HDR, "server", "akamaighost"}, {HDR, "x-akamai-transformed", ""}}},
        {"Vercel", {{HDR, "server", "vercel"}, {HDR, "x-vercel-id", ""}}},
        {"Netlify", {{HDR, "server", "netlify"}, {HDR, "x-nf-request-id", ""}}},
        {"Sucuri", {{HDR, "x-sucuri-id", ""}, {HDR, "server", "sucuri"}}},
        {"Imperva", {{HDR, "x-iinfo", ""}, {HDR, "x-cdn", "incapsula"}}},

        // --- app frameworks (headers) ---
        {"PHP", {{HDR, "x-powered-by", "php"}, {HDR, "set-cookie", "phpsessid"}}},
        {"ASP.NET", {{HDR, "x-powered-by", "asp.net"}, {HDR, "x-aspnet-version", ""},
                     {HDR, "set-cookie", "asp.net_sessionid"}}},
        {"ASP.NET MVC", {{HDR, "x-aspnetmvc-version", ""}}},
        {"Express", {{HDR, "x-powered-by", "express"}}},
        {"Next.js", {{HDR, "x-powered-by", "next.js"}, {BODY, "", "/_next/"},
                     {BODY, "", "__next_data__"}}},
        {"Nuxt.js", {{BODY, "", "__nuxt__"}, {BODY, "", "/_nuxt/"}}},
        {"Laravel", {{HDR, "set-cookie", "laravel_session"}, {HDR, "set-cookie", "xsrf-token"}}},
        {"Django", {{HDR, "set-cookie", "csrftoken"}, {HDR, "set-cookie", "django"}}},
        {"Flask", {{HDR, "set-cookie", "session="}, {HDR, "server", "werkzeug"}}},
        {"Ruby on Rails", {{HDR, "set-cookie", "_rails"}, {HDR, "x-powered-by", "phusion passenger"},
                           {HDR, "set-cookie", "_session_id"}}},
        {"Java (JSP/Servlet)", {{HDR, "set-cookie", "jsessionid"}}},
        {"Spring", {{HDR, "x-application-context", ""}}},
        {"CodeIgniter", {{HDR, "set-cookie", "ci_session"}}},
        {"ColdFusion", {{HDR, "set-cookie", "cfid"}, {HDR, "set-cookie", "cftoken"}}},
        {"Phusion Passenger", {{HDR, "x-powered-by", "phusion passenger"}}},

        // --- CMS / ecommerce (body + headers) ---
        {"WordPress", {{BODY, "", "wp-content"}, {BODY, "", "wp-includes"},
                       {BODY, "", "/wp-json/"}}},
        {"Drupal", {{HDR, "x-generator", "drupal"}, {BODY, "", "drupal.settings"},
                    {BODY, "", "sites/all/"}, {HDR, "x-drupal-cache", ""}}},
        {"Joomla", {{BODY, "", "/media/jui/"}, {BODY, "", "joomla!"},
                    {BODY, "", "content=\"joomla"}}},
        {"Magento", {{HDR, "set-cookie", "x-magento"}, {BODY, "", "/static/version"},
                     {BODY, "", "mage/cookies"}}},
        {"Shopify", {{HDR, "x-shopid", ""}, {HDR, "x-shopify-stage", ""},
                     {BODY, "", "cdn.shopify.com"}}},
        {"Ghost", {{HDR, "x-ghost-cache-status", ""}, {BODY, "", "content=\"ghost"}}},
        {"Wix", {{HDR, "x-wix-request-id", ""}, {BODY, "", "static.wixstatic.com"}}},
        {"Squarespace", {{BODY, "", "static.squarespace.com"},
                         {BODY, "", "this is squarespace"}}},
        {"Webflow", {{BODY, "", "content=\"webflow"}, {HDR, "server", "webflow"}}},
        {"TYPO3", {{BODY, "", "typo3"}, {BODY, "", "/typo3conf/"}}},
        {"Sitecore", {{HDR, "set-cookie", "sc_analytics"}, {BODY, "", "/sitecore/"}}},
        {"Adobe Experience Manager", {{BODY, "", "/etc.clientlibs/"},
                                      {BODY, "", "/content/dam/"}}},

        // --- JS frameworks / libraries (body) ---
        {"React", {{BODY, "", "data-reactroot"}, {BODY, "", "data-reactid"},
                   {BODY, "", "react-dom"}}},
        {"Angular", {{BODY, "", "ng-version"}, {BODY, "", "ng-app"}, {BODY, "", "angular.min.js"}}},
        {"Vue.js", {{BODY, "", "data-v-"}, {BODY, "", "vue.min.js"}, {BODY, "", "__vue__"}}},
        {"Svelte", {{BODY, "", "svelte-"}}},
        {"jQuery", {{BODY, "", "jquery.min.js"}, {BODY, "", "jquery.js"},
                    {BODY, "", "/jquery-"}}},
        {"Bootstrap", {{BODY, "", "bootstrap.min.css"}, {BODY, "", "bootstrap.min.js"},
                       {BODY, "", "class=\"navbar"}}},
        {"Tailwind CSS", {{BODY, "", "tailwindcss"}, {BODY, "", "tw-"}}},
        {"Gatsby", {{BODY, "", "/page-data/"}, {BODY, "", "___gatsby"}}},
        {"Font Awesome", {{BODY, "", "font-awesome"}, {BODY, "", "fontawesome"}}},
        {"Google Analytics", {{BODY, "", "google-analytics.com/analytics.js"},
                              {BODY, "", "gtag/js"}, {BODY, "", "googletagmanager.com"}}},
        {"Google Tag Manager", {{BODY, "", "googletagmanager.com/gtm.js"}}},
        {"reCAPTCHA", {{BODY, "", "google.com/recaptcha"}, {BODY, "", "grecaptcha"}}},
        {"Cloudflare Turnstile", {{BODY, "", "challenges.cloudflare.com/turnstile"}}},

        // --- dashboards / infra UIs ---
        {"Grafana", {{HDR, "set-cookie", "grafana_session"}, {BODY, "", "grafana-app"}}},
        {"Kibana", {{HDR, "kbn-name", ""}, {BODY, "", "kibana"}}},
        {"Jenkins", {{HDR, "x-jenkins", ""}}},
        {"GitLab", {{HDR, "set-cookie", "_gitlab_session"}, {BODY, "", "gitlab"}}},
        {"Prometheus", {{BODY, "", "prometheus time series"}}},
        {"phpMyAdmin", {{HDR, "set-cookie", "phpmyadmin"}, {BODY, "", "phpmyadmin"}}},
        {"Swagger UI", {{BODY, "", "swagger-ui"}}},
        {"Harbor", {{HDR, "set-cookie", "harbor"}}},
    };
    return sigs;
}

// Extracts a trailing version like "nginx/1.25.3" -> "1.25.3" from a header value.
std::string grab_version(const std::string& value_lower, const std::string& product_lower) {
    size_t p = value_lower.find(product_lower);
    if (p == std::string::npos) return "";
    size_t i = p + product_lower.size();
    if (i >= value_lower.size() || value_lower[i] != '/') return "";
    ++i;
    std::string v;
    while (i < value_lower.size() && (std::isdigit((unsigned char)value_lower[i]) ||
                                      value_lower[i] == '.')) {
        v += value_lower[i++];
    }
    // Trim a trailing dot if any.
    while (!v.empty() && v.back() == '.') v.pop_back();
    return v;
}

}  // namespace

std::vector<std::string> detect(const std::vector<std::pair<std::string, std::string>>& headers,
                                const std::string& body) {
    // Build lowercased header lookup (values joined when a key repeats).
    std::vector<std::pair<std::string, std::string>> hl;
    for (const auto& kv : headers) {
        std::string k = lower(kv.first);
        std::string v = lower(kv.second);
        bool merged = false;
        for (auto& e : hl)
            if (e.first == k) { e.second += "; " + v; merged = true; break; }
        if (!merged) hl.emplace_back(k, v);
    }
    auto hval = [&](const std::string& key) -> const std::string* {
        for (const auto& e : hl)
            if (e.first == key) return &e.second;
        return nullptr;
    };

    std::string body_l = lower(body);
    const std::string* server = hval("server");

    std::vector<std::string> out;
    auto add = [&](const std::string& t) {
        if (std::find(out.begin(), out.end(), t) == out.end()) out.push_back(t);
    };

    for (const auto& sig : signatures()) {
        bool hit = false;
        for (const auto& r : sig.any) {
            if (r.where == BODY) {
                if (body_l.find(r.needle) != std::string::npos) { hit = true; break; }
            } else {  // HDR / COOKIE both live in the header map
                const std::string* val = hval(r.key);
                if (!val) continue;
                if (r.needle[0] == '\0' || val->find(r.needle) != std::string::npos) {
                    hit = true;
                    break;
                }
            }
        }
        if (hit) add(sig.name);
    }

    // Attach versions for server-reported products where available.
    if (server) {
        struct VP { const char* name; const char* token; };
        static const VP vps[] = {{"nginx", "nginx"}, {"Apache", "apache"},
                                 {"OpenResty", "openresty"}, {"LiteSpeed", "litespeed"},
                                 {"IIS", "microsoft-iis"}, {"Jetty", "jetty"},
                                 {"Caddy", "caddy"}};
        for (const auto& vp : vps) {
            auto it = std::find(out.begin(), out.end(), vp.name);
            if (it == out.end()) continue;
            std::string ver = grab_version(*server, vp.token);
            if (!ver.empty()) *it = std::string(vp.name) + "/" + ver;
        }
    }
    // PHP version from X-Powered-By.
    if (const std::string* xp = hval("x-powered-by")) {
        auto it = std::find(out.begin(), out.end(), "PHP");
        if (it != out.end()) {
            std::string ver = grab_version(*xp, "php");
            if (!ver.empty()) *it = "PHP/" + ver;
        }
    }

    return out;
}

}  // namespace techfp
