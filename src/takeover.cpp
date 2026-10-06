#include "takeover.hpp"

#include <curl/curl.h>

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

#include "ratelimit.hpp"
#include "resolver.hpp"
#include "version.hpp"

namespace takeover {

namespace {

struct Fingerprint {
    const char* service;
    std::vector<const char*> cname_suffixes;  // CNAME targets that point at this service
    const char* body_signature;  // string in the HTTP body when the resource is unclaimed ("" = none)
    bool nxdomain_vulnerable;     // dangling CNAME (NXDOMAIN target) alone implies takeover
    const char* suggestion;
};

// Subset of the community "can-i-take-over-xyz" fingerprints.
const std::vector<Fingerprint>& fingerprints() {
    static const std::vector<Fingerprint> fp = {
        {"GitHub Pages", {"github.io", "github.map.fastly.net"},
         "There isn't a GitHub Pages site here", false,
         "Remove the CNAME or re-create the GitHub Pages site/repo for this name."},
        {"Amazon S3", {"s3.amazonaws.com", "s3-website", ".s3.", "s3.amazonaws"},
         "NoSuchBucket", false,
         "Re-create the referenced S3 bucket or delete the DNS record."},
        {"AWS Elastic Beanstalk", {"elasticbeanstalk.com"}, "", true,
         "Remove the DNS record or re-provision the Beanstalk environment."},
        {"Heroku", {"herokuapp.com", "herokudns.com", "herokussl.com"},
         "No such app", false,
         "Re-claim the Heroku app name or remove the CNAME."},
        {"Microsoft Azure", {"azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
                             "trafficmanager.net", "blob.core.windows.net", "azureedge.net",
                             "azurefd.net"}, "", true,
         "Remove the record or re-create the Azure resource it points to."},
        {"Fastly", {"fastly.net"}, "Fastly error: unknown domain", false,
         "Add the domain to the Fastly service or remove the CNAME."},
        {"Shopify", {"myshopify.com"}, "Sorry, this shop is currently unavailable", false,
         "Re-add the custom domain in Shopify or remove the record."},
        {"Surge.sh", {"surge.sh"}, "project not found", false,
         "Re-deploy to surge.sh or delete the CNAME."},
        {"Bitbucket", {"bitbucket.io"}, "Repository not found", false,
         "Re-create the Bitbucket site or remove the record."},
        {"Ghost", {"ghost.io"}, "The thing you were looking for is no longer here", false,
         "Re-claim the Ghost subdomain or remove the CNAME."},
        {"Pantheon", {"pantheonsite.io"}, "The gods are wise, but do not know of the site", false,
         "Re-add the domain in Pantheon or remove the record."},
        {"Tumblr", {"domains.tumblr.com"}, "Whatever you were looking for doesn't currently exist",
         false, "Re-add the domain in Tumblr or remove the CNAME."},
        {"WordPress.com", {"wordpress.com"}, "Do you want to register", false,
         "Re-map the domain in WordPress.com or remove the record."},
        {"Zendesk", {"zendesk.com"}, "Help Center Closed", false,
         "Re-activate the Zendesk host-mapping or remove the CNAME."},
        {"Readme.io", {"readme.io"}, "Project doesnt exist... yet!", false,
         "Re-create the Readme project or remove the record."},
        {"Netlify", {"netlify.app", "netlify.com"}, "Not Found - Request ID", false,
         "Re-add the domain in Netlify or remove the CNAME."},
        {"Agile CRM", {"agilecrm.com"}, "Sorry, this page is no longer available.", false,
         "Re-claim the Agile CRM domain or remove the record."},
        {"Aha!", {"ideas.aha.io"}, "There is no portal here", false,
         "Re-add the custom domain in Aha! or remove the CNAME."},
        {"Anima", {"animaapp.io"}, "If this is your website and you've just created it", false,
         "Re-publish the Anima project or remove the record."},
        {"AnnounceKit", {"announcekit.app"}, "Error 404 - AnnounceKit", false,
         "Re-create the AnnounceKit page or remove the CNAME."},
        {"Big Cartel", {"bigcartel.com"}, "<h1>Oops! We couldn", false,
         "Re-add the custom domain in Big Cartel or remove the record."},
        {"Campaign Monitor", {"createsend.com"}, "Double check the URL or ", false,
         "Re-add the domain in Campaign Monitor or remove the CNAME."},
        {"Canny", {"canny.io"}, "Company Not Found", false,
         "Re-map the Canny board domain or remove the record."},
        {"Cargo Collective", {"cargocollective.com"}, "404 Not Found", false,
         "Re-claim the Cargo site or remove the CNAME."},
        {"Gemfury", {"furyns.com"}, "404: This page could not be found.", false,
         "Re-create the Gemfury page or remove the record."},
        {"GetResponse", {"gr8.com"},
         "With GetResponse Landing Pages, lead generation has never been easier", false,
         "Re-add the domain in GetResponse or remove the CNAME."},
        {"HatenaBlog", {"hatenablog.com"}, "404 Blog is not found", false,
         "Re-map the HatenaBlog domain or remove the record."},
        {"Help Scout", {"helpscoutdocs.com"}, "No settings were found for this company:", false,
         "Re-configure the Help Scout docs domain or remove the CNAME."},
        {"Helpjuice", {"helpjuice.com"}, "We could not find what you're looking for.", false,
         "Re-add the Helpjuice domain or remove the record."},
        {"Intercom", {"custom.intercom.help"}, "Uh oh. That page doesn't exist.", false,
         "Re-map the Intercom custom domain or remove the CNAME."},
        {"JetBrains YouTrack", {"myjetbrains.com"}, "is not a registered InCloud YouTrack", false,
         "Re-register the YouTrack InCloud domain or remove the record."},
        {"LaunchRock", {"launchrock.com"}, "It looks like you may have taken a wrong turn somewhere.",
         false, "Re-create the LaunchRock page or remove the CNAME."},
        {"Ngrok", {"ngrok.io"}, "Tunnel *.ngrok.io not found", false,
         "Re-open the ngrok tunnel for this name or remove the record."},
        {"Read the Docs", {"readthedocs.io"}, "unknown to Read the Docs", false,
         "Re-add the custom domain in Read the Docs or remove the CNAME."},
        {"Short.io", {"short.io"}, "Link does not exist", false,
         "Re-claim the Short.io domain or remove the record."},
        {"Strikingly", {"strikinglydns.com"}, "But if you're looking to build your own website",
         false, "Re-add the domain in Strikingly or remove the CNAME."},
        {"Teamwork", {"teamwork.com"}, "Oops - We didn't find your site.", false,
         "Re-map the Teamwork site domain or remove the record."},
        {"Uberflip", {"uberflip.com"}, "The URL you've accessed does not provide a hub", false,
         "Re-map the Uberflip hub domain or remove the CNAME."},
        {"UserVoice", {"uservoice.com"}, "This UserVoice subdomain is currently available!", false,
         "Re-claim the UserVoice subdomain or remove the record."},
        {"Vend", {"vendecommerce.com"}, "Looks like you've traveled too far into cyberspace.", false,
         "Re-add the Vend store domain or remove the CNAME."},
        {"Webflow", {"proxy.webflow.com", "proxy-ssl.webflow.com"},
         "The page you are looking for doesn't exist or has been moved.", false,
         "Re-publish the Webflow site with this custom domain or remove the record."},
        {"Kinsta", {"kinsta.cloud"}, "No Site For Domain", false,
         "Re-add the domain in Kinsta or remove the CNAME."},
    };
    return fp;
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

size_t body_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    size_t total = size * nmemb;
    if (out->size() < 64 * 1024) out->append(ptr, std::min(total, 64 * 1024 - out->size()));
    return total;
}

// Fetches the HTTP(S) body for the host so body signatures can be matched.
std::string fetch_body(const std::string& host, long timeout) {
    CURL* c = curl_easy_init();
    if (!c) return "";
    std::string body;
    for (const char* scheme : {"https://", "http://"}) {
        ratelimit::acquire();
        std::string url = std::string(scheme) + host + "/";
        curl_easy_reset(c);
        curl_easy_setopt(c, CURLOPT_URL, url.c_str());
        curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(c, CURLOPT_MAXREDIRS, 10L);
        curl_easy_setopt(c, CURLOPT_TIMEOUT, timeout);
        curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 8L);
        curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(c, CURLOPT_USERAGENT, "certrecon/" CERTRECON_VERSION);
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, body_cb);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &body);
        if (curl_easy_perform(c) == CURLE_OK && !body.empty()) break;
        body.clear();
    }
    curl_easy_cleanup(c);
    return body;
}

const Fingerprint* match_fingerprint(const std::vector<std::string>& cnames) {
    for (const auto& raw : cnames) {
        std::string cn = to_lower(raw);
        for (const auto& fp : fingerprints())
            for (const char* suffix : fp.cname_suffixes)
                if (contains(cn, suffix)) return &fp;
    }
    return nullptr;
}

}  // namespace

void check(model::Host& host, bool allow_active, long http_timeout_secs) {
    const auto& cnames = host.dns.cnames;
    if (cnames.empty()) return;  // CNAME-based takeover only

    const std::string& final_target = cnames.back();
    const Fingerprint* fp = match_fingerprint(cnames);

    // Case 1: the CNAME target itself does not resolve (dangling pointer).
    bool target_dangling = resolver::is_nxdomain(final_target);

    if (target_dangling) {
        model::Finding f;
        if (fp) {
            f.severity = model::Severity::High;
            f.title = "Subdomain takeover (" + std::string(fp->service) + ")";
            f.detail = host.name + " -> " + final_target +
                       " (NXDOMAIN) on " + fp->service + ". The target resource is unclaimed.";
            f.suggestion = fp->suggestion;
        } else {
            f.severity = model::Severity::Medium;
            f.title = "Dangling CNAME";
            f.detail = host.name + " -> " + final_target +
                       " which does not resolve (NXDOMAIN). Potentially claimable.";
            f.suggestion = "Remove the stale CNAME, or re-create the resource it points to.";
        }
        host.findings.push_back(std::move(f));
        return;
    }

    // Case 2: target resolves and belongs to a known service — match the "unclaimed"
    // body signature to confirm the resource is free to take over. Needs an HTTP fetch.
    if (allow_active && fp && fp->body_signature && fp->body_signature[0] != '\0') {
        std::string body = fetch_body(host.name, http_timeout_secs);
        if (!body.empty() && contains(body, fp->body_signature)) {
            model::Finding f;
            f.severity = model::Severity::High;
            f.title = "Subdomain takeover (" + std::string(fp->service) + ")";
            f.detail = host.name + " -> " + final_target + " on " + fp->service +
                       " returns an unclaimed-resource page.";
            f.suggestion = fp->suggestion;
            host.findings.push_back(std::move(f));
        }
    }
}

}  // namespace takeover
