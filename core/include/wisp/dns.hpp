#pragma once

#include <memory>
#include <string>
#include <vector>

namespace wisp {

// Applying DNS means handing our resolver addresses to whatever owns
// /etc/resolv.conf on this machine. There is no single portable way to do
// that, so we detect the available mechanism rather than assuming one.
enum class DnsBackend {
    None,             // nothing usable: leave the resolver strictly alone
    SystemdResolved,  // resolvectl, the modern default
    ResolvConf,       // resolvconf(8)
    ResolvConfFile,   // last resort: rewrite /etc/resolv.conf, with a backup
};

const char* dns_backend_name(DnsBackend backend);

// One fully resolved external command: a fixed program plus argv, never a
// command string. No shell anywhere in Wisp, so a profile cannot smuggle
// metacharacters into a DNS helper the way wg-quick's PostUp allows.
struct DnsCommand {
    std::string program;
    std::vector<std::string> arguments;
    std::string stdin_data;

    bool operator==(const DnsCommand&) const = default;
};

// Host facts. Injectable so the selection logic is testable without depending
// on the machine the tests happen to run on.
struct DnsEnvironment {
    bool resolvectl_available = false;
    bool systemd_resolved_running = false;
    bool resolvconf_available = false;
    bool resolv_conf_is_regular_file = true;
    std::string resolv_conf_path = "/etc/resolv.conf";
};

DnsBackend select_backend(const DnsEnvironment& environment);
DnsEnvironment probe_environment();

// A resolver address must be an IP literal, so it can never be read as a flag.
bool is_valid_dns_server(const std::string& value);

// is_valid_search_domain lives in types.hpp, because the config parser needs
// the same rule but must not depend on this module.

std::vector<DnsCommand> plan_dns_apply(DnsBackend backend, const std::string& ifname,
                                       const std::vector<std::string>& servers,
                                       const std::vector<std::string>& domains);
std::vector<DnsCommand> plan_dns_revert(DnsBackend backend, const std::string& ifname);

std::string render_resolv_conf(const std::string& ifname, const std::vector<std::string>& servers,
                              const std::vector<std::string>& domains);

// Runs the planned commands. Returns false and fills `error` on the first
// non-zero exit. Uses fork/execvp: no shell, no string interpolation.
bool run_commands(const std::vector<DnsCommand>& commands, std::string& error);

class DnsManager {
  public:
    virtual ~DnsManager() = default;

    virtual bool apply(const std::string& ifname, const std::vector<std::string>& servers,
                       const std::vector<std::string>& domains, std::string& error) = 0;
    virtual bool revert(const std::string& ifname, std::string& error) = 0;
    virtual DnsBackend backend() const = 0;
};

std::unique_ptr<DnsManager> make_dns_manager(DnsBackend backend,
                                             const DnsEnvironment& environment = {});

}  // namespace wisp
