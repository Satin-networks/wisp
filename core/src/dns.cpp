#include "wisp/dns.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "wisp/types.hpp"

namespace wisp {
namespace {

constexpr const char* kRuntimeDir = "/run/wisp";
constexpr const char* kResolvConfBackup = "/run/wisp/resolv.conf.backup";

bool is_executable(const std::string& path) { return ::access(path.c_str(), X_OK) == 0; }

bool path_exists(const std::string& path) {
    struct stat info {};
    return ::stat(path.c_str(), &info) == 0;
}

std::string find_program(const std::vector<std::string>& candidates) {
    for (const auto& candidate : candidates) {
        if (is_executable(candidate)) return candidate;
    }
    return {};
}

std::string read_file(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

bool write_file(const std::string& path, const std::string& contents, mode_t mode) {
    const std::string tmp = path + ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0) return false;

    std::size_t written = 0;
    while (written < contents.size()) {
        const ssize_t n = ::write(fd, contents.data() + written, contents.size() - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            ::unlink(tmp.c_str());
            return false;
        }
        written += static_cast<std::size_t>(n);
    }
    if (::fsync(fd) != 0) {
        ::close(fd);
        ::unlink(tmp.c_str());
        return false;
    }
    ::close(fd);
    if (::chmod(tmp.c_str(), mode) != 0) {
        ::unlink(tmp.c_str());
        return false;
    }
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        return false;
    }
    return true;
}

// Keeps only the entries that are safe to place in an argument vector, so a
// malformed or hostile profile cannot inject a flag into resolvectl.
std::vector<std::string> filter_servers(const std::vector<std::string>& servers) {
    std::vector<std::string> kept;
    for (const auto& server : servers) {
        if (is_valid_dns_server(server)) kept.push_back(server);
    }
    return kept;
}

std::vector<std::string> filter_domains(const std::vector<std::string>& domains) {
    std::vector<std::string> kept;
    for (const auto& domain : domains) {
        if (is_valid_search_domain(domain)) kept.push_back(domain);
    }
    return kept;
}

}  // namespace

const char* dns_backend_name(DnsBackend backend) {
    switch (backend) {
        case DnsBackend::None: return "none";
        case DnsBackend::SystemdResolved: return "systemd-resolved";
        case DnsBackend::ResolvConf: return "resolvconf";
        case DnsBackend::ResolvConfFile: return "resolv.conf";
    }
    return "none";
}

DnsBackend select_backend(const DnsEnvironment& environment) {
    if (environment.resolvectl_available && environment.systemd_resolved_running) {
        return DnsBackend::SystemdResolved;
    }
    if (environment.resolvconf_available) {
        return DnsBackend::ResolvConf;
    }
    // Editing the file directly is the bluntest option and the easiest to get
    // wrong. If /etc/resolv.conf is a symlink it belongs to something else
    // (systemd-resolved's stub, for instance), and overwriting it would fight
    // that manager. Refusing is better than clobbering.
    if (environment.resolv_conf_is_regular_file) {
        return DnsBackend::ResolvConfFile;
    }
    return DnsBackend::None;
}

DnsEnvironment probe_environment() {
    DnsEnvironment environment;

    environment.resolvectl_available =
        !find_program({"/usr/bin/resolvectl", "/bin/resolvectl", "/usr/sbin/resolvectl",
                       "/sbin/resolvectl"})
             .empty();
    environment.resolvconf_available =
        !find_program({"/usr/sbin/resolvconf", "/sbin/resolvconf", "/usr/bin/resolvconf",
                       "/bin/resolvconf"})
             .empty();

    environment.systemd_resolved_running =
        path_exists("/run/systemd/resolve") || path_exists("/run/systemd/resolve/resolv.conf");

    struct stat info {};
    if (::lstat("/etc/resolv.conf", &info) == 0) {
        environment.resolv_conf_is_regular_file = S_ISREG(info.st_mode);
    } else {
        environment.resolv_conf_is_regular_file = false;
    }

    return environment;
}

bool is_valid_dns_server(const std::string& value) {
    if (value.empty()) return false;

    in_addr v4{};
    in6_addr v6{};
    return ::inet_pton(AF_INET, value.c_str(), &v4) == 1 ||
           ::inet_pton(AF_INET6, value.c_str(), &v6) == 1;
}

std::vector<DnsCommand> plan_dns_apply(DnsBackend backend, const std::string& ifname,
                                       const std::vector<std::string>& servers,
                                       const std::vector<std::string>& domains) {
    std::vector<DnsCommand> commands;

    const auto safe_servers = filter_servers(servers);
    const auto safe_domains = filter_domains(domains);
    if (safe_servers.empty()) return commands;

    switch (backend) {
        case DnsBackend::SystemdResolved: {
            DnsCommand dns;
            dns.program = "resolvectl";
            dns.arguments.push_back("dns");
            dns.arguments.push_back(ifname);
            for (const auto& server : safe_servers) dns.arguments.push_back(server);
            commands.push_back(dns);

            if (!safe_domains.empty()) {
                DnsCommand route;
                route.program = "resolvectl";
                route.arguments.push_back("domain");
                route.arguments.push_back(ifname);
                for (const auto& domain : safe_domains) {
                    // A routing domain (~example.com) sends queries for that
                    // suffix to this link's resolvers. That is what keeps DNS
                    // for the tunnel's own domains from leaking to the local
                    // resolver when split tunnelling. A profile may already
                    // spell the marker, so it is not added twice.
                    route.arguments.push_back(domain.front() == '~' ? domain : "~" + domain);
                }
                commands.push_back(route);
            }
            break;
        }

        case DnsBackend::ResolvConf: {
            DnsCommand command;
            command.program = "resolvconf";
            command.arguments = {"-a", ifname};
            command.stdin_data = render_resolv_conf(ifname, safe_servers, safe_domains);
            commands.push_back(command);
            break;
        }

        case DnsBackend::ResolvConfFile:
        case DnsBackend::None:
            // Handled directly by the manager (file) or not at all.
            break;
    }

    return commands;
}

std::vector<DnsCommand> plan_dns_revert(DnsBackend backend, const std::string& ifname) {
    switch (backend) {
        case DnsBackend::SystemdResolved:
            return {DnsCommand{"resolvectl", {"revert", ifname}, {}}};
        case DnsBackend::ResolvConf:
            // -f so that removing a link that is already gone is not an error.
            return {DnsCommand{"resolvconf", {"-d", ifname, "-f"}, {}}};
        case DnsBackend::ResolvConfFile:
        case DnsBackend::None:
            return {};
    }
    return {};
}

std::string render_resolv_conf(const std::string& ifname,
                               const std::vector<std::string>& servers,
                               const std::vector<std::string>& domains) {
    std::ostringstream out;
    out << "# Generated by Wisp for " << ifname << ". The previous file was backed up to "
        << kResolvConfBackup << ".\n";

    for (const auto& server : servers) {
        out << "nameserver " << server << "\n";
    }
    if (!domains.empty()) {
        out << "search";
        for (const auto& domain : domains) out << " " << domain;
        out << "\n";
    }
    return out.str();
}

bool run_commands(const std::vector<DnsCommand>& commands, std::string& error) {
    for (const auto& command : commands) {
        if (command.program.empty()) continue;

        int input[2] = {-1, -1};
        if (!command.stdin_data.empty()) {
            if (::pipe(input) != 0) {
                error = std::string("pipe failed: ") + std::strerror(errno);
                return false;
            }
        }

        const pid_t pid = ::fork();
        if (pid < 0) {
            error = std::string("fork failed: ") + std::strerror(errno);
            if (input[0] >= 0) {
                ::close(input[0]);
                ::close(input[1]);
            }
            return false;
        }

        if (pid == 0) {
            // Child. Between fork and exec only async-signal-safe calls.
            if (input[0] >= 0) {
                ::dup2(input[0], STDIN_FILENO);
                ::close(input[0]);
                ::close(input[1]);
            } else {
                const int devnull = ::open("/dev/null", O_RDONLY);
                if (devnull >= 0) {
                    ::dup2(devnull, STDIN_FILENO);
                    ::close(devnull);
                }
            }

            std::vector<char*> argv;
            argv.reserve(command.arguments.size() + 2);
            argv.push_back(const_cast<char*>(command.program.c_str()));
            for (const auto& argument : command.arguments) {
                argv.push_back(const_cast<char*>(argument.c_str()));
            }
            argv.push_back(nullptr);

            ::execvp(command.program.c_str(), argv.data());
            ::_exit(127);
        }

        if (input[1] >= 0) {
            const char* data = command.stdin_data.data();
            std::size_t remaining = command.stdin_data.size();
            while (remaining > 0) {
                const ssize_t n = ::write(input[1], data, remaining);
                if (n < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                data += n;
                remaining -= static_cast<std::size_t>(n);
            }
            ::close(input[1]);
        }
        if (input[0] >= 0) ::close(input[0]);

        int status = 0;
        while (::waitpid(pid, &status, 0) < 0) {
            if (errno != EINTR) {
                error = std::string("waitpid failed: ") + std::strerror(errno);
                return false;
            }
        }

        if (!WIFEXITED(status)) {
            error = command.program + " did not exit normally";
            return false;
        }
        if (WEXITSTATUS(status) != 0) {
            error = command.program + " exited with status " + std::to_string(WEXITSTATUS(status));
            return false;
        }
    }

    return true;
}

namespace {

class CommandDnsManager final : public DnsManager {
  public:
    CommandDnsManager(DnsBackend backend, const DnsEnvironment& environment)
        : backend_(backend), environment_(environment) {}

    DnsBackend backend() const override { return backend_; }

    bool apply(const std::string& ifname, const std::vector<std::string>& servers,
               const std::vector<std::string>& domains, std::string& error) override {
        if (backend_ == DnsBackend::None) {
            error = "no supported DNS manager found";
            return false;
        }
        if (backend_ == DnsBackend::ResolvConfFile) {
            return apply_resolv_conf_file(ifname, servers, domains, error);
        }
        return run_commands(plan_dns_apply(backend_, ifname, servers, domains), error);
    }

    bool revert(const std::string& ifname, std::string& error) override {
        if (backend_ == DnsBackend::None) return true;
        if (backend_ == DnsBackend::ResolvConfFile) {
            return revert_resolv_conf_file(error);
        }
        return run_commands(plan_dns_revert(backend_, ifname), error);
    }

  private:
    bool apply_resolv_conf_file(const std::string& ifname,
                                const std::vector<std::string>& servers,
                                const std::vector<std::string>& domains, std::string& error) {
        const auto safe_servers = filter_servers(servers);
        const auto safe_domains = filter_domains(domains);
        if (safe_servers.empty()) {
            error = "no valid DNS servers in the profile";
            return false;
        }

        std::error_code ignored;
        std::filesystem::create_directories(kRuntimeDir, ignored);
        ::chmod(kRuntimeDir, 0700);

        // Back up once. Overwriting an existing backup would destroy the
        // original the first apply saved.
        if (!path_exists(kResolvConfBackup)) {
            const auto original = read_file(environment_.resolv_conf_path);
            if (!write_file(kResolvConfBackup, original, 0600)) {
                error = std::string("could not back up ") + environment_.resolv_conf_path + ": " +
                        std::strerror(errno);
                return false;
            }
        }

        const auto contents = render_resolv_conf(ifname, safe_servers, safe_domains);
        if (!write_file(environment_.resolv_conf_path, contents, 0644)) {
            error = std::string("could not write ") + environment_.resolv_conf_path + ": " +
                    std::strerror(errno);
            return false;
        }
        return true;
    }

    bool revert_resolv_conf_file(std::string& error) {
        if (!path_exists(kResolvConfBackup)) return true;

        const auto original = read_file(kResolvConfBackup);
        if (!write_file(environment_.resolv_conf_path, original, 0644)) {
            error = std::string("could not restore ") + environment_.resolv_conf_path;
            return false;
        }
        std::error_code ignored;
        std::filesystem::remove(kResolvConfBackup, ignored);
        return true;
    }

    DnsBackend backend_;
    DnsEnvironment environment_;
};

}  // namespace

std::unique_ptr<DnsManager> make_dns_manager(DnsBackend backend,
                                             const DnsEnvironment& environment) {
    return std::make_unique<CommandDnsManager>(backend, environment);
}

}  // namespace wisp
