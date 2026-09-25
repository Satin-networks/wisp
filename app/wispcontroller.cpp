#include "wispcontroller.h"

#include <QClipboard>
#include <QDateTime>
#include <QGuiApplication>
#include <QLocalSocket>
#include <QMap>
#include <QSettings>
#include <QTimer>

#include <cmath>
#include <utility>

#include "wisp/ipc.hpp"
#include "wisp/keys.hpp"

// GCC used to flag a false positive in Qt's own QHash path (qhash.h:559) when
// applyStats() inlined QHash::insert. The parser below avoids QHash entirely,
// which cleared the warning and dropped an allocation per field per poll.

namespace {

// How often to poll, per state. Connected numbers move, so poll briskly (one
// write and one read on the persistent connection). Idle keeps a cheap
// heartbeat in case the helper appears or vanishes. Hidden windows back off
// hard instead of burning a wakeup every second on a laptop.
constexpr int kPollConnectedMs = 400;
constexpr int kPollIdleMs = 1500;
constexpr int kPollBackgroundMs = 6000;

// A request that gets no answer must not leave the UI spinning forever.
constexpr int kRequestTimeoutMs = 5000;

constexpr int kHistoryLength = 90;

QString verb_from_std_string(std::string_view value) {
    return QString::fromLatin1(value.data(), static_cast<int>(value.size()));
}

// Compares a token against a short ASCII key without constructing a QString.
bool token_equals(const QString& payload, qsizetype start, qsizetype length, const char* key) {
    qsizetype index = 0;
    for (; index < length && key[index] != '\0'; ++index) {
        if (payload.at(start + index).unicode() !=
            static_cast<char16_t>(static_cast<unsigned char>(key[index]))) {
            return false;
        }
    }
    return index == length && key[index] == '\0';
}

// Reads the numeric value of `key` out of a "key=value key=value" status line.
// No allocations: this runs several times a second over a handful of fields,
// so a hash map would be pure overhead here.
double numeric_field(const QString& payload, const char* key) {
    const qsizetype size = payload.size();
    qsizetype position = 0;

    while (position < size) {
        while (position < size && payload.at(position) == QLatin1Char(' ')) ++position;
        const qsizetype start = position;
        while (position < size && payload.at(position) != QLatin1Char(' ')) ++position;
        if (position == start) break;

        // A token without '=' is not a field, but the '=' search must still be
        // bounded to this token so that the next one cannot be mistaken for it.
        const qsizetype equals = payload.indexOf(QLatin1Char('='), start);
        if (equals >= 0 && equals < position && token_equals(payload, start, equals - start, key)) {
            bool ok = false;
            const double value =
                QStringView(payload).mid(equals + 1, position - equals - 1).toDouble(&ok);
            return ok ? value : 0.0;
        }
    }
    return 0.0;
}

}  // namespace

WispController::WispController(QString socketPath, QObject* parent) : QObject(parent) {
    if (socketPath.isEmpty()) {
        socketPath = qEnvironmentVariable("WISP_SOCKET");
    }
    if (socketPath.isEmpty()) {
        socketPath = QString::fromLatin1(wisp::ipc::kDefaultSocketPath);
    }
    socketPath_ = socketPath;

    // Key generation is unprivileged, so the UI can offer it directly.
    wisp::crypto_init();

    loadTheme();

    pollTimer_ = new QTimer(this);
    connect(pollTimer_, &QTimer::timeout, this, &WispController::onPollTick);

    watchdog_ = new QTimer(this);
    watchdog_->setSingleShot(true);
    connect(watchdog_, &QTimer::timeout, this, [this]() {
        if (pending_.empty()) return;
        if (socket_) socket_->abort();
        failAllPending(tr("the helper stopped responding"));
    });

    updatePollInterval();
    pollTimer_->start();

    refresh();
}

WispController::~WispController() {
    // The private key is the one secret this process holds; overwrite it rather
    // than leaving it in a freed heap block for whatever allocates next.
    wisp::secure_wipe(privateKey_);
}

QString WispController::version() const { return QStringLiteral(WISP_VERSION); }

QString WispController::generatedPrivateKey() const {
    return QString::fromLatin1(privateKey_.data(), static_cast<int>(privateKey_.size()));
}

void WispController::ensureSocket() {
    if (socket_) return;

    socket_ = new QLocalSocket(this);
    connect(socket_, &QLocalSocket::connected, this, [this]() { pumpWrites(); });
    connect(socket_, &QLocalSocket::readyRead, this, &WispController::onReadyRead);
    connect(socket_, &QLocalSocket::disconnected, this, &WispController::onDisconnected);
    connect(socket_, &QLocalSocket::errorOccurred, this,
            [this](QLocalSocket::LocalSocketError) { onDisconnected(); });
}

void WispController::send(const QString& verb, const QString& argument,
                          std::function<void(bool, const QString&)> handler) {
    PendingRequest request;
    request.line = argument.isEmpty()
                       ? (verb + QLatin1Char('\n')).toUtf8()
                       : (verb + QLatin1Char(' ') + argument + QLatin1Char('\n')).toUtf8();
    request.handler = std::move(handler);
    pending_.push_back(std::move(request));

    armWatchdog();
    ensureSocket();
    pumpWrites();
}

void WispController::pumpWrites() {
    if (!socket_) return;

    if (socket_->state() == QLocalSocket::UnconnectedState) {
        socket_->connectToServer(socketPath_);
        return;
    }
    if (socket_->state() != QLocalSocket::ConnectedState) return;

    // The helper answers in order, so everything queued can be written at once
    // and matched up positionally as responses arrive.
    while (sentCount_ < static_cast<qsizetype>(pending_.size())) {
        const QByteArray& line = pending_[static_cast<std::size_t>(sentCount_)].line;
        if (socket_->write(line) != line.size()) {
            onDisconnected();
            return;
        }
        ++sentCount_;
    }
    socket_->flush();
}

void WispController::onReadyRead() {
    if (!socket_) return;
    readBuffer_ += socket_->readAll();

    for (;;) {
        const qsizetype newline = readBuffer_.indexOf('\n');
        if (newline < 0) break;

        const QByteArray body = readBuffer_.left(newline);
        readBuffer_.remove(0, newline + 1);

        // A reply with nothing outstanding would mean the stream is out of
        // step; dropping it keeps the positional match intact.
        if (pending_.empty()) continue;

        PendingRequest request = std::move(pending_.front());
        pending_.pop_front();
        if (sentCount_ > 0) --sentCount_;

        bool ok = false;
        QString payload;
        const auto is_status = [&body](const char* word, qsizetype length) {
            return body.size() >= length && body.startsWith(word) &&
                   (body.size() == length || body.at(length) == ' ');
        };

        // "OK" must be exactly "OK" or "OK ", never "OKAY".
        if (is_status("OK", 2)) {
            ok = true;
            payload = QString::fromUtf8(body.mid(2)).trimmed();
        } else if (is_status("ERR", 3)) {
            payload = QString::fromUtf8(body.mid(3)).trimmed();
        } else {
            payload = tr("the helper sent an unexpected reply");
        }

        if (request.handler) request.handler(ok, payload);
    }

    armWatchdog();
}

void WispController::onDisconnected() {
    // Detach before aborting: abort() re-enters here through the socket's own
    // signals, and a null socket_ is what makes the second entry a no-op.
    if (socket_) {
        QLocalSocket* socket = socket_;
        socket_ = nullptr;
        socket->disconnect(this);
        socket->abort();
        socket->deleteLater();
    }

    readBuffer_.clear();
    sentCount_ = 0;

    failAllPending(tr("the helper is not running"));
    setDaemon(false, tr("helper not reachable"));

    if (connected_) {
        connected_ = false;
        connectedTunnel_.clear();
        emit statsChanged();
    }
}

void WispController::failAllPending(const QString& reason) {
    if (pending_.empty()) {
        watchdog_->stop();
        return;
    }

    // Move the queue out first: a handler is free to send another request, and
    // that must land in the fresh queue rather than the one being drained.
    std::deque<PendingRequest> abandoned = std::move(pending_);
    pending_.clear();
    sentCount_ = 0;
    watchdog_->stop();

    for (auto& request : abandoned) {
        if (request.handler) request.handler(false, reason);
    }
}

void WispController::armWatchdog() {
    if (pending_.empty()) {
        watchdog_->stop();
        return;
    }
    watchdog_->start(kRequestTimeoutMs);
}

void WispController::setDaemon(bool available, const QString& message) {
    if (daemonAvailable_ == available && daemonMessage_ == message) return;
    daemonAvailable_ = available;
    daemonMessage_ = message;
    emit daemonChanged();
}

void WispController::setStatus(const QString& message, bool isError) {
    statusMessage_ = message;
    statusIsError_ = isError;
    emit statusChanged();
}

void WispController::setBusy(bool busy) {
    if (busy_ == busy) return;
    busy_ = busy;
    emit busyChanged();
}

void WispController::dismissStatus() {
    if (statusMessage_.isEmpty()) return;
    statusMessage_.clear();
    statusIsError_ = false;
    emit statusChanged();
}

void WispController::setActiveTunnel(const QString& name) {
    if (activeTunnel_ == name) return;
    activeTunnel_ = name;

    // Only reset the counters when the new selection is not the tunnel that is
    // already up, otherwise clicking down the list would blank live numbers.
    if (name != connectedTunnel_) {
        resetStats();
    }

    emit activeTunnelChanged();
    onPollTick();
}

void WispController::updatePollInterval() {
    const int desired = !uiActive_ ? kPollBackgroundMs
                                   : (connected_ ? kPollConnectedMs : kPollIdleMs);
    if (desired == pollIntervalMs_) return;

    pollIntervalMs_ = desired;
    if (pollTimer_) pollTimer_->setInterval(desired);
    emit pollIntervalChanged();
}

void WispController::setUiActive(bool active) {
    if (uiActive_ == active) return;
    uiActive_ = active;
    updatePollInterval();

    // Poll immediately on the way back in, so what the user sees is current
    // rather than up to a full background interval old.
    if (active) onPollTick();
}

void WispController::onPollTick() {
    // One request in flight at a time. If the helper is slow there is nothing
    // to gain by queueing the next sample on top of the last.
    if (!pending_.empty()) return;

    if (connected_ && !activeTunnel_.isEmpty()) {
        pollStats();
    } else {
        refresh();
    }
}

void WispController::refresh() {
    // PING is a reachability probe, and a probe is only interesting when there
    // is no connection yet to judge by. On an established socket a successful
    // LIST already proves the helper is answering, so sending a PING as well
    // would double the work of every idle poll - two round trips every second
    // and a half - to learn something the next request tells us anyway.
    //
    // The probe is still the first thing that happens, so the very first poll
    // distinguishes "helper is not running" from "helper answered badly",
    // which is what makes the empty-window message accurate rather than
    // guessing.
    if (socket_ != nullptr && socket_->state() == QLocalSocket::ConnectedState) {
        setDaemon(true, tr("helper connected"));
        refreshList();
        return;
    }

    send(verb_from_std_string(wisp::ipc::kPing), {}, [this](bool ok, const QString&) {
        if (!ok) {
            setDaemon(false, tr("helper not reachable"));
            return;
        }

        setDaemon(true, tr("helper connected"));
        refreshList();
    });
}

void WispController::refreshList() {
    send(verb_from_std_string(wisp::ipc::kList), {}, [this](bool listed, const QString& payload) {
        if (!listed) return;

        QStringList names;
        for (const auto& name : payload.split(QLatin1Char(','), Qt::SkipEmptyParts)) {
            names << name.trimmed();
        }
        if (names != tunnels_) {
            tunnels_ = names;
            // Scores are memory-only: drop anything whose profile went away so
            // a removed tunnel cannot stay "fastest" forever.
            bool pruned = false;
            for (auto it = tunnelScores_.begin(); it != tunnelScores_.end();) {
                if (!tunnels_.contains(it.key())) {
                    it = tunnelScores_.erase(it);
                    pruned = true;
                } else {
                    ++it;
                }
            }
            recomputeFastest();
            emit tunnelsChanged();
            if (pruned) emit scoresChanged();
        }

        // Keep the selection valid: pick something so the detail pane is
        // never empty, and drop a selection whose profile has gone away.
        if (!tunnels_.contains(activeTunnel_)) {
            const QString fallback = tunnels_.isEmpty() ? QString() : tunnels_.first();
            if (fallback != activeTunnel_) {
                activeTunnel_ = fallback;
                if (fallback != connectedTunnel_) resetStats();
                emit activeTunnelChanged();
            }
        }
    });
}

void WispController::connectTunnel(const QString& name) {
    if (name.isEmpty()) return;

    // Refuse to bring up a second tunnel while another is up. The helper's UP
    // is idempotent for one name, but it knows nothing about the others, so
    // connecting here would leave two sets of routes competing for the default
    // route. Failing loudly is better than silently reconfiguring routing under
    // a live tunnel.
    if (connected_ && !connectedTunnel_.isEmpty() && connectedTunnel_ != name) {
        setStatus(tr("%1 is still connected - disconnect it first").arg(connectedTunnel_), true);
        return;
    }

    setBusy(true);
    setStatus(tr("Bringing up %1...").arg(name), false);

    send(verb_from_std_string(wisp::ipc::kUp), name, [this, name](bool ok, const QString& payload) {
        setBusy(false);
        if (ok) {
            setStatus(tr("%1 is up").arg(name), false);
            activeTunnel_ = name;
            connectedTunnel_ = name;
            emit activeTunnelChanged();
            resetStats();
            updatePollInterval();
            pollStats();
        } else {
            setStatus(payload, true);
        }
    });
}

void WispController::disconnectTunnel(const QString& name) {
    if (name.isEmpty()) return;

    setBusy(true);
    setStatus(tr("Bringing down %1...").arg(name), false);

    send(verb_from_std_string(wisp::ipc::kDown), name,
         [this, name](bool ok, const QString& payload) {
             setBusy(false);
             if (ok) {
                 setStatus(tr("%1 is down").arg(name), false);
                 if (connectedTunnel_ == name) connectedTunnel_.clear();
                 resetStats();
                 updatePollInterval();
             } else {
                 setStatus(payload, true);
             }
         });
}

void WispController::toggleTunnel(const QString& name) {
    if (name.isEmpty()) return;
    if (connected_ && connectedTunnel_ == name) {
        disconnectTunnel(name);
    } else {
        connectTunnel(name);
    }
}

void WispController::resetStats() {
    connected_ = false;
    downloadRate_ = QStringLiteral("0 B/s");
    uploadRate_ = QStringLiteral("0 B/s");
    handshakeAge_ = QStringLiteral("--");
    peerCount_ = 0;
    listenPort_ = 0;
    lastRx_ = 0;
    lastTx_ = 0;
    lastSampleMs_ = 0;

    // Totals and history are reset too, so a new session never shows the
    // previous tunnel's numbers.
    totalReceived_ = QStringLiteral("0 B");
    totalSent_ = QStringLiteral("0 B");
    downloadHistory_.clear();
    uploadHistory_.clear();

    emit statsChanged();
    emit historyChanged();
}

void WispController::pollStats() {
    if (activeTunnel_.isEmpty()) return;

    send(verb_from_std_string(wisp::ipc::kStatus), activeTunnel_,
         [this](bool ok, const QString& payload) {
             if (!ok) {
                 if (connected_) {
                     connected_ = false;
                     connectedTunnel_.clear();
                     emit statsChanged();
                     updatePollInterval();
                 }
                 return;
             }
             applyStats(payload);
         });
}

void WispController::appendHistory(QVariantList& history, double value) {
    history.append(value);
    while (history.size() > kHistoryLength) history.removeFirst();
}

void WispController::applyStats(const QString& payload) {
    // Payload shape: "up peers=1 rx=123 tx=456 handshake=1700000000 listen_port=51820"
    const double rx = numeric_field(payload, "rx");
    const double tx = numeric_field(payload, "tx");
    const double handshake = numeric_field(payload, "handshake");

    const bool was_connected = connected_;
    connected_ = true;
    if (connectedTunnel_ != activeTunnel_) {
        connectedTunnel_ = activeTunnel_;
    }
    peerCount_ = static_cast<int>(numeric_field(payload, "peers"));
    listenPort_ = static_cast<int>(numeric_field(payload, "listen_port"));
    totalReceived_ = formatBytes(rx);
    totalSent_ = formatBytes(tx);

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (lastSampleMs_ != 0 && now > lastSampleMs_) {
        const double seconds = static_cast<double>(now - lastSampleMs_) / 1000.0;
        // Counters only move forward; a smaller reading means the tunnel was
        // restarted, in which case the delta is meaningless.
        const double rxDelta = rx >= static_cast<double>(lastRx_) ? rx - static_cast<double>(lastRx_) : 0.0;
        const double txDelta = tx >= static_cast<double>(lastTx_) ? tx - static_cast<double>(lastTx_) : 0.0;

        const double rxRate = rxDelta / seconds;
        const double txRate = txDelta / seconds;

        downloadRate_ = formatBytes(rxRate) + QStringLiteral("/s");
        uploadRate_ = formatBytes(txRate) + QStringLiteral("/s");

        appendHistory(downloadHistory_, rxRate);
        appendHistory(uploadHistory_, txRate);
        emit historyChanged();
    }

    lastRx_ = static_cast<std::uint64_t>(rx);
    lastTx_ = static_cast<std::uint64_t>(tx);
    lastSampleMs_ = now;

    if (handshake > 0) {
        const qint64 elapsed = QDateTime::currentSecsSinceEpoch() - static_cast<qint64>(handshake);
        if (elapsed < 0) {
            handshakeAge_ = tr("just now");
        } else if (elapsed < 60) {
            handshakeAge_ = tr("%1s ago").arg(elapsed);
        } else if (elapsed < 3600) {
            handshakeAge_ = tr("%1m ago").arg(elapsed / 60);
        } else {
            handshakeAge_ = tr("%1h ago").arg(elapsed / 3600);
        }
    } else {
        handshakeAge_ = tr("never");
    }

    emit statsChanged();
    if (!was_connected) updatePollInterval();

    const qint64 handshakeSecs = handshake > 0 ? static_cast<qint64>(handshake) : 0;
    const qint64 elapsedSecs =
        handshakeSecs > 0 ? (QDateTime::currentSecsSinceEpoch() - handshakeSecs) : -1;
    double rate = 0.0;
    if (!downloadHistory_.isEmpty()) rate = downloadHistory_.last().toDouble();
    if (!uploadHistory_.isEmpty()) rate = qMax(rate, uploadHistory_.last().toDouble());
    updateScores(activeTunnel_, rate, rate, elapsedSecs >= 0 ? static_cast<double>(elapsedSecs)
                                                             : -1.0);
}

// Theme list and fastest pick live here. Scores stay in memory only.

QStringList WispController::availableThemes() const {
    return {QStringLiteral("Midnight"), QStringLiteral("Glacier"), QStringLiteral("Forest"),
            QStringLiteral("Dusk"), QStringLiteral("Mono")};
}

QStringList WispController::availableAccents() const {
    return {QStringLiteral("Mint"), QStringLiteral("Sky"), QStringLiteral("Violet"),
            QStringLiteral("Amber"), QStringLiteral("Rose"), QStringLiteral("Cyan")};
}

void WispController::loadTheme() {
    QSettings settings(QStringLiteral("Wisp"), QStringLiteral("Wisp"));
    const QString theme = settings.value(QStringLiteral("themeName"), themeName_).toString();
    const QString accent = settings.value(QStringLiteral("accentName"), accentName_).toString();
    if (availableThemes().contains(theme)) themeName_ = theme;
    if (availableAccents().contains(accent)) accentName_ = accent;
}

void WispController::saveTheme() {
    QSettings settings(QStringLiteral("Wisp"), QStringLiteral("Wisp"));
    settings.setValue(QStringLiteral("themeName"), themeName_);
    settings.setValue(QStringLiteral("accentName"), accentName_);
}

void WispController::setThemeName(const QString& name) {
    if (!availableThemes().contains(name) || name == themeName_) return;
    themeName_ = name;
    saveTheme();
    emit themeChanged();
}

void WispController::setAccentName(const QString& name) {
    if (!availableAccents().contains(name) || name == accentName_) return;
    accentName_ = name;
    saveTheme();
    emit themeChanged();
}

void WispController::updateScores(const QString& name, double rxRate, double txRate,
                                  double handshakeElapsedSecs) {
    if (name.isEmpty()) return;
    const double throughput = qMax(rxRate, txRate);
    if (throughput > bestThroughput_.value(name, 0.0)) bestThroughput_[name] = throughput;

    double score = 0.0;
    if (handshakeElapsedSecs < 0) {
        score = qMin(20.0, 5.0 + bestThroughput_.value(name, 0.0) / 102400.0);
    } else if (handshakeElapsedSecs < 60) {
        score = 80.0;
    } else if (handshakeElapsedSecs < 300) {
        score = 60.0;
    } else if (handshakeElapsedSecs < 3600) {
        score = 40.0;
    } else {
        score = 20.0;
    }
    score += qMin(20.0, throughput / 51200.0);
    score = qBound(0.0, score, 100.0);

    if (!qFuzzyCompare(tunnelScores_.value(name, -1.0).toDouble(), score)) {
        tunnelScores_[name] = score;
        recomputeFastest();
        emit scoresChanged();
    }
}

void WispController::recomputeFastest() {
    QString best;
    double bestScore = -1.0;
    for (auto it = tunnelScores_.constBegin(); it != tunnelScores_.constEnd(); ++it) {
        if (!tunnels_.contains(it.key())) continue;
        if (it.value().toDouble() > bestScore) {
            bestScore = it.value().toDouble();
            best = it.key();
        }
    }
    if (best != fastestTunnel_) {
        fastestTunnel_ = best;
    }
}

void WispController::connectFastest() {
    if (busy_) return;
    if (tunnels_.isEmpty()) {
        setStatus(tr("No tunnels to race yet"), true);
        return;
    }
    QString pick = fastestTunnel_;
    if (pick.isEmpty() || !tunnels_.contains(pick)) pick = tunnels_.first();
    if (connected_ && connectedTunnel_ == pick) {
        setStatus(tr("Already on the fastest tunnel (%1)").arg(pick), false);
        return;
    }
    setActiveTunnel(pick);
    connectTunnel(pick);
}

QString WispController::scoreLabel(const QString& name) const {
    if (!tunnelScores_.contains(name)) return QStringLiteral("--");
    return QString::number(qRound(tunnelScores_.value(name).toDouble()));
}

void WispController::generateKeypair() {
    wisp::secure_wipe(privateKey_);
    privateKey_ = wisp::generate_private_key();
    generatedPublicKey_ = QString::fromStdString(wisp::public_key_from_private(privateKey_));
    emit keypairGenerated();
}

void WispController::clearKeypair() {
    wisp::secure_wipe(privateKey_);
    privateKey_.clear();
    generatedPublicKey_.clear();
    emit keypairGenerated();
}

void WispController::copyToClipboard(const QString& text) {
    if (auto* clipboard = QGuiApplication::clipboard()) {
        clipboard->setText(text);
        setStatus(tr("Copied to clipboard"), false);
        QTimer::singleShot(30000, this, [this, text]() {
            if (auto* clipboard = QGuiApplication::clipboard()) {
                if (clipboard->text() == text) clipboard->clear();
            }
        });
    }
}

QString WispController::formatBytes(double bytes) const {
    static const char* units[] = {"B", "KB", "MB", "GB", "TB"};

    int unit = 0;
    while (bytes >= 1024.0 && unit < 4) {
        bytes /= 1024.0;
        ++unit;
    }

    const int precision = (unit == 0 || bytes >= 100.0) ? 0 : 1;
    return QStringLiteral("%1 %2").arg(bytes, 0, 'f', precision).arg(QString::fromLatin1(units[unit]));
}
