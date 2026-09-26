#pragma once

#include <QByteArray>
#include <QObject>
#include <QSettings>
#include <QString>
#include <QStringList>
#include <QVariantList>
#include <QVariantMap>

#include <cstdint>
#include <deque>
#include <functional>
#include <string>

class QLocalSocket;
class QTimer;

// Bridges the unprivileged UI to the privileged helper.
//
// What this class cannot do is the point: no netlink, no reading the config
// directory, never sending configuration to the helper. It can only ask for a
// tunnel by name. Everything privileged stays on the far side of the socket.
class WispController : public QObject {
    Q_OBJECT

    Q_PROPERTY(QStringList tunnels READ tunnels NOTIFY tunnelsChanged)
    Q_PROPERTY(QString activeTunnel READ activeTunnel WRITE setActiveTunnel NOTIFY activeTunnelChanged)

    Q_PROPERTY(bool connected READ connected NOTIFY statsChanged)
    // Which tunnel is actually carrying traffic, which is not necessarily the
    // one selected in the sidebar. Without this the list would show a green dot
    // next to whatever row you clicked rather than the one that is up.
    Q_PROPERTY(QString connectedTunnel READ connectedTunnel NOTIFY statsChanged)
    Q_PROPERTY(bool daemonAvailable READ daemonAvailable NOTIFY daemonChanged)
    Q_PROPERTY(QString daemonMessage READ daemonMessage NOTIFY daemonChanged)
    Q_PROPERTY(QString socketPath READ socketPath CONSTANT)
    Q_PROPERTY(QString version READ version CONSTANT)

    // True while a connect or disconnect is in flight, so the UI can stop
    // accepting a second click before the first one has finished.
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)

    Q_PROPERTY(QString statusMessage READ statusMessage NOTIFY statusChanged)
    Q_PROPERTY(bool statusIsError READ statusIsError NOTIFY statusChanged)

    Q_PROPERTY(QString downloadRate READ downloadRate NOTIFY statsChanged)
    Q_PROPERTY(QString uploadRate READ uploadRate NOTIFY statsChanged)
    Q_PROPERTY(QString totalReceived READ totalReceived NOTIFY statsChanged)
    Q_PROPERTY(QString totalSent READ totalSent NOTIFY statsChanged)
    Q_PROPERTY(QString handshakeAge READ handshakeAge NOTIFY statsChanged)
    Q_PROPERTY(int peerCount READ peerCount NOTIFY statsChanged)
    Q_PROPERTY(int listenPort READ listenPort NOTIFY statsChanged)
    Q_PROPERTY(int pollInterval READ pollInterval NOTIFY pollIntervalChanged)

    Q_PROPERTY(QVariantList downloadHistory READ downloadHistory NOTIFY historyChanged)
    Q_PROPERTY(QVariantList uploadHistory READ uploadHistory NOTIFY historyChanged)

    // Theme is the only thing persisted to disk (QSettings, org Wisp).
    // No tunnel history, no scores, no keys: the fastest pick is recomputed
    // from live stats each run, so there is no activity timeline to subpoena.
    Q_PROPERTY(QStringList availableThemes READ availableThemes CONSTANT)
    Q_PROPERTY(QString themeName READ themeName WRITE setThemeName NOTIFY themeChanged)
    Q_PROPERTY(QStringList availableAccents READ availableAccents CONSTANT)
    Q_PROPERTY(QString accentName READ accentName WRITE setAccentName NOTIFY themeChanged)

    // In-memory only, never written: name -> 0..100 score from the most recent
    // handshake and throughput sample. Disconnected tunnels score 0.
    Q_PROPERTY(QVariantMap tunnelScores READ tunnelScores NOTIFY scoresChanged)
    Q_PROPERTY(QString fastestTunnel READ fastestTunnel NOTIFY scoresChanged)

    // Only the public key is exposed as a property. The private key lives in a
    // std::string so it can be wiped with sodium_memzero; a QString would be
    // implicitly shared and copied, leaving copies of the secret behind.
    Q_PROPERTY(QString generatedPublicKey READ generatedPublicKey NOTIFY keypairGenerated)
    Q_PROPERTY(bool hasKeypair READ hasKeypair NOTIFY keypairGenerated)

  public:
    explicit WispController(QString socketPath = {}, QObject* parent = nullptr);
    ~WispController() override;

    QStringList tunnels() const { return tunnels_; }
    QString activeTunnel() const { return activeTunnel_; }
    void setActiveTunnel(const QString& name);

    bool connected() const { return connected_; }
    QString connectedTunnel() const { return connectedTunnel_; }
    bool daemonAvailable() const { return daemonAvailable_; }
    QString daemonMessage() const { return daemonMessage_; }
    QString socketPath() const { return socketPath_; }
    QString version() const;

    bool busy() const { return busy_; }

    QString statusMessage() const { return statusMessage_; }
    bool statusIsError() const { return statusIsError_; }

    QString downloadRate() const { return downloadRate_; }
    QString uploadRate() const { return uploadRate_; }
    QString totalReceived() const { return totalReceived_; }
    QString totalSent() const { return totalSent_; }
    QString handshakeAge() const { return handshakeAge_; }
    int peerCount() const { return peerCount_; }
    int listenPort() const { return listenPort_; }
    int pollInterval() const { return pollIntervalMs_; }

    QVariantList downloadHistory() const { return downloadHistory_; }
    QVariantList uploadHistory() const { return uploadHistory_; }

    QStringList availableThemes() const;
    QString themeName() const { return themeName_; }
    void setThemeName(const QString& name);
    QStringList availableAccents() const;
    QString accentName() const { return accentName_; }
    void setAccentName(const QString& name);

    QVariantMap tunnelScores() const { return tunnelScores_; }
    QString fastestTunnel() const { return fastestTunnel_; }
    Q_INVOKABLE void connectFastest();
    Q_INVOKABLE QString scoreLabel(const QString& name) const;

    QString generatedPublicKey() const { return generatedPublicKey_; }

    // The private key, converted on demand. Never cached, so there is exactly
    // one long-lived copy in the process and it can be wiped.
    Q_INVOKABLE QString generatedPrivateKey() const;
    bool hasKeypair() const { return !privateKey_.empty(); }

    // Attempts to reach the helper, and reloads the tunnel list if it answers.
    Q_INVOKABLE void refresh();
    Q_INVOKABLE void connectTunnel(const QString& name);
    Q_INVOKABLE void disconnectTunnel(const QString& name);
    Q_INVOKABLE void toggleTunnel(const QString& name);
    Q_INVOKABLE void generateKeypair();
    Q_INVOKABLE void clearKeypair();
    Q_INVOKABLE void copyToClipboard(const QString& text);
    Q_INVOKABLE void dismissStatus();

    // Tells the controller whether the window is frontmost and visible.
    //
    // Polling exists to refresh numbers nobody is looking at when the window is
    // hidden, so the interval backs off rather than doing the same work at the
    // same rate in the background. Coming back to the front polls immediately,
    // so the numbers are never stale when they are actually on screen.
    Q_INVOKABLE void setUiActive(bool active);

    Q_INVOKABLE QString formatBytes(double bytes) const;

  signals:
    void tunnelsChanged();
    void activeTunnelChanged();
    void daemonChanged();
    void statusChanged();
    void statsChanged();
    void historyChanged();
    void keypairGenerated();
    void busyChanged();
    void pollIntervalChanged();
    void themeChanged();
    void scoresChanged();

  private:
    struct PendingRequest {
        QByteArray line;
        std::function<void(bool, const QString&)> handler;
    };

    void send(const QString& verb, const QString& argument,
              std::function<void(bool, const QString&)> handler);
    void ensureSocket();
    void pumpWrites();
    void onReadyRead();
    void onDisconnected();
    void failAllPending(const QString& reason);
    void armWatchdog();

    void onPollTick();
    void refreshList();
    void updatePollInterval();

    void setStatus(const QString& message, bool isError);
    void setDaemon(bool available, const QString& message);
    void setBusy(bool busy);
    void pollStats();
    void applyStats(const QString& payload);
    void resetStats();
    void appendHistory(QVariantList& history, double value);

    QString socketPath_;
    QStringList tunnels_;
    QString activeTunnel_;
    QString connectedTunnel_;

    bool connected_ = false;
    bool daemonAvailable_ = false;
    QString daemonMessage_ = QStringLiteral("checking for the helper...");

    bool busy_ = false;

    QString statusMessage_;
    bool statusIsError_ = false;

    QString downloadRate_;
    QString uploadRate_;
    QString totalReceived_;
    QString totalSent_;
    QString handshakeAge_;
    int peerCount_ = 0;
    int listenPort_ = 0;

    std::uint64_t lastRx_ = 0;
    std::uint64_t lastTx_ = 0;
    qint64 lastSampleMs_ = 0;

    QVariantList downloadHistory_;
    QVariantList uploadHistory_;

    // One long-lived connection, reused for every request.
    //
    // Opening a socket per request meant a connect/accept round trip several
    // times a second purely to read byte counters. The helper now keeps the
    // connection open, so a poll is one write and one read.
    QLocalSocket* socket_ = nullptr;
    QByteArray readBuffer_;
    std::deque<PendingRequest> pending_;
    qsizetype sentCount_ = 0;

    // Wiped with sodium_memzero when cleared or on destruction.
    std::string privateKey_;
    QString generatedPublicKey_;

    QString themeName_ = QStringLiteral("Midnight");
    QString accentName_ = QStringLiteral("Mint");
    QVariantMap tunnelScores_;
    QString fastestTunnel_;
    QMap<QString, double> bestThroughput_;

    void loadTheme();
    void saveTheme();
    void updateScores(const QString& name, double rxRate, double txRate, double handshake);
    void recomputeFastest();

    QTimer* pollTimer_ = nullptr;
    QTimer* watchdog_ = nullptr;

    int pollIntervalMs_ = 0;
    bool uiActive_ = true;
};
