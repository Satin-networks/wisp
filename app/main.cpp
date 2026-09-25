#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QUrl>

#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wispcontroller.h"

int main(int argc, char** argv) {
    ::umask(077);
    rlimit no_core{};
    no_core.rlim_cur = 0;
    no_core.rlim_max = 0;
    ::setrlimit(RLIMIT_CORE, &no_core);
    ::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    QGuiApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("Wisp"));
    app.setApplicationDisplayName(QStringLiteral("Wisp"));
    app.setOrganizationName(QStringLiteral("Wisp"));

    // --socket lets the UI be pointed at a test daemon; otherwise the
    // controller falls back to WISP_SOCKET or the system default.
    QString socketPath;
    const QStringList arguments = app.arguments();
    for (int i = 1; i < arguments.size(); ++i) {
        if (arguments[i] == QStringLiteral("--socket") && i + 1 < arguments.size()) {
            socketPath = arguments[++i];
        }
    }

    WispController controller(socketPath);

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty(QStringLiteral("wisp"), &controller);

    QObject::connect(
        &engine, &QQmlApplicationEngine::objectCreationFailed, &app,
        []() { QCoreApplication::exit(1); }, Qt::QueuedConnection);

    engine.load(QUrl(QStringLiteral("qrc:/qml/Main.qml")));
    if (engine.rootObjects().isEmpty()) return 1;

    return app.exec();
}
