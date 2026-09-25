import QtQuick
import QtQuick.Window

Window {
    id: root

    width: 1220
    height: 780
    minimumWidth: 1020
    minimumHeight: 680
    visible: true
    title: qsTr("Wisp")
    color: theme.background

    function syncActivity() {
        wisp.setUiActive(root.active && root.visibility !== Window.Minimized
                         && root.visibility !== Window.Hidden);
    }

    Component.onCompleted: syncActivity()
    onActiveChanged: syncActivity()
    onVisibilityChanged: syncActivity()

    readonly property bool hasTunnels: wisp.tunnels.length > 0

    Theme {
        id: theme
        name: wisp.themeName
        accent: wisp.accentName
    }

    Rectangle {
        anchors.fill: parent
        gradient: Gradient {
            GradientStop { position: 0.0; color: theme.background }
            GradientStop { position: 1.0; color: theme.backgroundEnd }
        }
    }

    Rectangle {
        width: 720
        height: 720
        radius: 360
        x: root.width - 460
        y: -400
        color: theme.violet
        opacity: 0.07
    }

    Sidebar {
        id: sidebar
        anchors.left: parent.left
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        width: 300

        controller: wisp
        panelColor: theme.panel
        cardColor: theme.card
        cardHoverColor: theme.cardHover
        borderColor: theme.border
        textColor: theme.text
        textDimColor: theme.textDim
        textFaintColor: theme.textFaint
        accentColor: theme.accentColor
        violetColor: theme.violet
    }

    Item {
        id: content
        anchors.left: sidebar.right
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.bottom: parent.bottom

        Column {
            id: stack
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            anchors.leftMargin: 34
            anchors.rightMargin: 34
            anchors.topMargin: 28
            spacing: 18

            Item {
                id: header
                width: stack.width
                height: 84

                Column {
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: 4

                    Text {
                        text: wisp.activeTunnel.length > 0
                              ? wisp.activeTunnel
                              : qsTr("No tunnel selected")
                        color: theme.text
                        font.pixelSize: 26
                        font.bold: true
                    }

                    Text {
                        text: wisp.activeTunnel.length === 0
                              ? qsTr("Add a profile to /etc/wisp/tunnels")
                              : (wisp.connected
                                 ? qsTr("Traffic is encrypted and flowing")
                                 : (wisp.fastestTunnel.length > 0 && wisp.fastestTunnel === wisp.activeTunnel
                                    ? qsTr("Fastest in your list · ready to connect")
                                    : qsTr("Ready to connect")))
                        color: theme.textDim
                        font.pixelSize: 13
                    }

                    Row {
                        spacing: 6

                        Repeater {
                            model: ["Local only", "No logs", "Fail-closed DNS"]
                            delegate: Rectangle {
                                height: 20
                                width: badgeLabel.width + 18
                                radius: 10
                                color: "transparent"
                                border.width: 1
                                border.color: theme.border

                                Text {
                                    id: badgeLabel
                                    anchors.centerIn: parent
                                    text: modelData
                                    color: theme.textFaint
                                    font.pixelSize: 10
                                    font.letterSpacing: 0.6
                                    font.capitalization: Font.AllUppercase
                                }
                            }
                        }
                    }
                }

                Row {
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: 10

                    Rectangle {
                        width: 34
                        height: 34
                        radius: 17
                        color: refreshArea.containsMouse ? theme.cardHover : theme.card
                        border.width: 1
                        border.color: theme.border

                        Behavior on color {
                            ColorAnimation { duration: 130 }
                        }

                        Text {
                            anchors.centerIn: parent
                            text: "\u21BB"
                            color: refreshArea.containsMouse ? theme.text : theme.textDim
                            font.pixelSize: 17
                        }

                        MouseArea {
                            id: refreshArea
                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: wisp.refresh()
                        }
                    }

                    Rectangle {
                        width: pill.width + 28
                        height: 32
                        radius: 16
                        color: theme.card
                        border.width: 1
                        border.color: theme.border

                        Row {
                            id: pill
                            anchors.centerIn: parent
                            spacing: 8

                            Rectangle {
                                width: 8
                                height: 8
                                radius: 4
                                anchors.verticalCenter: parent.verticalCenter
                                color: wisp.daemonAvailable ? theme.accentColor : theme.danger
                            }

                            Text {
                                anchors.verticalCenter: parent.verticalCenter
                                text: wisp.daemonMessage
                                color: theme.textDim
                                font.pixelSize: 12
                            }
                        }
                    }
                }
            }

            Item {
                id: hero
                width: stack.width
                height: 186

                ConnectButton {
                    id: connectButton
                    anchors.left: parent.left
                    anchors.leftMargin: 4
                    anchors.verticalCenter: parent.verticalCenter
                    connected: wisp.connected
                    busy: wisp.busy
                    enabled: wisp.activeTunnel.length > 0
                    accentColor: theme.accentColor
                    idleColor: theme.violet
                    trackColor: theme.border
                    onClicked: wisp.toggleTunnel(wisp.activeTunnel)
                }

                Text {
                    anchors.horizontalCenter: connectButton.horizontalCenter
                    anchors.top: connectButton.bottom
                    anchors.topMargin: 6
                    text: wisp.busy ? qsTr("Working")
                                    : (wisp.connected ? qsTr("Disconnect") : qsTr("Connect"))
                    color: wisp.busy ? theme.violet : theme.textDim
                    font.pixelSize: 11
                    font.letterSpacing: 1.1
                    font.capitalization: Font.AllUppercase
                }

                StatCard {
                    id: downloadCard
                    anchors.left: connectButton.right
                    anchors.leftMargin: 34
                    anchors.verticalCenter: parent.verticalCenter
                    width: (hero.width - connectButton.width - 34 - 12) / 2
                    label: qsTr("Download")
                    value: wisp.downloadRate
                    caption: wisp.totalReceived + qsTr(" received")
                    accentColor: theme.blue
                    cardColor: theme.card
                    borderColor: theme.border
                    textColor: theme.text
                    textDimColor: theme.textDim
                }

                StatCard {
                    anchors.left: downloadCard.right
                    anchors.leftMargin: 12
                    anchors.verticalCenter: parent.verticalCenter
                    width: downloadCard.width
                    label: qsTr("Upload")
                    value: wisp.uploadRate
                    caption: wisp.totalSent + qsTr(" sent")
                    accentColor: theme.accentColor
                    cardColor: theme.card
                    borderColor: theme.border
                    textColor: theme.text
                    textDimColor: theme.textDim
                }
            }

            ThroughputGraph {
                width: stack.width
                height: 164
                download: wisp.downloadHistory
                upload: wisp.uploadHistory
                downloadColor: theme.blue
                uploadColor: theme.accentColor
                gridColor: theme.border
                surfaceColor: theme.surface
            }

            Row {
                id: details
                width: stack.width
                spacing: 12

                StatCard {
                    width: (details.width - 24) / 3
                    height: 96
                    label: qsTr("Peers")
                    value: String(wisp.peerCount)
                    caption: qsTr("configured in this tunnel")
                    accentColor: theme.violet
                    cardColor: theme.card
                    borderColor: theme.border
                    textColor: theme.text
                    textDimColor: theme.textDim
                }

                StatCard {
                    width: (details.width - 24) / 3
                    height: 96
                    label: qsTr("Handshake")
                    value: wisp.handshakeAge
                    caption: qsTr("most recent with a peer")
                    accentColor: theme.blue
                    cardColor: theme.card
                    borderColor: theme.border
                    textColor: theme.text
                    textDimColor: theme.textDim
                }

                StatCard {
                    width: (details.width - 24) / 3
                    height: 96
                    label: qsTr("Listening")
                    value: wisp.listenPort > 0 ? String(wisp.listenPort) : "--"
                    caption: qsTr("WireGuard port reported by the kernel")
                    accentColor: theme.accentColor
                    cardColor: theme.card
                    borderColor: theme.border
                    textColor: theme.text
                    textDimColor: theme.textDim
                }
            }

            Text {
                width: stack.width
                wrapMode: Text.WordWrap
                color: theme.textFaint
                font.pixelSize: 11
                lineHeight: 1.4
                text: qsTr("Fastest is memory-only: it ranks tunnels you already configured by live handshake and throughput. No probing, no downloads, no telemetry. Free server lists are hostile by default, so import profiles by hand and check them with --dry-run.")
            }
        }

        Rectangle {
            anchors.fill: parent
            anchors.margins: 34
            visible: !root.hasTunnels
            color: theme.card
            radius: 14
            border.width: 1
            border.color: theme.border

            Column {
                anchors.centerIn: parent
                width: Math.min(parent.width - 80, 540)
                spacing: 12

                Text {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: qsTr("No profiles yet")
                    color: theme.text
                    font.pixelSize: 20
                    font.bold: true
                }

                Text {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: qsTr("A Satin Networks opsec project")
                    color: theme.textFaint
                    font.pixelSize: 11
                    font.letterSpacing: 1.1
                    font.capitalization: Font.AllUppercase
                }

                Text {
                    width: parent.width
                    horizontalAlignment: Text.AlignHCenter
                    wrapMode: Text.WordWrap
                    color: theme.textDim
                    font.pixelSize: 13
                    lineHeight: 1.4
                    text: qsTr("Wisp reads wg-quick profiles from a directory only root can write. Put one there, then press refresh. To use free servers, download their .conf files yourself. Wisp never fetches lists on its own.")
                }

                Rectangle {
                    anchors.horizontalCenter: parent.horizontalCenter
                    width: command.width + 32
                    height: 34
                    radius: 8
                    color: theme.surface
                    border.width: 1
                    border.color: theme.border

                    Text {
                        id: command
                        anchors.centerIn: parent
                        text: "sudo cp home.conf /etc/wisp/tunnels/ && sudo chmod 600 /etc/wisp/tunnels/*.conf"
                        color: theme.accentColor
                        font.pixelSize: 11
                        font.family: "monospace"
                    }
                }

                Text {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: qsTr("Check first: wispd --dry-run --fail-closed. Free VPNs log, inject ads, or exit maliciously. Paid audited providers beat any free list on opsec.")
                    width: parent.width
                    horizontalAlignment: Text.AlignHCenter
                    wrapMode: Text.WordWrap
                    color: theme.textFaint
                    font.pixelSize: 11
                }
            }
        }

        Text {
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            anchors.rightMargin: 34
            anchors.bottomMargin: 10
            text: qsTr("wisp %1  ·  %2  ·  poll %3 ms")
                  .arg(wisp.version).arg(wisp.socketPath).arg(wisp.pollInterval)
            color: theme.textFaint
            font.pixelSize: 10
        }

        Rectangle {
            id: toast
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.bottom: parent.bottom
            anchors.bottomMargin: 26
            width: toastText.width + 56
            height: 42
            radius: 21
            visible: wisp.statusMessage.length > 0
            color: wisp.statusIsError ? "#2A1720" : "#13251C"
            border.width: 1
            border.color: wisp.statusIsError ? "#5B2A34" : "#245237"

            opacity: visible ? 1 : 0
            Behavior on opacity {
                NumberAnimation { duration: 180 }
            }

            Text {
                id: toastText
                anchors.centerIn: parent
                text: wisp.statusMessage
                color: wisp.statusIsError ? "#F8B4B4" : "#A7F3C8"
                font.pixelSize: 12
            }

            MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: wisp.dismissStatus()
            }
        }

        Timer {
            id: toastTimer
            interval: 4500
            onTriggered: wisp.dismissStatus()
        }

        Connections {
            target: wisp
            function onStatusChanged() {
                if (wisp.statusMessage.length > 0) toastTimer.restart();
            }
        }
    }
}
