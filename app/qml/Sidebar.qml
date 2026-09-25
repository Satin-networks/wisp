import QtQuick

Rectangle {
    id: sidebar

    property var controller

    property color panelColor: "#111624"
    property color cardColor: "#161C2B"
    property color cardHoverColor: "#1B2233"
    property color borderColor: "#242D40"
    property color textColor: "#E9EDF5"
    property color textDimColor: "#7F8AA3"
    property color textFaintColor: "#5A6478"
    property color accentColor: "#4ADE80"
    property color violetColor: "#7C5CFF"

    property string searchText: ""
    property string sortMode: "Name"

    color: panelColor

    function displayTunnels() {
        if (!sidebar.controller) return [];
        var names = sidebar.controller.tunnels.slice();
        if (sidebar.searchText.length > 0) {
            var needle = sidebar.searchText.toLowerCase();
            names = names.filter(function (n) { return n.toLowerCase().indexOf(needle) >= 0; });
        }
        if (sidebar.sortMode === "Fastest" && sidebar.controller.tunnelScores) {
            var scores = sidebar.controller.tunnelScores;
            names.sort(function (a, b) {
                var sa = scores[a] !== undefined ? scores[a] : -1;
                var sb = scores[b] !== undefined ? scores[b] : -1;
                if (sa !== sb) return sb - sa;
                var al = a.toLowerCase(), bl = b.toLowerCase();
                return al < bl ? -1 : (al > bl ? 1 : 0);
            });
        } else {
            names.sort(function (a, b) {
                var al = a.toLowerCase(), bl = b.toLowerCase();
                return al < bl ? -1 : (al > bl ? 1 : 0);
            });
        }
        return names;
    }

    Rectangle {
        anchors.right: parent.right
        width: 1
        height: parent.height
        color: sidebar.borderColor
    }

    Item {
        id: header
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.leftMargin: 22
        anchors.rightMargin: 22
        anchors.topMargin: 22
        height: 34

        Row {
            anchors.verticalCenter: parent.verticalCenter
            spacing: 11

            Rectangle {
                width: 32
                height: 32
                radius: 10
                color: sidebar.violetColor

                Text {
                    anchors.centerIn: parent
                    text: "W"
                    color: "#0A0D14"
                    font.pixelSize: 17
                    font.bold: true
                }
            }

            Column {
                anchors.verticalCenter: parent.verticalCenter
                spacing: 1

                Text {
                    text: "Wisp"
                    color: sidebar.textColor
                    font.pixelSize: 17
                    font.bold: true
                }
                Text {
                    text: qsTr("local wireguard")
                    color: sidebar.textFaintColor
                    font.pixelSize: 11
                }
            }
        }
    }

    Item {
        id: searchBox
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: header.bottom
        anchors.leftMargin: 18
        anchors.rightMargin: 18
        anchors.topMargin: 14
        height: 34

        Rectangle {
            anchors.fill: parent
            radius: 9
            color: sidebar.cardColor
            border.width: 1
            border.color: searchInput.activeFocus ? sidebar.accentColor : sidebar.borderColor
        }

        Text {
            anchors.left: parent.left
            anchors.leftMargin: 12
            anchors.verticalCenter: parent.verticalCenter
            visible: searchInput.text.length === 0
            text: qsTr("Search tunnels")
            color: sidebar.textFaintColor
            font.pixelSize: 12
        }

        TextInput {
            id: searchInput
            anchors.left: parent.left
            anchors.right: clearButton.left
            anchors.leftMargin: 12
            anchors.rightMargin: 4
            anchors.verticalCenter: parent.verticalCenter
            color: sidebar.textColor
            font.pixelSize: 13
            clip: true
            onTextChanged: sidebar.searchText = text
        }

        Text {
            id: clearButton
            anchors.right: parent.right
            anchors.rightMargin: 10
            anchors.verticalCenter: parent.verticalCenter
            visible: searchInput.text.length > 0
            text: "×"
            color: sidebar.textDimColor
            font.pixelSize: 16

            MouseArea {
                anchors.fill: parent
                anchors.margins: -6
                cursorShape: Qt.PointingHandCursor
                onClicked: searchInput.clear()
            }
        }
    }

    Item {
        id: sectionRow
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: searchBox.bottom
        anchors.leftMargin: 22
        anchors.rightMargin: 22
        anchors.topMargin: 12
        height: 26

        Text {
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            text: qsTr("Tunnels")
            color: sidebar.textFaintColor
            font.pixelSize: 10
            font.letterSpacing: 1.4
            font.capitalization: Font.AllUppercase
        }

        Row {
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            spacing: 6

            Repeater {
                model: ["Name", "Fastest"]
                delegate: Rectangle {
                    width: sortLabel.width + 16
                    height: 22
                    radius: 11
                    color: sidebar.sortMode === modelData ? sidebar.cardHoverColor : "transparent"
                    border.width: 1
                    border.color: sidebar.sortMode === modelData ? sidebar.borderColor : "transparent"

                    Text {
                        id: sortLabel
                        anchors.centerIn: parent
                        text: modelData
                        color: sidebar.sortMode === modelData ? sidebar.textColor : sidebar.textFaintColor
                        font.pixelSize: 10
                        font.bold: sidebar.sortMode === modelData
                    }

                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: sidebar.sortMode = modelData
                    }
                }
            }
        }
    }

    Rectangle {
        id: fastestButton
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: sectionRow.bottom
        anchors.leftMargin: 18
        anchors.rightMargin: 18
        anchors.topMargin: 4
        height: 38
        radius: 10
        color: fastestMouse.containsMouse ? sidebar.accentColor : "transparent"
        border.width: 1
        border.color: sidebar.accentColor
        visible: sidebar.controller ? sidebar.controller.tunnels.length > 1 : false

        Text {
            anchors.centerIn: parent
            text: {
                if (!sidebar.controller) return qsTr("Connect fastest");
                if (sidebar.controller.fastestTunnel.length > 0)
                    return qsTr("Connect fastest · %1").arg(sidebar.controller.fastestTunnel);
                return qsTr("Connect fastest");
            }
            color: fastestMouse.containsMouse ? "#0A0D14" : sidebar.accentColor
            font.pixelSize: 12
            font.bold: true
            elide: Text.ElideRight
            width: parent.width - 24
            horizontalAlignment: Text.AlignHCenter
        }

        MouseArea {
            id: fastestMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: {
                if (sidebar.controller) sidebar.controller.connectFastest();
            }
        }
    }

    ListView {
        id: list
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: fastestButton.visible ? fastestButton.bottom : sectionRow.bottom
        anchors.bottom: footer.top
        anchors.leftMargin: 14
        anchors.rightMargin: 14
        anchors.topMargin: 8
        anchors.bottomMargin: 12
        clip: true
        spacing: 4
        model: displayTunnels()

        delegate: Rectangle {
            id: row

            readonly property bool highlighted: sidebar.controller
                                                && modelData === sidebar.controller.activeTunnel
            readonly property bool running: sidebar.controller
                                            && modelData === sidebar.controller.connectedTunnel
            readonly property bool isFastest: sidebar.controller
                                              && modelData === sidebar.controller.fastestTunnel
                                              && !row.running

            width: list.width
            height: 56
            radius: 10
            color: highlighted || mouse.containsMouse ? sidebar.cardHoverColor : "transparent"
            border.width: highlighted ? 1 : 0
            border.color: sidebar.borderColor

            Behavior on color {
                ColorAnimation { duration: 130 }
            }

            Item {
                id: dot
                width: 8
                height: 8
                x: 15
                anchors.verticalCenter: parent.verticalCenter

                Rectangle {
                    anchors.centerIn: parent
                    width: 16
                    height: 16
                    radius: 8
                    color: sidebar.accentColor
                    opacity: row.running ? 0.22 : 0.0

                    Behavior on opacity {
                        NumberAnimation { duration: 200 }
                    }
                }

                Rectangle {
                    anchors.fill: parent
                    radius: 4
                    color: row.running ? sidebar.accentColor : sidebar.textFaintColor

                    Behavior on color {
                        ColorAnimation { duration: 200 }
                    }
                }
            }

            Column {
                anchors.left: dot.right
                anchors.leftMargin: 12
                anchors.right: scoreBadge.left
                anchors.rightMargin: 8
                anchors.verticalCenter: parent.verticalCenter
                spacing: 2

                Text {
                    width: parent.width
                    text: modelData
                    color: row.highlighted ? sidebar.textColor : sidebar.textDimColor
                    font.pixelSize: 14
                    font.bold: row.highlighted
                    elide: Text.ElideRight
                }

                Text {
                    visible: row.isFastest
                    text: qsTr("FASTEST")
                    color: sidebar.accentColor
                    font.pixelSize: 9
                    font.bold: true
                    font.letterSpacing: 1.2
                }
            }

            Rectangle {
                id: scoreBadge
                anchors.right: parent.right
                anchors.rightMargin: 12
                anchors.verticalCenter: parent.verticalCenter
                width: 34
                height: 22
                radius: 11
                visible: sidebar.controller && sidebar.controller.tunnelScores[modelData] !== undefined
                color: "transparent"
                border.width: 1
                border.color: sidebar.borderColor

                Text {
                    anchors.centerIn: parent
                    text: sidebar.controller ? sidebar.controller.scoreLabel(modelData) : ""
                    color: sidebar.textFaintColor
                    font.pixelSize: 10
                    font.family: "monospace"
                }
            }

            MouseArea {
                id: mouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: sidebar.controller.activeTunnel = modelData
            }
        }
    }

    Text {
        anchors.centerIn: list
        visible: list.count === 0
        text: sidebar.searchText.length > 0 ? qsTr("No matches") : qsTr("No profiles found")
        color: sidebar.textFaintColor
        font.pixelSize: 12
    }

    Rectangle {
        id: footer
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.leftMargin: 18
        anchors.rightMargin: 18
        anchors.bottomMargin: 18
        height: 236
        radius: 12
        color: sidebar.cardColor
        border.width: 1
        border.color: sidebar.borderColor

        Column {
            anchors.fill: parent
            anchors.margins: 14
            spacing: 8

            Text {
                text: qsTr("Keypair")
                color: sidebar.textFaintColor
                font.pixelSize: 10
                font.letterSpacing: 1.3
                font.capitalization: Font.AllUppercase
            }

            Text {
                width: parent.width
                visible: sidebar.controller ? sidebar.controller.hasKeypair : false
                text: sidebar.controller ? sidebar.controller.generatedPublicKey : ""
                color: sidebar.accentColor
                font.pixelSize: 10
                font.family: "monospace"
                elide: Text.ElideMiddle
            }

            Text {
                width: parent.width
                visible: sidebar.controller ? !sidebar.controller.hasKeypair : true
                text: qsTr("Generate a keypair to register a new peer.")
                color: sidebar.textFaintColor
                font.pixelSize: 11
                wrapMode: Text.WordWrap
            }

            Row {
                spacing: 8

                Rectangle {
                    width: 104
                    height: 30
                    radius: 8
                    color: generateMouse.containsMouse ? "#8E72FF" : sidebar.violetColor

                    Behavior on color {
                        ColorAnimation { duration: 130 }
                    }

                    Text {
                        anchors.centerIn: parent
                        text: sidebar.controller && sidebar.controller.hasKeypair
                              ? qsTr("Regenerate")
                              : qsTr("Generate")
                        color: "#0A0D14"
                        font.pixelSize: 12
                        font.bold: true
                    }

                    MouseArea {
                        id: generateMouse
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: sidebar.controller.generateKeypair()
                    }
                }

                Rectangle {
                    width: 104
                    height: 30
                    radius: 8
                    color: "transparent"
                    border.width: 1
                    border.color: copyMouse.containsMouse ? sidebar.accentColor : sidebar.borderColor
                    visible: sidebar.controller ? sidebar.controller.hasKeypair : false

                    Text {
                        anchors.centerIn: parent
                        text: qsTr("Copy key")
                        color: sidebar.textDimColor
                        font.pixelSize: 12
                    }

                    MouseArea {
                        id: copyMouse
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: sidebar.controller.copyToClipboard(sidebar.controller.generatedPublicKey)
                    }
                }
            }

            Text {
                text: qsTr("Theme")
                color: sidebar.textFaintColor
                font.pixelSize: 10
                font.letterSpacing: 1.3
                font.capitalization: Font.AllUppercase
            }

            Row {
                spacing: 8

                Repeater {
                    model: sidebar.controller ? sidebar.controller.availableThemes : []
                    delegate: Rectangle {
                        width: 22
                        height: 22
                        radius: 11
                        color: {
                            if (modelData === "Glacier") return "#E9EFF7";
                            if (modelData === "Forest") return "#16241D";
                            if (modelData === "Dusk") return "#241B26";
                            if (modelData === "Mono") return "#333333";
                            return "#1B2233";
                        }
                        border.width: sidebar.controller && sidebar.controller.themeName === modelData ? 2 : 1
                        border.color: sidebar.controller && sidebar.controller.themeName === modelData
                                      ? sidebar.accentColor : sidebar.borderColor

                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: sidebar.controller.themeName = modelData
                        }
                    }
                }
            }

            Row {
                spacing: 8

                Repeater {
                    model: sidebar.controller ? sidebar.controller.availableAccents : []
                    delegate: Rectangle {
                        width: 18
                        height: 18
                        radius: 9
                        color: {
                            if (modelData === "Sky") return "#38BDF8";
                            if (modelData === "Violet") return "#8B5CF6";
                            if (modelData === "Amber") return "#FBBF24";
                            if (modelData === "Rose") return "#FB7185";
                            if (modelData === "Cyan") return "#22D3EE";
                            return "#4ADE80";
                        }
                        border.width: sidebar.controller && sidebar.controller.accentName === modelData ? 2 : 1
                        border.color: sidebar.controller && sidebar.controller.accentName === modelData
                                      ? sidebar.textColor : sidebar.borderColor

                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: sidebar.controller.accentName = modelData
                        }
                    }
                }
            }
        }
    }
}
