import QtQuick

// The primary action: one big target that toggles the tunnel.
//
// The colour and the pulsing halo are the whole status language - a glance is
// enough to know whether traffic is encrypted, which matters more than any
// label on screen. The spinner replaces the halo while a request is in flight,
// so "nothing happened yet" never looks like "nothing is happening".
Item {
    id: control

    property bool connected: false
    property bool enabled: true
    property bool busy: false
    property color accentColor: "#4ADE80"
    property color idleColor: "#7C5CFF"
    property color trackColor: "#242D40"
    property color glyphColor: "#0A0D14"

    signal clicked()

    width: 168
    height: 168

    readonly property bool interactive: enabled && !busy
    readonly property color activeColor: !enabled ? "#3A4256"
                                                  : (connected ? accentColor : idleColor)

    // Halo: only animates while connected, so the UI is calm when idle.
    Rectangle {
        id: halo
        anchors.centerIn: parent
        width: 148
        height: 148
        radius: 74
        color: "transparent"
        border.width: 2
        border.color: control.activeColor
        opacity: 0
        scale: 0.82
    }

    SequentialAnimation {
        running: control.connected && control.enabled && !control.busy
        loops: Animation.Infinite

        ParallelAnimation {
            NumberAnimation {
                target: halo
                property: "scale"
                from: 0.82
                to: 1.16
                duration: 1900
                easing.type: Easing.OutCubic
            }
            NumberAnimation {
                target: halo
                property: "opacity"
                from: 0.45
                to: 0.0
                duration: 1900
                easing.type: Easing.OutCubic
            }
        }
    }

    Rectangle {
        anchors.centerIn: parent
        width: 152
        height: 152
        radius: 76
        color: "transparent"
        border.width: 1
        border.color: control.trackColor
    }

    Rectangle {
        id: core
        anchors.centerIn: parent
        width: 126
        height: 126
        radius: 63
        color: control.activeColor

        Behavior on color {
            ColorAnimation {
                duration: 320
                easing.type: Easing.InOutQuad
            }
        }

        // Top-light sheen for depth.
        Rectangle {
            anchors.fill: parent
            radius: parent.radius
            gradient: Gradient {
                GradientStop { position: 0.0; color: "#38FFFFFF" }
                GradientStop { position: 0.48; color: "#00FFFFFF" }
                GradientStop { position: 1.0; color: "#30000000" }
            }
        }

        // Power glyph: a ring with a stem breaking through it.
        Item {
            anchors.centerIn: parent
            width: 44
            height: 44
            visible: !control.busy

            Rectangle {
                anchors.horizontalCenter: parent.horizontalCenter
                y: -4
                width: 5
                height: 22
                radius: 2.5
                color: control.glyphColor
            }

            Rectangle {
                anchors.horizontalCenter: parent.horizontalCenter
                anchors.bottom: parent.bottom
                width: 34
                height: 34
                radius: 17
                color: "transparent"
                border.width: 5
                border.color: control.glyphColor
            }
        }

        // Spinner: an open arc that turns while a request is outstanding.
        Canvas {
            id: spinner
            anchors.centerIn: parent
            width: 46
            height: 46
            visible: control.busy
            renderStrategy: Canvas.Cooperative

            Connections {
                target: control
                function onBusyChanged() {
                    spinner.requestPaint();
                }
            }

            onPaint: {
                var ctx = getContext("2d");
                ctx.reset();
                ctx.lineWidth = 4;
                ctx.lineCap = "round";
                ctx.strokeStyle = control.glyphColor;
                ctx.beginPath();
                ctx.arc(width / 2, height / 2, width / 2 - 3, 0, Math.PI * 1.3);
                ctx.stroke();
            }
        }

        RotationAnimator {
            target: spinner
            from: 0
            to: 360
            duration: 900
            loops: Animation.Infinite
            running: control.busy
        }

        scale: mouse.containsMouse && control.interactive ? 1.04 : 1.0
        Behavior on scale {
            NumberAnimation {
                duration: 140
                easing.type: Easing.OutQuad
            }
        }
    }

    MouseArea {
        id: mouse
        anchors.fill: parent
        hoverEnabled: true
        cursorShape: control.interactive ? Qt.PointingHandCursor : Qt.ArrowCursor
        onClicked: {
            if (control.interactive) control.clicked();
        }
    }
}
