import QtQuick

Rectangle {
    id: card

    property string label: ""
    property string value: ""
    property string caption: ""
    property color accentColor: "#60A5FA"
    property color cardColor: "#161C2B"
    property color borderColor: "#242D40"
    property color textColor: "#E9EDF5"
    property color textDimColor: "#7F8AA3"

    height: 108
    radius: 14
    color: cardColor
    border.width: 1
    border.color: borderColor

    Rectangle {
        width: 3
        height: parent.height - 30
        radius: 1.5
        x: 0
        anchors.verticalCenter: parent.verticalCenter
        color: card.accentColor
    }

    Column {
        anchors.left: parent.left
        anchors.leftMargin: 20
        anchors.right: parent.right
        anchors.rightMargin: 14
        anchors.verticalCenter: parent.verticalCenter
        spacing: 5

        Text {
            text: card.label
            color: card.textDimColor
            font.pixelSize: 10
            font.letterSpacing: 1.3
            font.capitalization: Font.AllUppercase
        }

        Text {
            text: card.value
            color: card.textColor
            font.pixelSize: 25
            font.bold: true
        }

        Text {
            text: card.caption
            color: card.textDimColor
            font.pixelSize: 11
            width: parent.width
            elide: Text.ElideRight
        }
    }
}
