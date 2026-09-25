import QtQuick

Item {
    id: graph

    property var download: []
    property var upload: []
    property color downloadColor: "#60A5FA"
    property color uploadColor: "#4ADE80"
    property color gridColor: "#1E2739"
    property color surfaceColor: "#121826"

    implicitHeight: 170

    Rectangle {
        anchors.fill: parent
        radius: 14
        color: graph.surfaceColor
        border.width: 1
        border.color: gridColor
    }

    Canvas {
        id: canvas

        anchors.fill: parent
        anchors.margins: 16
        renderStrategy: Canvas.Cooperative

        Connections {
            target: graph
            function onDownloadChanged() {
                canvas.requestPaint();
            }
            function onUploadChanged() {
                canvas.requestPaint();
            }
        }

        onWidthChanged: requestPaint()
        onHeightChanged: requestPaint()

        onPaint: {
            var ctx = getContext("2d");
            ctx.clearRect(0, 0, width, height);

            var w = width;
            var h = height;

            ctx.lineWidth = 1;
            ctx.strokeStyle = graph.gridColor;
            for (var line = 1; line <= 3; ++line) {
                var y = (h * line) / 4;
                ctx.beginPath();
                ctx.moveTo(0, y);
                ctx.lineTo(w, y);
                ctx.stroke();
            }

            // Scale both series together so the two lines stay comparable.
            var peak = 1024.0;
            var i;
            for (i = 0; i < graph.download.length; ++i) {
                if (graph.download[i] > peak) peak = graph.download[i];
            }
            for (i = 0; i < graph.upload.length; ++i) {
                if (graph.upload[i] > peak) peak = graph.upload[i];
            }

            function drawSeries(data, colour) {
                if (data.length < 2) return;

                var step = w / (data.length - 1);
                var usable = h - 4;

                ctx.beginPath();
                ctx.moveTo(0, h - (data[0] / peak) * usable);
                for (var index = 1; index < data.length; ++index) {
                    ctx.lineTo(index * step, h - (data[index] / peak) * usable);
                }
                ctx.strokeStyle = colour;
                ctx.lineWidth = 2;
                ctx.lineJoin = "round";
                ctx.lineCap = "round";
                ctx.stroke();

                // Soft fill beneath, to give the line some weight.
                ctx.lineTo((data.length - 1) * step, h);
                ctx.lineTo(0, h);
                ctx.closePath();
                ctx.globalAlpha = 0.13;
                ctx.fillStyle = colour;
                ctx.fill();
                ctx.globalAlpha = 1.0;
            }

            drawSeries(graph.download, graph.downloadColor);
            drawSeries(graph.upload, graph.uploadColor);
        }
    }

    // Shown until there is enough history to draw a line.
    Text {
        anchors.centerIn: parent
        visible: graph.download.length < 2 && graph.upload.length < 2
        text: qsTr("Waiting for traffic")
        color: "#5A6478"
        font.pixelSize: 12
    }
}
