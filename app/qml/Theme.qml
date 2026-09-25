import QtQuick

QtObject {
    id: theme

    property string name: "Midnight"
    property string accent: "Mint"

    readonly property color background: {
        if (name === "Glacier") return "#F6F8FC";
        if (name === "Forest") return "#070D0B";
        if (name === "Dusk") return "#0F0B10";
        if (name === "Mono") return "#000000";
        return "#0A0D14";
    }
    readonly property color backgroundEnd: {
        if (name === "Glacier") return "#E9EFF7";
        if (name === "Forest") return "#0E1A15";
        if (name === "Dusk") return "#1B1219";
        if (name === "Mono") return "#0A0A0A";
        return "#131A29";
    }
    readonly property color panel: {
        if (name === "Glacier") return "#FFFFFF";
        if (name === "Forest") return "#0C1411";
        if (name === "Dusk") return "#151016";
        if (name === "Mono") return "#0A0A0A";
        return "#111624";
    }
    readonly property color card: {
        if (name === "Glacier") return "#FFFFFF";
        if (name === "Forest") return "#111C17";
        if (name === "Dusk") return "#1C151D";
        if (name === "Mono") return "#111111";
        return "#161C2B";
    }
    readonly property color cardHover: {
        if (name === "Glacier") return "#F1F5FB";
        if (name === "Forest") return "#16241D";
        if (name === "Dusk") return "#241B26";
        if (name === "Mono") return "#1A1A1A";
        return "#1B2233";
    }
    readonly property color border: {
        if (name === "Glacier") return "#DCE4F0";
        if (name === "Forest") return "#22382E";
        if (name === "Dusk") return "#372A3A";
        if (name === "Mono") return "#333333";
        return "#242D40";
    }
    readonly property color text: {
        if (name === "Glacier") return "#0E1626";
        if (name === "Forest") return "#E6F0E9";
        if (name === "Dusk") return "#F2E9F0";
        if (name === "Mono") return "#FFFFFF";
        return "#E9EDF5";
    }
    readonly property color textDim: {
        if (name === "Glacier") return "#4B5A75";
        if (name === "Forest") return "#86A293";
        if (name === "Dusk") return "#A08AA3";
        if (name === "Mono") return "#CCCCCC";
        return "#7F8AA3";
    }
    readonly property color textFaint: {
        if (name === "Glacier") return "#8A96AD";
        if (name === "Forest") return "#5A7266";
        if (name === "Dusk") return "#6E5A70";
        if (name === "Mono") return "#888888";
        return "#5A6478";
    }
    readonly property color surface: {
        if (name === "Glacier") return "#EDF2F9";
        if (name === "Forest") return "#0D1512";
        if (name === "Dusk") return "#171119";
        if (name === "Mono") return "#0D0D0D";
        return "#121826";
    }
    readonly property color danger: {
        if (name === "Glacier") return "#DC2626";
        return "#F87171";
    }
    readonly property color violet: {
        if (name === "Glacier") return "#6D28D9";
        return "#7C5CFF";
    }
    readonly property color blue: {
        if (name === "Glacier") return "#2563EB";
        return "#60A5FA";
    }
    readonly property color accentColor: {
        if (accent === "Sky") return name === "Glacier" ? "#0284C7" : "#38BDF8";
        if (accent === "Violet") return name === "Glacier" ? "#6D28D9" : "#8B5CF6";
        if (accent === "Amber") return name === "Glacier" ? "#B45309" : "#FBBF24";
        if (accent === "Rose") return name === "Glacier" ? "#BE123C" : "#FB7185";
        if (accent === "Cyan") return name === "Glacier" ? "#0E7490" : "#22D3EE";
        return name === "Glacier" ? "#15803D" : "#4ADE80";
    }
}
