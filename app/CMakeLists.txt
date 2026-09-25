# WispController uses Q_OBJECT, so Qt needs to run moc over the headers.
set(CMAKE_AUTOMOC ON)

qt_add_executable(wisp-app
  main.cpp
  wispcontroller.cpp
  wispcontroller.h
)

qt_add_resources(wisp-app "wisp_qml"
  PREFIX "/"
  FILES
    qml/Main.qml
    qml/Sidebar.qml
    qml/ConnectButton.qml
    qml/StatCard.qml
    qml/ThroughputGraph.qml
    qml/Theme.qml
)

target_link_libraries(wisp-app PRIVATE
  Qt6::Core
  Qt6::Gui
  Qt6::Qml
  Qt6::Quick
  wisp_core
)

install(TARGETS wisp-app RUNTIME DESTINATION bin)
