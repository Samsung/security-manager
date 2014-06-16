INSTALL(FILES
    ${CMAKE_SOURCE_DIR}/systemd/security-server.service
    ${CMAKE_SOURCE_DIR}/systemd/security-server.target
    ${CMAKE_SOURCE_DIR}/systemd/security-manager-installer.socket
    DESTINATION
    /usr/lib/systemd/system
)

