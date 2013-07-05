INSTALL(FILES
    ${CMAKE_SOURCE_DIR}/systemd/security-server.service
    ${CMAKE_SOURCE_DIR}/systemd/security-server.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-data-share.socket
    DESTINATION
    /usr/lib/systemd/system
)

