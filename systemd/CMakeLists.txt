INSTALL(FILES
    ${CMAKE_SOURCE_DIR}/systemd/security-server.service
    ${CMAKE_SOURCE_DIR}/systemd/security-server.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-data-share.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-get-gid.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-privilege-by-pid.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-exec-path.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-get-object-name.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-app-permissions.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-cookie-get.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-cookie-check.socket
    DESTINATION
    /usr/lib/systemd/system
)

