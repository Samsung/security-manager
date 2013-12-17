INSTALL(FILES
    ${CMAKE_SOURCE_DIR}/systemd/security-server.service
    ${CMAKE_SOURCE_DIR}/systemd/security-server.target
    ${CMAKE_SOURCE_DIR}/systemd/security-server-data-share.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-get-gid.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-privilege-by-pid.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-app-permissions.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-cookie-get.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-cookie-check.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-app-privilege-by-name.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-open-for.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-password-reset.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-password-check.socket
    ${CMAKE_SOURCE_DIR}/systemd/security-server-password-set.socket
    DESTINATION
    /usr/lib/systemd/system
)

