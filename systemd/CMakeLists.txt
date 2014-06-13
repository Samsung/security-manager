INSTALL(FILES
    ${CMAKE_SOURCE_DIR}/systemd/security-manager.service
    ${CMAKE_SOURCE_DIR}/systemd/security-manager.target
    ${CMAKE_SOURCE_DIR}/systemd/security-manager-installer.socket
    DESTINATION
    /usr/lib/systemd/system
)

