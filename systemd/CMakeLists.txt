CONFIGURE_FILE(security-manager.service.in security-manager.service @ONLY)

INSTALL(FILES
    security-manager.service
    security-manager.target
    security-manager-installer.socket
    DESTINATION
    ${LIB_INSTALL_DIR}/systemd/system
)
