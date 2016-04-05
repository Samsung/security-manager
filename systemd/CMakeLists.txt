CONFIGURE_FILE(security-manager.service.in security-manager.service @ONLY)
CONFIGURE_FILE(security-manager-cleanup.service.in security-manager-cleanup.service @ONLY)
CONFIGURE_FILE(security-manager-rules-loader.service.in security-manager-rules-loader.service @ONLY)

INSTALL(FILES
    security-manager.service
    security-manager.socket
    security-manager-cleanup.service
    security-manager-rules-loader.service
    DESTINATION
    ${SYSTEMD_INSTALL_DIR}
)
