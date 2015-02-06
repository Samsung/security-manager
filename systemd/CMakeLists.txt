CONFIGURE_FILE(security-manager.service.in security-manager.service @ONLY)
CONFIGURE_FILE(security-manager-master.service.in security-manager-master.service @ONLY)
CONFIGURE_FILE(security-manager-slave.service.in security-manager-slave.service @ONLY)

INSTALL(FILES
    security-manager.service
    security-manager.socket
    security-manager-master.service
    security-manager-master.socket
    security-manager-slave.service
    security-manager-slave.socket
    DESTINATION
    ${SYSTEMD_INSTALL_DIR}
)
