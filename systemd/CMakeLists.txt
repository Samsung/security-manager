IF(CMAKE_BUILD_TYPE MATCHES "VALGRIND")
    CONFIGURE_FILE(security-manager-valgrind.service.in security-manager.service @ONLY)
ELSE()
    CONFIGURE_FILE(security-manager.service.in security-manager.service @ONLY)
ENDIF()

CONFIGURE_FILE(security-manager-cleanup.service.in security-manager-cleanup.service @ONLY)
CONFIGURE_FILE(security-manager-rules-loader.service.in security-manager-rules-loader.service @ONLY)

INSTALL(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/security-manager.service
    security-manager.socket
    ${CMAKE_CURRENT_BINARY_DIR}/security-manager-cleanup.service
    ${CMAKE_CURRENT_BINARY_DIR}/security-manager-rules-loader.service
    DESTINATION
    ${SYSTEMD_INSTALL_DIR}
)
