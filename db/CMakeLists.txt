SET(DB_SCRIPT_DIR "${DATA_ROOT_DIR}/${PROJECT_NAME}/db")
SET(FOTA_DIR "${SYSCONF_INSTALL_DIR}/opt/upgrade")

# Update scrpipts
INSTALL(FILES update.sh DESTINATION ${DB_SCRIPT_DIR})
INSTALL(DIRECTORY updates DESTINATION ${DB_SCRIPT_DIR})
INSTALL(FILES db.sql DESTINATION ${DB_SCRIPT_DIR})

# FOTA updater
INSTALL(FILES 240.security-manager.db-update.sh DESTINATION ${FOTA_DIR})
