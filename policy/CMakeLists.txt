FILE(GLOB USERTYPE_POLICY_FILES usertype-*.profile)

CONFIGURE_FILE(security-manager-policy-reload.in security-manager-policy-reload @ONLY)

INSTALL(FILES ${USERTYPE_POLICY_FILES} DESTINATION ${POLICY_DIR})
INSTALL(FILES "app-rules-template.smack" DESTINATION ${POLICY_DIR})
INSTALL(FILES "pkg-rules-template.smack" DESTINATION ${POLICY_DIR})
INSTALL(FILES "author-rules-template.smack" DESTINATION ${POLICY_DIR})
INSTALL(FILES "privilege-group.list" DESTINATION ${POLICY_DIR})
INSTALL(PROGRAMS security-manager-policy-reload DESTINATION ${BIN_INSTALL_DIR})
