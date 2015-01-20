FIND_PACKAGE(Boost REQUIRED COMPONENTS program_options)

INCLUDE_DIRECTORIES(SYSTEM
    ${Boost_INCLUDE_DIRS}
    )

INCLUDE_DIRECTORIES(
    ${INCLUDE_PATH}
    ${COMMON_PATH}/include
    ${DPL_PATH}/core/include
    ${DPL_PATH}/log/include
    )

SET(CMD_SOURCES
    ${CMD_PATH}/security-manager-cmd.cpp
    )

ADD_EXECUTABLE(${TARGET_CMD} ${CMD_SOURCES})

SET_TARGET_PROPERTIES(${TARGET_CMD}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fvisibility=hidden")

TARGET_LINK_LIBRARIES(${TARGET_CMD}
    ${TARGET_COMMON}
    ${TARGET_CLIENT}
    ${Boost_LIBRARIES}
    )

INSTALL(TARGETS ${TARGET_CMD} DESTINATION ${BIN_INSTALL_DIR})

INSTALL(FILES
    50_security-manager-add.post
    DESTINATION
    /etc/gumd/useradd.d
)

INSTALL(FILES
    50_security-manager-remove.pre
    DESTINATION
    /etc/gumd/userdel.d
)
