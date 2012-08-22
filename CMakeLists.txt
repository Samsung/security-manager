CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(secrutiy-server-C)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")
SET(VERSION_MAJOR 1)
SET(VERSION ${VERSION_MAJOR}.0.1)

#Verbose
#SET(CMAKE_VERBOSE_MAKEFILE ON)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED dlog openssl libsmack)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(sec_svr_dir "./")
SET(sec_svr_include_dir "./include")
SET(sec_svr_src_dir "./src")
SET(sec_svr_test_dir "./testcases")

## Additional flag
#SET(debug_type "-DSECURITY_SERVER_DEBUG_TO_CONSOLE")
SET(debug_type "-DSECURITY_SERVER_DEBUG_DLOG")
#SET(debug_type "")

SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

###################################################################################################
## for libsecurity-server-client.so (library)
SET(libsecurity-server-client_SOURCES ${sec_svr_src_dir}/client/security-server-client.c ${sec_svr_src_dir}/communication/security-server-comm.c)
SET(libsecurity-server-client_LDFLAGS " -module -avoid-version")
SET(libsecurity-server-client_CFLAGS  " ${CFLAGS} -fPIC -I${sec_svr_include_dir} ${debug_type} -D_GNU_SOURCE ")
#SET(libsecurity-server-client_LIBADD "")

ADD_LIBRARY(security-server-client SHARED ${libsecurity-server-client_SOURCES})
TARGET_LINK_LIBRARIES(security-server-client ${pkgs_LDFLAGS})
SET_TARGET_PROPERTIES(security-server-client PROPERTIES SOVERSION ${VERSION_MAJOR})
SET_TARGET_PROPERTIES(security-server-client PROPERTIES VERSION ${VERSION})
SET_TARGET_PROPERTIES(security-server-client PROPERTIES COMPILE_FLAGS "${libsecurity-server-client_CFLAGS}")
###################################################################################################

###################################################################################################
## for security-server (binary)
SET(security-server_SOURCES ${sec_svr_src_dir}/server/security-server-main.c ${sec_svr_src_dir}/communication/security-server-comm.c ${sec_svr_src_dir}/server/security-server-cookie.c ${sec_svr_src_dir}/server/security-server-password.c ${sec_svr_src_dir}/util/security-server-util-common.c )
SET(security-server_CFLAGS " -I/usr/include -I. -I${sec_svr_include_dir} ${debug_type} -D_GNU_SOURCE ")
SET(security-server_LDFLAGS ${pkgs_LDFLAGS} -lpthread)

ADD_EXECUTABLE(security-server ${security-server_SOURCES})
TARGET_LINK_LIBRARIES(security-server ${pkgs_LDFLAGS})
SET_TARGET_PROPERTIES(security-server PROPERTIES COMPILE_FLAGS "${security-server_CFLAGS}")
####################################################################################################

##FOR TEST METHOD ONLY. MUST BE DELETED ON RELEASE ############################################################
## for security-server util (binary)
SET(sec-svr-util_SOURCES ${sec_svr_src_dir}/util/security-server-util.c ${sec_svr_src_dir}/communication/security-server-comm.c ${sec_svr_src_dir}/util/security-server-util-common.c ${sec_svr_src_dir}/server/security-server-cookie.c)
SET(sec-svr-util_CFLAGS " -I/usr/include -I. -I${sec_svr_include_dir} ${debug_type} -D_GNU_SOURCE ")
SET(sec-svr-util_LDFLAGS ${pkgs_LDFLAGS})

ADD_EXECUTABLE(sec-svr-util ${sec-svr-util_SOURCES})
TARGET_LINK_LIBRARIES(sec-svr-util ${pkgs_LDFLAGS})
SET_TARGET_PROPERTIES(sec-svr-util PROPERTIES COMPILE_FLAGS "${sec-svr-util_CFLAGS}")
####################################################################################################

CONFIGURE_FILE(security-server.pc.in security-server.pc @ONLY)

INSTALL(TARGETS security-server-client DESTINATION lib)
INSTALL(PROGRAMS ${CMAKE_BINARY_DIR}/security-server DESTINATION bin)
INSTALL(PROGRAMS ${CMAKE_BINARY_DIR}/sec-svr-util DESTINATION bin)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/security-server.pc DESTINATION lib/pkgconfig)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/security-server.h DESTINATION include/security-server)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/mw-list DESTINATION share/security-server)
INSTALL(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/security-serverd DESTINATION /etc/rc.d/init.d)
