# libsmb2 pkg-config file

prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=@CMAKE_INSTALL_PREFIX@
libdir=@INSTALL_LIB_DIR@
includedir=@INSTALL_INC_DIR@

Name: libsmb2
Description: libsmb2 is a client library for accessing SMB shares over a network.
Version: @PROJECT_VERSION@
Requires:
Requires.private: @SMB2_PC_REQUIRES@
Conflicts:
Libs: -L${libdir} -lsmb2
Libs.private: @SMB2_PC_PRIVATE_LIBS@
Cflags: -I${includedir}
