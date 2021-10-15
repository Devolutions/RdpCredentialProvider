
set(MODULE_NAME "RdpCredProv")
set(MODULE_PREFIX "RDPCREDPROV")

add_library(${MODULE_NAME} SHARED
	common.h
	Dll.cpp
	Dll.h
	guid.cpp
	guid.h
	helpers.cpp
	helpers.h
	RdpCredential.cpp
	RdpCredential.h
	RdpProvider.cpp
	RdpProvider.h
	resources.rc
	RdpCredProv.def)

windows_rc_generate_version_info(
	NAME "${MODULE_NAME}" TYPE "DLL"
	VERSION "${RDPCREDPROV_VERSION}.0"
	FILENAME "${MODULE_NAME}.dll"
	VENDOR "${RDPCREDPROV_VENDOR}"
	COPYRIGHT "${RDPCREDPROV_COPYRIGHT}"
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/version.rc)

include_directories("${CMAKE_CURRENT_BINARY_DIR}")

target_link_libraries(RdpCredProv secur32 shlwapi)
