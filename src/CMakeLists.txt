SET(tpm_cmd_SRC
	tpm_cmd.c

	sha1.c

	../lib/tlcl/oiaposap.c
	../lib/tlcl/tlcl.c
	../lib/tlcl/tlcl_hmac.c
	../lib/tlcl/tlcl_keys.c
	../lib/tlcl/tlcl_seal.c
)

SET(CMAKE_C_FLAGS "-Wall -Wextra -O0 -ggdb3")
add_definitions("-DCONFIG_TLCL_DEBUG=1")

include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${CMAKE_SOURCE_DIR}/lib/tlcl/include)

ADD_EXECUTABLE(tpm_cmd ${tpm_cmd_SRC})
