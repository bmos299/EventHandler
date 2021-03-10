cmake_minimum_required(VERSION 3.1)
SET(LIBBOOST_IOSTREAM_COMPILE_FLAG "-lboost_iostreams")

set(LIBSNARK_DIRECTORY
	"../depends/libsnark"
)

set(LIBFF_LIBSNARK_DIRECTORY
	${LIBSNARK_DIRECTORY}/depends/libff
)
set(LIBFQFFT_LIBSNARK_DIRECTORY
	${LIBSNARK_DIRECTORY}/depends/libfqfft
)
set(YAML_CPP_DIRECTORY
	${CMAKE_SOURCE_DIR}/depends/yaml-cpp/include
)
set(RAPIDCSV_DIRECTORY
	${CMAKE_SOURCE_DIR}/depends/rapidcsv/src
)

add_executable(trusted_ai_zkp_interface src/trusted_ai_zkp_interface.cpp)
target_include_directories(
    trusted_ai_zkp_interface
    PUBLIC

	${YAML_CPP_DIRECTORY}
	${RAPIDCSV_DIRECTORY}
    ${LIBFF_LIBSNARK_DIRECTORY}
    ${LIBFQFFT_LIBSNARK_DIRECTORY}
    ${LIBSNARK_DIRECTORY}
)
target_link_libraries(
    trusted_ai_zkp_interface
    
    ${GMPXX_LIBRARIES}
    ${GMP_LIBRARIES}
    ${LIBSNARK_LIBRARIES}
    ${LIBSNARK_LIBFF_LIBRARIES}
    ${LEMON_LIBRARIES}
    ${GMPXX_LIBRARIES}
    ${GMP_LIBRARIES}
	${YAML_CPP_LIBRARIES}
)

