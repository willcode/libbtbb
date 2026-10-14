#
# This file is part of Libbtbb.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# libbtbb regression tests: build with the library and run with "ctest".
# The test programs compile the library sources directly (with
# AddressSanitizer/UBSan when available) so they can also exercise
# internal functions.

include(CheckCSourceCompiles)

option(BTBB_TEST_SANITIZERS "Build the tests with AddressSanitizer and UBSan" ON)

set(BTBB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/../src)
set(BTBB_TEST_FLAGS -g)

if(BTBB_TEST_SANITIZERS AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
	set(CMAKE_REQUIRED_FLAGS "-fsanitize=address,undefined")
	set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=address,undefined")
	check_c_source_compiles("int main(void) { return 0; }" BTBB_HAVE_SANITIZERS)
	unset(CMAKE_REQUIRED_FLAGS)
	unset(CMAKE_REQUIRED_LINK_OPTIONS)
	if(BTBB_HAVE_SANITIZERS)
		list(APPEND BTBB_TEST_FLAGS -fsanitize=address,undefined
		     -fno-sanitize-recover=undefined -fno-omit-frame-pointer)
	endif()
endif()

function(btbb_add_test_program name)
	add_executable(${name} ${ARGN})
	target_include_directories(${name} PRIVATE ${BTBB_SRC})
	target_compile_options(${name} PRIVATE ${BTBB_TEST_FLAGS})
	target_link_options(${name} PRIVATE ${BTBB_TEST_FLAGS})
endfunction()

# test_bredr.c includes bluetooth_packet.c itself
btbb_add_test_program(test_bredr test_bredr.c
	${BTBB_SRC}/bluetooth_piconet.c)
btbb_add_test_program(test_piconet test_piconet.c
	${BTBB_SRC}/bluetooth_packet.c
	${BTBB_SRC}/bluetooth_piconet.c)
# test_afh_blind.c includes bluetooth_piconet.c itself
btbb_add_test_program(test_afh_blind test_afh_blind.c
	${BTBB_SRC}/bluetooth_packet.c)
btbb_add_test_program(test_le test_le.c
	${BTBB_SRC}/bluetooth_le_packet.c
	${BTBB_SRC}/bluetooth_packet.c
	${BTBB_SRC}/bluetooth_piconet.c
	${BTBB_SRC}/companies.c
	${BTBB_SRC}/pcap.c
	${BTBB_SRC}/pcapng.c
	${BTBB_SRC}/pcapng-bt.c)

set(BTBB_TEST_ENV "ASAN_OPTIONS=detect_leaks=1" "UBSAN_OPTIONS=print_stacktrace=1")

add_test(NAME bredr COMMAND test_bredr)
add_test(NAME piconet COMMAND test_piconet)
add_test(NAME afh_blind COMMAND test_afh_blind)
add_test(NAME le COMMAND test_le ${CMAKE_CURRENT_BINARY_DIR})
set_tests_properties(bredr piconet afh_blind le PROPERTIES
	ENVIRONMENT "${BTBB_TEST_ENV}"
	TIMEOUT 600)
set_tests_properties(le PROPERTIES FIXTURES_SETUP le_captures)

# Check the capture files written by test_le with Wireshark's tools
find_program(CAPINFOS_EXECUTABLE capinfos)
find_program(TSHARK_EXECUTABLE tshark)

if(CAPINFOS_EXECUTABLE)
	# 450 CONNECT_INDs used to overflow the interface description block
	add_test(NAME le_connect_ind_capinfos
		COMMAND ${CAPINFOS_EXECUTABLE} -c
			${CMAKE_CURRENT_BINARY_DIR}/test_le_connect_ind.pcapng)
	set_tests_properties(le_connect_ind_capinfos PROPERTIES
		FIXTURES_REQUIRED le_captures
		PASS_REGULAR_EXPRESSION "Number of packets: +450")
	foreach(f test_le_fuzz.pcapng test_le_fuzz.pcap test_le_fuzz_ppi.pcap)
		add_test(NAME le_capinfos_${f}
			COMMAND ${CAPINFOS_EXECUTABLE} -c ${CMAKE_CURRENT_BINARY_DIR}/${f})
		set_tests_properties(le_capinfos_${f} PROPERTIES
			FIXTURES_REQUIRED le_captures
			PASS_REGULAR_EXPRESSION "Number of packets: +4,?214")
	endforeach()
else()
	message(STATUS "capinfos not found: skipping capture file checks")
endif()

if(TSHARK_EXECUTABLE)
	add_test(NAME le_connect_ind_tshark
		COMMAND ${TSHARK_EXECUTABLE} -n -r
			${CMAKE_CURRENT_BINARY_DIR}/test_le_connect_ind.pcapng
			-T fields -e frame.number)
	set_tests_properties(le_connect_ind_tshark PROPERTIES
		FIXTURES_REQUIRED le_captures
		PASS_REGULAR_EXPRESSION "(^|\n)450\n")
	# Wireshark must see the AUX_ADV_IND on a secondary channel as an
	# advertising PDU (LE PHDR PDU type "Auxiliary Advertising")
	add_test(NAME le_bt5_tshark
		COMMAND ${TSHARK_EXECUTABLE} -n -r
			${CMAKE_CURRENT_BINARY_DIR}/test_le_bt5.pcapng)
	set_tests_properties(le_bt5_tshark PROPERTIES
		FIXTURES_REQUIRED le_captures
		PASS_REGULAR_EXPRESSION "ADV_EXT_IND.*AUX_ADV_IND.*LL_LENGTH_REQ"
		FAIL_REGULAR_EXPRESSION "Malformed")
else()
	message(STATUS "tshark not found: skipping Wireshark decoding checks")
endif()
