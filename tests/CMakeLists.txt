

set(SOURCE_BASE ${CMAKE_SOURCE_DIR}/src/)
set(COMMON_FILES    munit.h munit.c
                    ${SOURCE_BASE}/log.h
                    ${SOURCE_BASE}/log.c
                    ${SOURCE_BASE}/nm-common.h
                    ${SOURCE_BASE}/nm-common.c
                    ${SOURCE_BASE}/nm-vendordb.h
                    ${SOURCE_BASE}/nm-vendordb.c)

#file(GLOB SOURCE_FILES ${SOURCE_BASE}/nm-host.c ${SOURCE_BASE}/nm-scan.c ${SOURCE_BASE}/nm-proto.c
#        ${SOURCE_BASE}/nm-common.c ${SOURCE_BASE}/nm-vendordb.c)



# add_executable(test_host test_host.c ${SOURCE_BASE}/nm-host.c ${SOURCE_BASE}/nm-common.c)
# target_include_directories(test_host PRIVATE ${SOURCE_BASE})
# target_link_libraries(test_host PkgConfig::GtkD)
# add_test(NAME host COMMAND test_host --verbose)

# add_executable(test_scan test_scan.c ${SOURCE_FILES})
# target_include_directories(test_scan PRIVATE ${SOURCE_BASE})
# target_link_libraries(test_scan PkgConfig::GtkD)
# add_test(NAME scan COMMAND test_scan --verbose)

#file(GLOB SOURCE_FILES ${SOURCE_BASE}/nm-common.c)

#add_executable(test_common test_common.c ${SOURCE_BASE}/nm-common.c)
#target_include_directories(test_common PRIVATE ${SOURCE_BASE})
#target_link_libraries(test_common PRIVATE cunit)
#add_test(NAME common COMMAND test_common)

add_executable(test_common test_common.c ${SOURCE_BASE}/nm-common.c ${COMMON_FILES})
target_include_directories(test_common PRIVATE ${SOURCE_BASE})
target_link_libraries(test_common PkgConfig::glib)
add_test(NAME common COMMAND test_common)

add_executable(test_host test_host.c ${SOURCE_BASE}/nm-host.c ${SOURCE_BASE}/nm-host.h ${COMMON_FILES})
target_include_directories(test_host PRIVATE ${SOURCE_BASE})
target_link_libraries(test_host PkgConfig::glib)
add_test(NAME host COMMAND test_host)

add_executable(test_vendordb test_vendordb.c ${SOURCE_BASE}/nm-vendordb.c ${COMMON_FILES})
target_include_directories(test_vendordb PRIVATE ${SOURCE_BASE})
target_link_libraries(test_vendordb PkgConfig::glib)
add_test(NAME vendordb COMMAND test_vendordb)

add_executable(test_protocol test_protocol.c ${SOURCE_BASE}/nm-protocol.c ${COMMON_FILES})
target_include_directories(test_protocol PRIVATE ${SOURCE_BASE})
target_link_libraries(test_protocol PkgConfig::glib)
add_test(NAME protocol COMMAND test_protocol)

# Experiment with cunit
#add_executable(test_basic test_basic.c)
#target_link_libraries(test_basic PRIVATE cunit)
#add_test(NAME basic COMMAND test_basic)

# munit
add_executable(test_basicm test_basicm.c munit.c)
target_include_directories(test_basicm PRIVATE ${SOURCE_BASE})
#target_link_libraries(test_basic PRIVATE cunit)
add_test(NAME basicm COMMAND test_basicm)

