set(SRC ${CMAKE_SOURCE_DIR}/src/)
set(COMMON_FILES    munit.h munit.c
                    ${SRC}/log.h
                    ${SRC}/log.c
                    ${SRC}/nm-common.h
                    ${SRC}/nm-common.c
                    ${SRC}/nm-vendordb.h
                    ${SRC}/nm-vendordb.c)


add_executable(test_common test_common.c ${SRC}/nm-common.c ${COMMON_FILES})
target_include_directories(test_common PRIVATE ${SRC})
target_link_libraries(test_common PkgConfig::glib)
add_test(NAME common COMMAND test_common)

add_executable(test_host test_host.c ${SRC}/nm-host.c ${SRC}/nm-host.h ${COMMON_FILES})
target_include_directories(test_host PRIVATE ${SRC})
target_link_libraries(test_host PkgConfig::glib)
add_test(NAME host COMMAND test_host)

add_executable(test_vendordb test_vendordb.c ${SRC}/nm-vendordb.c ${COMMON_FILES})
target_include_directories(test_vendordb PRIVATE ${SRC})
target_link_libraries(test_vendordb PkgConfig::glib)
add_test(NAME vendordb COMMAND test_vendordb)

add_executable(test_protocol test_protocol.c ${SRC}/nm-protocol.c ${COMMON_FILES})
target_include_directories(test_protocol PRIVATE ${SRC})
target_link_libraries(test_protocol PkgConfig::glib)
add_test(NAME protocol COMMAND test_protocol)



# Check GTK to test gui
pkg_check_modules(gtk IMPORTED_TARGET gtk+-3.0)
if (PKG_CONFIG_FOUND)

    add_executable(test_window test_window.c ${SRC}/nm-appwindow.c ${SRC}/nm-appwindow.h
                    ${SRC}/nm-host.c ${SRC}/nm-host.h
                    ${SRC}/nm-protocol.c ${SRC}/nm-protocol.h
                    ${SRC}/nm-scan.c ${SRC}/nm-scan.h
                    ${COMMON_FILES} ${CMAKE_BINARY_DIR}/${NM_GRESOURCE_C})
    target_include_directories(test_window PRIVATE ${SRC})
    target_link_libraries(test_window PkgConfig::gtk)

    set_source_files_properties(${CMAKE_BINARY_DIR}/${NM_GRESOURCE_C}
            PROPERTIES GENERATED TRUE)
    add_dependencies(test_window nmgui-resource)
    
    add_test(NAME window COMMAND test_window --verbose)

endif()

