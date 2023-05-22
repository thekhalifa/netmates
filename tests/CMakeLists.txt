set(SRC ${CMAKE_SOURCE_DIR}/src/)
add_library(munit munit.h munit.c)

add_executable(test_common test_common.c )
target_include_directories(test_common PRIVATE ${SRC})
target_link_libraries(test_common libnetmates munit)
add_test(NAME common COMMAND test_common)

add_executable(test_host test_host.c)
target_include_directories(test_host PRIVATE ${SRC})
target_link_libraries(test_host libnetmates munit)
add_test(NAME host COMMAND test_host)

add_executable(test_vendordb test_vendordb.c)
target_include_directories(test_vendordb PRIVATE ${SRC})
target_link_libraries(test_vendordb libnetmates munit)
add_test(NAME vendordb COMMAND test_vendordb)

add_executable(test_protocol test_protocol.c)
target_include_directories(test_protocol PRIVATE ${SRC})
target_link_libraries(test_protocol libnetmates munit)
add_test(NAME protocol COMMAND test_protocol)

add_executable(test_scan test_scan.c)
target_include_directories(test_scan PRIVATE ${SRC})
target_link_libraries(test_scan libnetmates munit)
add_test(NAME scan COMMAND test_scan)


# Check GTK to test gui
if (WITH_GUI_TESTS)
    pkg_check_modules(gtk IMPORTED_TARGET gtk+-3.0)
    if (PKG_CONFIG_FOUND)
        add_executable(test_window test_window.c
                        ${SRC}/nm-appwindow.c ${SRC}/nm-appwindow.h
                        ${CMAKE_BINARY_DIR}/${NM_GRESOURCE_C})
        target_include_directories(test_window PRIVATE ${SRC})
        target_link_libraries(test_window libnetmates munit)
        target_link_libraries(test_window PkgConfig::gtk)

        set_source_files_properties(${CMAKE_BINARY_DIR}/${NM_GRESOURCE_C}
                PROPERTIES GENERATED TRUE)
        add_dependencies(test_window nmgui-resource)
        add_test(NAME window COMMAND test_window --verbose)
    endif()
endif()
