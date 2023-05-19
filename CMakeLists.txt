cmake_minimum_required(VERSION 3.10)
project(netmates VERSION 0.2 LANGUAGES C)
set(CMAKE_C_STANDARD 11)

set(WITH_TESTS YES)
set(WITH_GUI_TESTS YES)


find_package(PkgConfig REQUIRED)
pkg_check_modules(glib REQUIRED IMPORTED_TARGET glib-2.0)

add_executable( netmates src/nm-app.c
                src/nm-common.h src/nm-common.c
                src/nm-host.h src/nm-host.c
                src/nm-scan.h src/nm-scan.c
                src/nm-protocol.h src/nm-protocol.c
                src/nm-vendordb.h src/nm-vendordb.c
                src/log.h src/log.c)
target_include_directories(netmates PRIVATE src/)
target_link_libraries(netmates PkgConfig::glib)


# Check GTK to build gui
pkg_check_modules(gtk IMPORTED_TARGET gtk+-3.0)
if (PKG_CONFIG_FOUND)
    #pkg_check_modules(gtk REQUIRED IMPORTED_TARGET gtk+-3.0)
    find_program(GLIB_COMPILE_RESOURCES NAMES glib-compile-resources REQUIRED)

    set(NM_GRESOURCE_XML gui/nm.gresource.xml)
    set(NM_GRESOURCE_C nm.gresource.c)

    add_custom_command(OUTPUT ${NM_GRESOURCE_C} WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            COMMAND ${GLIB_COMPILE_RESOURCES}
            ARGS --generate --target=${CMAKE_CURRENT_BINARY_DIR}/${NM_GRESOURCE_C} ${NM_GRESOURCE_XML} VERBATIM
            MAIN_DEPENDENCY ${NM_GRESOURCE_XML} DEPENDS gui/nm-window.ui gui/nm-style.css)
    add_custom_target(nmgui-resource DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${NM_GRESOURCE_C})

    add_executable( netmates-gui src/nm-appgui.c
                    src/nm-appwindow.h src/nm-appwindow.c
                    src/nm-common.h src/nm-common.c
                    src/nm-host.h src/nm-host.c
                    src/nm-scan.h src/nm-scan.c
                    src/nm-protocol.h src/nm-protocol.c
                    src/nm-vendordb.h src/nm-vendordb.c
                    src/log.h src/log.c
                    ${CMAKE_CURRENT_BINARY_DIR}/${NM_GRESOURCE_C})
    target_include_directories(netmates-gui PRIVATE src/)
    set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/${NM_GRESOURCE_C}
            PROPERTIES GENERATED TRUE)
    # netmates target not required here, but nicer for IDE integration
    add_dependencies(netmates-gui netmates nmgui-resource)
    target_link_libraries(netmates-gui PkgConfig::gtk)
endif()

# Tests
if (WITH_TESTS)
    
    enable_testing()
    add_subdirectory(tests)
    
endif()

# Documentation
add_custom_command(OUTPUT netmates.html 
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/doc
                    COMMAND man2html 
                    ARGS ${CMAKE_CURRENT_SOURCE_DIR}/doc/netmates.1 > ${CMAKE_CURRENT_SOURCE_DIR}/doc/netmates.html
                    VERBATIM)
add_custom_target(nmdoc DEPENDS netmates.html)

