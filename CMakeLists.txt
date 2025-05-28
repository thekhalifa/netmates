cmake_minimum_required(VERSION 3.10..3.30)
set(CMAKE_C_STANDARD 11)
project(netmates VERSION 0.2.3 LANGUAGES C)
set(PROJECT_AUTHOR "Ahmad Khalifa")
set(PROJECT_HOMEPAGE_URL "https://netmates.uk")
set(PROJECT_DESCRIPTION "Network discovery tool for local devices")
set(PROJECT_DESCRIPTION_LONG "Network discovery tool for local devices.\n\
Combining multiple discovery methods and available as command-line and a simple gtk-based interface.")

set(WITH_TESTS YES)
set(WITH_GUI_TESTS YES)

find_package(PkgConfig REQUIRED)
pkg_check_modules(glib REQUIRED IMPORTED_TARGET glib-2.0)

add_library(netmates-core STATIC src/nm-common.h src/nm-common.c
                src/nm-host.h src/nm-host.c
                src/nm-scan.h src/nm-scan.c
                src/nm-probe.h src/nm-probe.c
                src/nm-protocol.h src/nm-protocol.c
                src/nm-vendordb.h src/nm-vendordb.c
                src/log.h src/log.c)
target_link_libraries(netmates-core PkgConfig::glib)


add_executable(netmates src/nm-app.c)
target_link_libraries(netmates netmates-core)

install(TARGETS netmates RUNTIME)
install(FILES "doc/netmates.1" DESTINATION "share/man/man1"
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
install(FILES "gui/netmates.desktop" DESTINATION "share/applications"
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

# Check GTK to build gui
pkg_check_modules(gtk IMPORTED_TARGET gtk+-3.0)
if (PKG_CONFIG_FOUND)
    find_program(GLIB_COMPILE_RESOURCES NAMES glib-compile-resources REQUIRED)

    set(NM_GRESOURCE_XML gui/nm.gresource.xml)
    set(NM_GRESOURCE_C nm.gresource.c)

    add_custom_command(OUTPUT ${NM_GRESOURCE_C} WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            COMMAND ${GLIB_COMPILE_RESOURCES}
            ARGS --generate --target=${CMAKE_CURRENT_BINARY_DIR}/${NM_GRESOURCE_C} ${NM_GRESOURCE_XML} VERBATIM
            MAIN_DEPENDENCY ${NM_GRESOURCE_XML} DEPENDS gui/nm-window.ui gui/nm-style.css)
    add_custom_target(nmgui-resource DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${NM_GRESOURCE_C})

    add_executable(netmates-gui src/nm-appgui.c
                    src/nm-appwindow.h src/nm-appwindow.c
                    ${CMAKE_CURRENT_BINARY_DIR}/${NM_GRESOURCE_C})
    target_link_libraries(netmates-gui netmates-core)
    target_include_directories(netmates-gui PRIVATE src/)
    set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/${NM_GRESOURCE_C}
            PROPERTIES GENERATED TRUE)
    # netmates target not required here, but nicer for IDE integration
    add_dependencies(netmates-gui netmates nmgui-resource)
    target_link_libraries(netmates-gui PkgConfig::gtk)
    install(TARGETS netmates-gui DESTINATION bin)
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
                    ARGS -M "" netmates.1 > netmates.html
                    VERBATIM)
add_custom_target(nmdoc DEPENDS netmates.html)
set_property(TARGET netmates APPEND 
           PROPERTY ADDITIONAL_CLEAN_FILES ${CMAKE_CURRENT_SOURCE_DIR}/doc/netmates.html)

# Packaging
include(InstallRequiredSystemLibraries)
set(CPACK_GENERATOR DEB RPM TGZ)
set(CPACK_PACKAGE_DIRECTORY dist/)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY ${PROJECT_DESCRIPTION})
set(CPACK_PACKAGE_HOMEPAGE_URL ${PROJECT_HOMEPAGE_URL})
set(CPACK_DEBIAN_PACKAGE_MAINTAINER ${PROJECT_AUTHOR})
set(CPACK_PACKAGE_VENDOR ${PROJECT_AUTHOR})
## Debian package
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS 1)
set(CPACK_DEBIAN_PACKAGE_SECTION net)
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION ${PROJECT_DESCRIPTION_LONG})
set(CPACK_DEBIAN_PACKAGE_RELEASE 1)
## Redhat package
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_RPM_PACKAGE_LICENSE GPLv3)
set(CPACK_RPM_PACKAGE_DESCRIPTION ${PROJECT_DESCRIPTION_LONG})

include(CPack)
