cmake_minimum_required(VERSION 3.10)
project(network-mates-lite VERSION 0.2 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
 

#add_executable(nmlite src/main.c
#		src/log.h src/log.c
#		src/nm-app.h src/nm-app.c
#		src/nm-common.h src/nm-common.c
#		src/nm-vendordb.h src/nm-vendordb.c)
# add_executable(nmlite src/main.c src/nm-app.c src/nm-common.c src/nm-host.c
#         src/nm-scan.c src/nm-proto.c src/nm-vendordb.c)

#add_executable( nmlite src/main.c
                #src/nm-common.h src/nm-common.c
                #src/nm-host.h src/nm-host.c
                #src/nm-vendordb.h src/nm-vendordb.c
                #src/log.h src/log.c)


find_package(PkgConfig REQUIRED)
pkg_check_modules(glib REQUIRED IMPORTED_TARGET glib-2.0)

add_executable( nmlite src/nm-app.c
                src/nm-common.h src/nm-common.c
                src/nm-host.h src/nm-host.c
                src/nm-scan.h src/nm-scan.c
                src/nm-protocol.h src/nm-protocol.c
                src/nm-vendordb.h src/nm-vendordb.c
                src/log.h src/log.c)
target_include_directories(nmlite PRIVATE src/)
target_link_libraries(nmlite PkgConfig::glib)

enable_testing()
add_subdirectory(tests)
