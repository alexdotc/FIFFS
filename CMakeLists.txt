cmake_minimum_required(VERSION 3.0)

project(
  tmpfs_fuse
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig)
pkg_check_modules(FUSE3 REQUIRED fuse3)

file(GLOB SRCFILES ${PROJECT_SOURCE_DIR}/src/*.cpp)
add_executable(tmpfs_fuse ${SRCFILES})
target_include_directories(tmpfs_fuse PRIVATE ${PROJECT_SOURCE_DIR}/include ${FUSE3_INCLUDE_DIR})
target_link_libraries(tmpfs_fuse ${FUSE3_LIBRARIES})
