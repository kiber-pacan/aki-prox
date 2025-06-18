cmake_minimum_required(VERSION 3.16)

project(aki-prox)
set(EXECUTABLE_NAME ${PROJECT_NAME})

add_compile_definitions(PROJECT_ROOT_DIR="${CMAKE_SOURCE_DIR}")

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)

qt_standard_project_setup()  # только если используешь Qt6 CMake API

add_executable(${EXECUTABLE_NAME}
        main.cpp
        libs/QAnsiTextEdit-main/src/QAnsiTextEdit.cpp
        libs/json.hpp
        sep/loader.h
)

target_include_directories(${EXECUTABLE_NAME} PRIVATE
        libs/QAnsiTextEdit-main/src
        libs
        sep
)

target_link_libraries(${EXECUTABLE_NAME} PRIVATE
        Qt6::Widgets
)

set(BUILD_DIR $<TARGET_FILE_DIR:${EXECUTABLE_NAME}>/build)

add_custom_command(TARGET ${EXECUTABLE_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${BUILD_DIR}"

        COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:${EXECUTABLE_NAME}>" "${BUILD_DIR}/"
        COMMAND ${CMAKE_COMMAND} -E copy_directory "${CMAKE_SOURCE_DIR}/proxy" "$<TARGET_FILE_DIR:${EXECUTABLE_NAME}>/build/proxy"

        COMMAND ${CMAKE_COMMAND} -E remove -f "${BUILD_DIR}.tar.gz"
        COMMAND ${CMAKE_COMMAND} -E tar "cfv" "${BUILD_DIR}.tar.gz" "${BUILD_DIR}"
        COMMAND ${CMAKE_COMMAND} -E remove_directory -f "${BUILD_DIR}"

)



