cmake_minimum_required(VERSION 3.16)

project(aki-prox)
set(EXECUTABLE_NAME ${PROJECT_NAME})

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Is it even needed?
if(NOT CMAKE_PREFIX_PATH)
    set(CMAKE_PREFIX_PATH "C:/Qt/6.8.3/msvc2022_64/lib/cmake" CACHE PATH "Qt6 path")
endif()

# Qt
find_package(Qt6 REQUIRED COMPONENTS Widgets)
qt_standard_project_setup()

# Binaries
qt_add_executable(${EXECUTABLE_NAME}
        main.cpp
        libs/QAnsiTextEdit-main/src/QAnsiTextEdit.cpp
        libs/json.hpp
        sep/loader.h
)

# Libraries
target_include_directories(${EXECUTABLE_NAME} PRIVATE
        libs/QAnsiTextEdit-main/src
        libs
        sep
)

target_compile_definitions(${EXECUTABLE_NAME} PRIVATE
        PROJECT_ROOT_DIR="${CMAKE_SOURCE_DIR}"
)

target_link_libraries(${EXECUTABLE_NAME} PRIVATE
        Qt6::Widgets
)

# Deploy script (windeployqt)
if(WIN32)
    add_custom_command(TARGET ${EXECUTABLE_NAME} POST_BUILD
            COMMAND "${Qt6_DIR}/../../bin/windeployqt.exe" --release "$<TARGET_FILE_DIR:${EXECUTABLE_NAME}>"
    )
endif()

# Setting names
set(OUTPUT_DIR $<TARGET_FILE_DIR:${EXECUTABLE_NAME}>)
set(BUILD_DIR "${OUTPUT_DIR}/build")
set(ARCHIVE_NAME "${OUTPUT_DIR}/aki-prox-${CMAKE_SYSTEM_NAME}.tar.gz")

# Archivation and copy
add_custom_command(TARGET ${EXECUTABLE_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${BUILD_DIR}"
        COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:${EXECUTABLE_NAME}>" "${BUILD_DIR}/"
        COMMAND ${CMAKE_COMMAND} -E copy_directory "${CMAKE_SOURCE_DIR}/proxy" "${BUILD_DIR}/proxy"
        COMMAND ${CMAKE_COMMAND} -E copy_directory "${CMAKE_SOURCE_DIR}/proxy" "${OUTPUT_DIR}/proxy"
        COMMAND ${CMAKE_COMMAND} -E remove -f "${ARCHIVE_NAME}"
        COMMAND ${CMAKE_COMMAND} -E tar cfv "${ARCHIVE_NAME}" "${OUTPUT_DIR}" build
        COMMAND ${CMAKE_COMMAND} -E remove_directory "${BUILD_DIR}"
)



#skebedi