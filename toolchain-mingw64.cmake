# toolchain-mingw64.cmake

# Система — Windows
set(CMAKE_SYSTEM_NAME Windows)

# Архитектура — 64-бит
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Компиляторы MinGW-w64
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)

# Пути для поиска библиотек и заголовков (корень MinGW)
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)

# Правила поиска (бинарники ищем в хост-системе, а либы/инклюды — в MinGW)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
