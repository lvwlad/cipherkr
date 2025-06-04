cmake_minimum_required(VERSION 3.16)

project(test VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Добавляем путь к Qt
set(CMAKE_PREFIX_PATH "/opt/homebrew/opt/qt@6/lib/cmake" ${CMAKE_PREFIX_PATH})

# Добавляем путь к QCA
set(CMAKE_PREFIX_PATH "/opt/homebrew/Cellar/qca/2.3.10_1/lib/cmake" ${CMAKE_PREFIX_PATH})

# Подключаем Qt
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets Core Gui)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Core Gui)

# Подключаем QCA
find_package(Qca-qt6 REQUIRED)

# Источники проекта
set(PROJECT_SOURCES
        main.cpp
        mainwindow.cpp
        mainwindow.h
        mainwindow.ui
        ciphers.h
        ciphers.cpp
        exporter.h
        exporter.cpp
        exportformatdialog.h
        exportformatdialog.cpp
        kuz_calc.h
        kuz_calc.cpp
)

# Создание исполняемого файла
if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(test
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )
else()
    if(ANDROID)
        add_library(test SHARED
            ${PROJECT_SOURCES}
        )
    else()
        add_executable(test
            ${PROJECT_SOURCES}
        )
    endif()
endif()

# Линковка с Qt и QCA
target_link_libraries(test PRIVATE 
    Qt${QT_VERSION_MAJOR}::Widgets 
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::Gui
    qca-qt6
)

target_include_directories(test PRIVATE
    "/opt/homebrew/opt/qt@6/include"
    "/opt/homebrew/opt/qt@6/include/QtWidgets"
    "/opt/homebrew/opt/qt@6/include/QtCore"
    "/opt/homebrew/opt/qt@6/include/QtGui"
    "/opt/homebrew/Cellar/qca/2.3.10_1/lib/qca-qt6.framework/Headers"
)

# Свойства для macOS/iOS
if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.test)
endif()
set_target_properties(test PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

# Установка
include(GNUInstallDirs)
install(TARGETS test
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Завершение для Qt6
if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(test)
endif()
