cmake_minimum_required (VERSION 2.6)

option(BUILD_WITH_LOCAL_LIBEVENT "Build with local libevent" OFF)

if (BUILD_WITH_LOCAL_LIBEVENT)
	include(main_libevent.cmake)
else()
	include(main.cmake)
endif()