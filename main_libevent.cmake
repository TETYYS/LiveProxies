cmake_minimum_required (VERSION 2.6)
project (LiveProxies)
set(CMAKE_BUILD_TYPE RelWithDebInfo)
set (CMAKE_C_FLAGS "-DDEBUG -g ${CMAKE_C_FLAGS}")

message(STATUS "---")
message(STATUS "Local libevent build")
message(STATUS "---")

include(CheckIncludeFile)
check_include_file("valgrind/memcheck.h" HAVE_VALGRIND)

if (WIN32)
	set (CMAKE_C_FLAGS "--std=gnu99 -Wall ${CMAKE_C_FLAGS}")
ELSE()
	set (CMAKE_C_FLAGS "--std=gnu99 -Wall -pthread ${CMAKE_C_FLAGS}")
ENDIF()

add_executable(LiveProxies Base64.c Global.c Harvester.c Interface.c IPv6Map.c LiveProxies.c Logger.c ProxyLists.c ProxyRemove.c ProxyRequest.c Server.c PBKDF2.c SingleCheck.c HtmlTemplate.c Websocket.c Stats.c DNS.c CPH_Threads.c
						   Base64.h Global.h Harvester.h Interface.h IPv6Map.h LiveProxies.h Logger.h ProxyLists.h ProxyRemove.h ProxyRequest.h Server.h PBKDF2.h SingleCheck.h HtmlTemplate.h Websocket.h Stats.h DNS.h CPH_Threads.h
						   PortableEndian.h
						   tadns.c tadns.h llist.h
			  )

if (WIN32)
	include_directories(
		C:/LIB/openssl/include
		C:/LIB/libevent/cmake__/include
		C:/LIB/libconfig/libconfig-1.5/lib
		C:/Python27/include
		C:/LIB/libmaxminddb/include
		"C:/Program Files (x86)/GnuWin32/include"
		C:/LIB/curl-7.45.0/builds/libcurl-vc-x86-release-dll-ssl-dll-zlib-dll-ipv6-sspi/include
	)
	IF (MINGW)
		# MINGW
		target_link_libraries(
			LiveProxies
			C:/LIB/libevent/cmake__/lib/libevent.a
			C:/LIB/libmaxminddb/projects/VS12/Release/libmaxminddb.a
			C:/LIB/openssl-1.0.2d/libssl.a
			C:/LIB/openssl-1.0.2d/libcrypto.a
			C:/Python27/libs/libpython27.a
			"C:/Program Files (x86)/GnuWin32/lib/libpcre.dll.a"
			C:/LIB/libconfig/libconfig-1.5/lib/.libs/libconfig.dll.a
			C:/LIB/curl-7.45.0/lib/.libs/libcurl.dll.a
			Ws2_32
			Shlwapi
			iphlpapi
		)
	ELSE()
		# MSVC
		message(AUTHOR_WARNING "LiveProxies is not compiled with MSVC and most likely to fail.")
		target_link_libraries(
			LiveProxies
			C:/LIB/libevent/bin/lib/Release/event.lib
			C:/LIB/libmaxminddb/projects/VS12/Release/libmaxminddb.lib
			C:/OpenSSL-Win32/lib/libeay32.lib
			C:/Python27/libs/python27.lib
			"C:/Program Files (x86)/GnuWin32/lib/pcre.lib"
			C:/LIB/libconfig/libconfig-1.5/Release/libconfig.lib
			C:/LIB/curl-7.45.0/builds/libcurl-vc-x86-release-dll-ssl-dll-zlib-dll-ipv6-sspi/lib/libcurl.lib
			Ws2_32
			Shlwapi
			iphlpapi
		)
	ENDIF()
	
	add_definitions(-DWIN32_LEAN_AND_MEAN)
ELSE()
	target_link_libraries(LiveProxies ${CMAKE_SOURCE_DIR}/libevent.a maxminddb crypto ssl python2.7 pcre config m util anl curl)
ENDIF()