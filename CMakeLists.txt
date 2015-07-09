cmake_minimum_required (VERSION 2.6)
project (LIVEPROXIES)

set (CMAKE_C_FLAGS "--std=c99 -pthread ${CMAKE_C_FLAGS}")

add_executable(LiveProxies Base64.c Global.c Harvester.c Interface.c IPv6Map.c LiveProxies.c Logger.c ProxyLists.c ProxyRemove.c ProxyRequest.c WServer.c PBKDF2.c)
target_link_libraries(LiveProxies event GeoIP crypto python2.7 pcre config m util)
