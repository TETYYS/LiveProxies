cmake_minimum_required (VERSION 2.6)
project (LIVEPROXIES)

set (CMAKE_C_FLAGS "--std=gnu99 -pthread ${CMAKE_C_FLAGS}")

add_executable(LiveProxies Base64.c Global.c Harvester.c Interface.c IPv6Map.c LiveProxies.c Logger.c ProxyLists.c ProxyRemove.c ProxyRequest.c Server.c PBKDF2.c SingleCheck.c HtmlTemplate.c Websocket.c)
target_link_libraries(LiveProxies event GeoIP crypto ssl python2.7 pcre config m util anl curl)
