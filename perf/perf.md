# Performance tests
[Input](input.txt): 300 proxies (HTTP) (source: http://txt.proxyspy.net/proxy.txt)

Tests are highly inaccurate because of external proxy servers. Needs testing on reliable (preferable local, with random timeouts) proxy servers.

## LiveProxies (tested on 2015-08-31)
 - GlobalTimeout: **20000** ms
 - AcceptableSequentialFails: **1**
 - CheckingInterval: **1** ms

Notes:
 - Version: 0.7.2 (pre-release)
 - Not multi-threaded
 - Peak memory usage 10~ MB
 - Includes * second idle state

Time (sec)  | Result (proxies)
----------- | -------------
20          | 89
20          | 93
20          | 90
## [ProxyMaid](https://github.com/runarbu/ProxyMaid) (tested on 2015-08-30)
 - GlobalTimeout: **20000** ms
 - Threads: **50**

Notes:
 - Version: 1.0.0.12
 - Relies on untrusted proxy judge (http://azenv.net/)
 - Peak memory usage 45~ MB (program is .NET)
 - Threaded checking mechanism is the bottleneck. Times will increase on input size.

Time (sec)  | Result (proxies)
----------- | -------------
151         | 176
146         | 178
172         | 160
## [ProxyFire](http://www.proxyfire.net/) (tested on 2015-08-30)
 - Connect and receive timeout: 20
 - Threads: 1000
 - Retries: 2

Notes:
 - Version 1.25 (build 1015)
 - Freeware (threads capped at 1000)
 - Relies on untrusted proxy judge. [Settings `.png`](ProxyFireSettings.png)
 - Threaded checking mechanism is the bottleneck. Times will increase on input size.
 - **Imports only 226 proxies out of 300**
 - Peak memory usage 15~ MB (7~ MB according program)

Time (sec)  | Result (proxies)
----------- | -------------
160         | 154
158         | 140
154         | 159
## [node-proxy-checker](https://github.com/scastiel/node-proxy-checker) (tested on 2015-08-31)
 - Timeout: **20000** ms

Notes:
 - Version 1.0.0
 - Requires module modification to set timeout
 - Relies on untrusted external websites. Doesn't check for anonymity.
 - Peak memory usage 41~ MB

Time (sec)  | Result (proxies)
----------- | -------------
40          | 120
40          | 122
40          | 109