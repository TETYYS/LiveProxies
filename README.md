# LiveProxies
Latest Version: **1.0.1** (release) [![Travis-CI](https://api.travis-ci.org/TETYYS/LiveProxies.svg)](https://travis-ci.org/TETYYS/LiveProxies/)

LiveProxies is a [high-performance](perf/perf.md) asynchronous proxy checker.

## Download:
 - Windows (untested, outdated): [x86](https://github.com/TETYYS/LiveProxies/raw/devel/bin/win32_mingw/LiveProxies.1.0.0.x86.7z)
 - Linux: [Compile from source](https://github.com/TETYYS/LiveProxies.git)

## Features
 - Utilizes any scripts, manual addition, urls and static text files to get proxy lists
 - Analyzes proxy output headers and determines proxy anonymity being:
 - - When proxy reveals correct IP behind the proxy - **transparent**
 - - When proxy modifies or adds any kind of headers - **anonymous**
 - - When proxy headers match request headers - **max**
 - Doesn't require any external web servers for its interface and internal proxy checking page
 - Supports: HTTP, HTTPS, SOCKS4, SOCKS4A, SOCKS5, SOCKS4 -> SSL, SOCKS4A -> SSL, SOCKS5 -> SSL, SOCKS5 UDP association
 - Spamhaus, Project Honey Pot and StopForumSpam blacklist checks
 - Invalid or modified SSL certificate detection
 - <sub><sup>Custom requests to pages from interface</sup></sub>
 - <sub><sup>Multi custom requests from all checked proxies</sup></sub>

## Get it running
If you still haven't installed [depencencies](#dependencies):
```
apt-get install libevent-dev python2.7-dev libssl-dev libgeoip-dev libpcre3-dev libconfig-dev libmaxminddb0 libmaxminddb-dev mmdb-bin
```
### Compilation: 
```
cmake .
make
```
### Installation:
```
mkdir /etc/liveproxies
cp -R config/* /etc/liveproxies

nano /etc/liveproxies.conf # Modify configuration here, see docs/liveproxies.conf for commented file

mkdir /usr/local/share/GeoIP
wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz
gunzip GeoIP.dat.gz
mv GeoLite2-Country.mmdb /usr/local/share/GeoIP/
```
### Usage:

After running, you can access interface at [ip]:[server port]/

See [Prxsrc](docs/prxsrc.md) for importing proxies to LiveProxies. You can also import proxies in the interface.
 
See [Auth](docs/auth.md) for preparing users for interface. **Access to interface is blocked by default if no users are present.**

## Dependencies <a name="dependencies"></a>
 - libevent >= 2.1.5-beta
 - python >= 2.7
 - [libmaxminddb] (PPA ppa:maxmind/ppa)
 - libconfig
 - pcre
 - openssl
 - curl (this is not used as primary library for checking proxies)
 - Modified [madns] (included in files)

## Development
Push requests welcome. See TODO list.

## TODO
 - Daemon mode
 - Custom SOCKS5 UDP requests

## Screenshots

Two (5.6k and 350 prxs) proxy sources check timeline with 60000 ms global timeout and AcceptableSequentialFails 1.

Second proxy source is added at 11:00 and checked completely at 12:08.

First proxy source is added at 10:41 and checked completely 11:48

![1](https://github.com/TETYYS/LiveProxies/raw/devel/screenshots/1.png)

Tools

![2](https://github.com/TETYYS/LiveProxies/raw/devel/screenshots/2.png)

Checked proxies

![3](https://github.com/TETYYS/LiveProxies/raw/devel/screenshots/3.png)

Unchecked proxies

![4](https://github.com/TETYYS/LiveProxies/raw/devel/screenshots/4.png)

Home

![5](https://github.com/TETYYS/LiveProxies/raw/devel/screenshots/5.png)

### Bonus screenshots:

Most anonymous proxy (found in the wild)

![6](https://github.com/TETYYS/LiveProxies/raw/devel/screenshots/6.png)

Smash-on-keyboard reverse DNS (found in the wild)

![7](https://github.com/TETYYS/LiveProxies/raw/devel/screenshots/7.png)

Public proxy hosted by Google - no blacklist entries (found in the wild)

![8](https://github.com/TETYYS/LiveProxies/raw/devel/screenshots/8.png)

Most evil proxy (found in the wild)

![9](https://github.com/TETYYS/LiveProxies/raw/devel/screenshots/9.png)

Long run with AcceptableSequentialFails = 1

![10](https://github.com/TETYYS/LiveProxies/raw/devel/screenshots/10.png)

[libmaxminddb]:https://github.com/maxmind/libmaxminddb
[madns]:https://github.com/tiago4orion/madns