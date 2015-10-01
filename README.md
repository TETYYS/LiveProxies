# LiveProxies
Latest Version: **0.9.1** (beta)

LiveProxies is a [high-performance](perf/perf.md) asynchronous proxy checker.

## Features
 - Utilizes Python scripts to harvest (or scrape) proxy lists
 - Analyzes proxy output headers and determines proxy anonymity being:
 - - When proxy reveals correct IP behind the proxy - **transparent**
 - - When proxy modifies or adds any kind of headers - **anonymous**
 - - When proxy headers match request headers - **max**
 - Doesn't require any external web servers for its interface and internal proxy checking page
 - Supports:
 - - HTTP
 - - HTTPS
 - - SOCKS4
 - - SOCKS4A
 - - SOCKS5
 - - SOCKS4 -> SSL
 - - SOCKS4A -> SSL
 - - SOCKS5 -> SSL
 - - SOCKS5 UDP association
 - ...

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

## Development
Push requests welcome. See TODO list.

## TODO
 - Custom page request automatization and interface
 - Windows support
 - Custom SOCKS5 UDP requests
 - Daemon mode
 - Change asynchronous DNS mode from thread to signal
 - Check and fix unicode
 - Suggesstions?

[libmaxminddb]:https://github.com/maxmind/libmaxminddb