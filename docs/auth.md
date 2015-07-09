Preparing users for interface pages
===================
To begin adding users available for login in interface pages, launch program with `passwd` parameter, like so:
```
./LiveProxies passwd
```
The program will ask you for `username`, `password` and `passwd.conf` storage place to use - either in working directory, or `/etc/liveproxies`. After entering details, restart all instances of program.

**Now, when entering any interface page, program will ask for authorization.**