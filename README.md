# c-vtapi
New life for VirusTotal API in C language

> **⚠️ Note** \
make sure you have some 
libc, linux, cc, meson/ninja \
and shared dependencies (1) jansson, curl

**(1) IF NOT PLEASE USE** ```-Dstatic=true```
**in meson, cause this project support static build**

## build
    meson setup build
    ninja -C build

## usage
    vtscan --apikey VT_APIKEY YOUR_FILE
vtscan is available for running through scripts
with VT_APIKEY environment variable, but if so
make sure this variable will never be exposed out of
the script
```
vtheads --dir SOME_DIR
```

## legacy usages
    url --apikey=YOUR_KEY --scan http://youtube.com
    url --apikey=YOUR_KEY --report http://youtube.com
    scan --help
    ./scan --apikey YOUR_KEY --filescan /bin/ls
    ./scan --apikey YOUR_KEY --report HASH
