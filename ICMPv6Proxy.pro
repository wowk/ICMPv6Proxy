TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        main.c \
    lib.c \
    fdb.c \
    icmp6.c

HEADERS += \
    proxy.h \
    lib.h \
    fdb.h \
    icmp6.h
