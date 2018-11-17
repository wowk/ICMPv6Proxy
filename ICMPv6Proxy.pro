TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        main.c \
    lib.c \
    ndisc.c \
    table.c

HEADERS += \
    proxy.h \
    lib.h \
    ndisc.h \
    table.h
