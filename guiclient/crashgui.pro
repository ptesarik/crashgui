#-------------------------------------------------
#
# Project created by QtCreator 2013-04-05T13:52:42
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = crashgui
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
        qmemview.cpp \
    memviewchooser.cpp

HEADERS  += mainwindow.h \
         qmemview.h \
	 guiserver.h \
    memviewchooser.h \
    memtypes.h

FORMS += \
    memviewchooser.ui
