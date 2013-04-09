#include "qmemview.h"

QMemView::QMemView(QWidget *parent) :
    QLabel(parent),
    addr(0),
    fileName("")
{
    setBackgroundRole(QPalette::Base);
    setText("Howdy!");
}

void QMemView::setAddr(unsigned long long newAddr, bool refresh)
{
    addr = newAddr;

    if (refresh)
        do_refresh();
}

void QMemView::setCharView(bool newCharView, bool refresh)
{
    charView = newCharView;

    if (refresh)
        do_refresh();
}

void QMemView::setEndianity(OBJECT_ENDIANITY newEndianity, bool refresh)
{
    if (newEndianity <= BIG_ENDIAN_OBJECTS)
    {
        endianity = newEndianity;

        if (refresh)
            do_refresh();
    }
}

void QMemView::setFileName(QString fname)
{
    fileName = fname;
    setWindowTitle(fileName);
    resize(230, 150);
}

void QMemView::setObjectSize(OBJECT_SIZE newObjSize, bool refresh)
{
    if (newObjSize <= QWORD_OBJECTS)
    {
        objSize = newObjSize;

        if (refresh)
            do_refresh();
    }
}
