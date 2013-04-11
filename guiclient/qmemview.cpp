#include "qmemview.h"

QMemView::QMemView(QWidget *parent) :
    QLabel(parent),
    mainWindow(NULL),
    vsb(this),
    addr(0),
    fileName("")
{
    setBackgroundRole(QPalette::Base);

    // Switch to a fixed-pitch font
    QFont fnt = font();
    fnt.setFamily("Courier");
    fnt.setFixedPitch(true);
    setFont(fnt);

    vsb.setRange(0, 0x7FFFFFFF);
    vsb.setVisible(true);
}

void QMemView::resizeEvent(QResizeEvent *event)
{
    QSize sbSize = event->size();
    sbSize.setWidth(vsb.width());

    QResizeEvent sbEvent(sbSize, vsb.size());

    // Any base class handling?
    QLabel::resizeEvent(event);

    // Force the scrollbar to change height only
    vsb.resize(sbSize);
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
