#include <QFontMetrics>
#include <QPainter>

#include "qmemview.h"

QMemView::QMemView(QWidget *parent) :
    mainWindow(NULL),
    vsb(Qt::Vertical, this),
    addr(0),
    fileName("")
{
    (void)parent;

    setAutoFillBackground(true);
    setBackgroundRole(QPalette::Base);
    setBaseSize(sizeHint());
    setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    updateGeometry();

    // Switch to a fixed-pitch font
    viewFont = font();
    viewFont.setFamily("Courier");
    viewFont.setFixedPitch(true);
    setFont(viewFont);
    viewFont = font();

    // Get the font metrics
    (void)getPreferredSizeInfo();

//    vsb.setRange(0, 0x7FFFFFFF);
    vsb.setVisible(true);
    if (addr != 0)
    {
        curScroll = 50;
    }
    else
    {
        curScroll = 0;
    }
    // TBD: Need to do an end of memory detection for end of scroll-bar

    QObject::connect(&vsb, SIGNAL(valueChanged(int)), this, SLOT(scrolled(int)));

    vsb.setValue(curScroll);
}

int QMemView::getPreferredSizeInfo()
{
    int width;

    viewFont = font();
    QFontMetrics fm(viewFont);

    lineHeight = fm.size(0, "88888888\n88888888\n88888888\n88888888\n88888888\n88888888\n88888888\n88888888\n88888888\n88888888");
    charViewSize = fm.size(0, "8888888888888888  8  8  8  8  8  8  8  8  8  8  8  8  8  8  8  8");
    byteViewSize = fm.size(0, "8888888888888888  88  88  88  88  88  88  88  88  88  88  88  88  88  88  88  88");
    wordViewSize = fm.size(0, "8888888888888888  8888  8888  8888  8888  8888  8888  8888  8888");
    dwordViewSize = fm.size(0, "8888888888888888  88888888  88888888  88888888  88888888");
    qwordViewSize = fm.size(0, "8888888888888888  8888888888888888  8888888888888888");
    qDebug() << "Worst font metrics are " << charViewSize.width() << " x " << lineHeight.height();

    width = getPreferredWidth();

    return width;
}

int QMemView::getPreferredWidth() const
{
    int width;

    width = vsb.width() + TEXT_MARGIN;

    // Decide which width applies and return it
    if (charView)
    {
        width += charViewSize.width();
    }
    else
    {
        switch (objSize)
        {
        case BYTE_OBJECTS:
        default:
            width += byteViewSize.width();
            break;

        case WORD_OBJECTS:
            width += wordViewSize.width();
            break;

        case DWORD_OBJECTS:
            width += dwordViewSize.width();
            break;

        case QWORD_OBJECTS:
            width += qwordViewSize.width();
            break;
        }
    }

    return width;
}

QSize QMemView::sizeHint() const
{
    QString format;
    QSize room;

    room.setHeight(lineHeight.height());
    room.setWidth(getPreferredWidth());

    return room;
}

void QMemView::resizeEvent(QResizeEvent *event)
{
    QSize sbSize = event->size();
    sbSize.setWidth(vsb.width());

    QResizeEvent sbEvent(sbSize, vsb.size());

    // Any base class handling?
    QWidget::resizeEvent(event);

    // Force the scrollbar to change height only
    vsb.resize(sbSize);
}

void QMemView::paintEvent(QPaintEvent *event)
{
    int ht;
    unsigned long pos;
    QSize rect;
    QString readAddrStr = QString::number(addr, 10);
    QString line;

    QPainter paint(this);

    (void)event;

    viewFont = font();
    QFontMetrics fm(viewFont);

    // While we have vertical space, write each line
    ht = (lineHeight.height() / 10);
    pos = 0;
    while (ht < height())
    {
        line = createMemoryLine(pos);
        if (line.length() > 0)
        {
            rect = fm.size(0, line);

            paint.drawText(4, ht, line);

            ht += rect.height();
            pos += 16;
        }
        else
        {
            // TBD: Read more memory
            break;
        }
    }
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

void QMemView::setMemType(MEM_TYPE newMemType, bool refresh)
{
    if (newMemType <= FILEADDR)
    {
        memType = newMemType;

        if (refresh)
            do_refresh();
    }
}

QString QMemView::createMemoryLine(unsigned long offset)
{
    int i, n, m, step;
    unsigned long long readAddr = addr + offset;
    QString ws, wordws;
    QString display;
    QChar byteVal;

    if (!charView)
    {
        switch (objSize)
        {
        case BYTE_OBJECTS:
            step = 1;
            break;

        case WORD_OBJECTS:
            step = 2;
            break;

        case DWORD_OBJECTS:
            step = 4;
            break;

        case QWORD_OBJECTS:
            step = 8;
            break;

        default:
            step = 1;
            break;
        }
    }
    else
    {
        // Char view has object size 1
        step = 1;
    }

//    qDebug() << "Trying a line with step: " << step;
//    qDebug() << "CurrentView length is: " << currentView.length();

    // TBD: Do what if the currentView.length() is not an integer multiple of the step size?

//    for(n = 0; n < currentView.length(); n += step)
    for(n = 0; n < 16; n += step)
    {
        if ((offset + n) >= currentView.length())
            break;

        if ((n % 16) == 0)
        {
//            if (n != 0)
//                display += "\n";
            ws = QString::number(readAddr + n, 16);
            for(m = ws.length(); m < 16; m++)
            {
                ws.prepend('0');
            }
            ws.prepend("  ");
            display += ws;
        }

        display += "  ";

        wordws = "";
        for (i = 0; i < step; i++)
        {

            byteVal = currentView.at(n + i);

            if (!charView)
            {
                ws = QString::number((unsigned char)byteVal.toAscii(), 16);
                for(m = ws.length(); m < 2; m++)
                {
                    ws.prepend('0');
                }

                if (endianity == LITTLE_ENDIAN_OBJECTS)
                {
                    wordws.prepend(ws);
                }
                else
                {
                    wordws += ws;
                }
            }
            else
            {
                if (byteVal.isPrint())
                {
                    wordws += byteVal;
                }
                else
                {
                    wordws += '.';
                }
            }
        }

        display += wordws;
    }

    return display;
}

void QMemView::do_refresh()
{
    QString readAddrStr = QString::number(addr, 10);
    unsigned long long readAddr;
    bool ok;

    currentView = mainWindow->readMemory(readAddrStr, 4096);

    // Use the response address for display
    readAddr = readAddrStr.toULongLong(&ok);
    if (ok)
    {
        addr = readAddr;
    }

    qDebug() << "Refreshing window from read of " << currentView.length() << " bytes";

    update();
    updateGeometry();
}

void QMemView::scrolled(int value)
{
    int rePos = (value - curScroll);
    bool negative = (rePos < 0);
    int lines;
    unsigned long offset;
    QSize ourSize;

    qDebug() << "SCROLLED from cur-value " << curScroll << " to " << value;

    if (curScroll != value)
    {
        // How many lines can we fit
        ourSize = size();
        lines = ourSize.height() / (lineHeight.height() / 10);
        lines--;

        // Detect the re-position
        if (rePos == 1)
        {
            offset = rePos * 16;
        }
        else if (rePos == -1)
        {

            offset = (0 - rePos) * 16;
        }
        else // if (rePos != +/-1)
        {
            offset = lines * 16;
        }

        // Eliminate scroll out of ranges
        if (negative && (offset >= addr))
        {
            offset = addr;
            curScroll = 0;
        }
        else
        {
            curScroll = 50;
        }
        // TBD the same for an end of memory value

        // Do a readmem for the new address
        if (negative)
            addr -= offset;
        else
            addr += offset;

        vsb.setValue(curScroll);
        do_refresh();
    }
}
