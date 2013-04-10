#ifndef QMEMVIEW_H
#define QMEMVIEW_H

#include <QLabel>

#include <QDebug>

#include "mainwindow.h"

typedef enum object_size
{
    BYTE_OBJECTS,
    WORD_OBJECTS,
    DWORD_OBJECTS,
    QWORD_OBJECTS
}OBJECT_SIZE;

typedef enum object_endianity
{
    LITTLE_ENDIAN_OBJECTS,
    BIG_ENDIAN_OBJECTS
}OBJECT_ENDIANITY;

class QMemView : public QLabel
{
    Q_OBJECT
public:
    explicit QMemView(QWidget *parent = 0);

    void setMainWindow(MainWindow *newMainWindow)
    {
        mainWindow = newMainWindow;
    }

    void setAddr(unsigned long long newAddr, bool refresh = false);
    void setCharView(bool newCharView = true, bool refresh = false);
    void setEndianity(OBJECT_ENDIANITY newEndianity, bool refresh = false);
    void setFileName(QString fname);
    void setObjectSize(OBJECT_SIZE newObjSize, bool refresh = false);

    void setView(unsigned long long newAddr, bool newCharView, OBJECT_SIZE newObjSize, OBJECT_ENDIANITY newEndianity, bool refresh = true)
    {
        setAddr(newAddr);
        setCharView(newCharView);
        setObjectSize(newObjSize);
        setEndianity(newEndianity);
        if (refresh)
            do_refresh();
    }

    void do_refresh()
    {
        int i, n, m, step;
        QChar byteVal;
        QString display;
        QString ws, wordws;
        QString readAddrStr = QString::number(addr, 10);
        unsigned long long readAddr;
        bool ok;

        // TBBD: Pick a memory type
        currentView = mainWindow->readMemory(readAddrStr, 4096, PHYSADDR);

        // Use the response address for display
        readAddr = readAddrStr.toULongLong(&ok);
        if (!ok)
        {
            readAddr = addr;
        }

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

        // TBD: Do what if the currentView.length() is not an integer multiple of the step size?

        for(n = 0; n < currentView.length(); n += step)
        {
            if ((n % 16) == 0)
            {
                if (n != 0)
                    display += "\n";
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
                    ws = QString::number(byteVal.toAscii(), 16);
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

        qDebug() << "Refresh window with " << display;

        setText(display);
    }

protected:
    MainWindow *mainWindow;
    unsigned long long addr;
    bool charView;
    OBJECT_ENDIANITY endianity;
    QString fileName;
    OBJECT_SIZE objSize;

    QByteArray currentView;

signals:
    
public slots:
    
};

#endif // QMEMVIEW_H
