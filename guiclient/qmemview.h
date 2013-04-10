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
        int n, m;
        unsigned char byteVal;
        QString display;
        QString ws;

        // TBBD: Pick a memory type
        currentView = mainWindow->readMemory(QString::number(addr, 10), 4096, PHYSADDR);

        for(n = 0; n < currentView.length(); n++)
        {
            byteVal = (unsigned char)currentView.at(n);

            if ((n % 16) == 0)
            {
                if (n != 0)
                    display += "\n";
                ws = QString::number(n, 16);
                for(m = ws.length(); m < 16; m++)
                {
                    ws.prepend('0');
                }
                ws.prepend("  ");
                display += ws;
            }

            display += "  ";
            ws = QString::number(byteVal, 16);
            for(m = ws.length(); m < 2; m++)
            {
                ws.prepend('0');
            }
            display += ws;
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
