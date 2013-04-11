#ifndef QMEMVIEW_H
#define QMEMVIEW_H

#include <QLabel>
#include <QScrollBar>
#include <QResizeEvent>

#include <QDebug>

#include "memtypes.h"
#include "mainwindow.h"

#define TEXT_MARGIN 4

class QMemView : public QWidget
{
    Q_OBJECT
public:
    explicit QMemView(QWidget *parent = 0);

    void setMainWindow(MainWindow *newMainWindow)
    {
        mainWindow = newMainWindow;
    }

    QSize sizeHint() const;

    void setAddr(unsigned long long newAddr, bool refresh = false);
    void setCharView(bool newCharView = true, bool refresh = false);
    void setEndianity(OBJECT_ENDIANITY newEndianity, bool refresh = false);
    void setFileName(QString fname);
    void setObjectSize(OBJECT_SIZE newObjSize, bool refresh = false);
    void setMemType(MEM_TYPE newMemType, bool refresh = false);

    void setView(unsigned long long newAddr, bool newCharView, OBJECT_SIZE newObjSize, OBJECT_ENDIANITY newEndianity, MEM_TYPE newMemType, bool refresh = true)
    {
        setAddr(newAddr);
        setCharView(newCharView);
        setObjectSize(newObjSize);
        setEndianity(newEndianity);
        setMemType(newMemType);
        if (refresh)
            do_refresh();
    }

    void do_refresh();

protected:
    void paintEvent(QPaintEvent *event);
    virtual void resizeEvent(QResizeEvent * event);

    int getPreferredSizeInfo();
    int getPreferredWidth() const;
    QString createMemoryLine(unsigned long offset);

    MainWindow *mainWindow;
    QFont viewFont;
    QSize lineHeight;
    QSize charViewSize;
    QSize byteViewSize;
    QSize wordViewSize;
    QSize dwordViewSize;
    QSize qwordViewSize;
    QScrollBar vsb;
    int curScroll;
    unsigned long long addr;
    bool charView;
    OBJECT_ENDIANITY endianity;
    QString fileName;
    OBJECT_SIZE objSize;
    MEM_TYPE memType;

    QByteArray currentView;

signals:
    
public slots:
    void scrolled(int value);
};

#endif // QMEMVIEW_H
