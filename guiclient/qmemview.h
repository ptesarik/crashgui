#ifndef QMEMVIEW_H
#define QMEMVIEW_H

#include <QLabel>

typedef enum
{
    BYTE_OBJECTS,
    WORD_OBJECTS,
    DWORD_OBJECTS,
    QWORD_OBJECTS
}OBJECT_SIZE;

typedef enum
{
    LITTLE_ENDIAN_OBJECTS,
    BIG_ENDIAN_OBJECTS
}OBJECT_ENDIANITY;

class QMemView : public QLabel
{
    Q_OBJECT
public:
    explicit QMemView(QWidget *parent = 0);

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

protected:
    unsigned long long addr;
    bool charView;
    OBJECT_ENDIANITY endianity;
    QString fileName;
    OBJECT_SIZE objSize;

    void do_refresh()
    {
    }
    
signals:
    
public slots:
    
};

#endif // QMEMVIEW_H
