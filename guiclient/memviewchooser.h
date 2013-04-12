#ifndef MEMVIEWCHOOSER_H
#define MEMVIEWCHOOSER_H

#include <QDialog>

#include "qmemview.h"

namespace Ui {
class MemViewChooser;
}

class MemViewChooser : public QDialog
{
    Q_OBJECT
    
public:
    explicit MemViewChooser(QWidget *parent = 0);
    ~MemViewChooser();

    unsigned long long addr();
    QString symbol();
    bool charView();
    OBJECT_ENDIANITY objectEndianity();
    OBJECT_SIZE objectSize();
    MEM_TYPE memoryType();

private slots:
    void on_cbText_clicked();

private:
    Ui::MemViewChooser *ui;
};

#endif // MEMVIEWCHOOSER_H
