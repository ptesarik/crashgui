#include "memviewchooser.h"
#include "ui_memviewchooser.h"

MemViewChooser::MemViewChooser(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MemViewChooser)
{
    ui->setupUi(this);

    // TBD: What should the defaults be?
    ui->cbText->setChecked(false);
    ui->dwordButton->setChecked(true);
    ui->littleEndian->setChecked(true);
}

MemViewChooser::~MemViewChooser()
{
    delete ui;
}

unsigned long long MemViewChooser::addr()
{
    bool ok;
    quint64 result = ui->startAddr->text().toULongLong(&ok, 0);

    if (ok)
    {
        return result;
    }
    else
    {
        // TBD - what's the error case
        return 0xFFFFFFFFFFFFFFFF;
    }
}

bool MemViewChooser::charView()
{
    return ui->cbText->isChecked();
}

OBJECT_ENDIANITY MemViewChooser::objectEndianity()
{
    if (ui->littleEndian->isChecked())
    {
        return LITTLE_ENDIAN_OBJECTS;
    }
    if (ui->bigEndian->isChecked())
    {
        return BIG_ENDIAN_OBJECTS;
    }

    // TBD: Is there a default or is there an error
    return LITTLE_ENDIAN_OBJECTS;
}

OBJECT_SIZE MemViewChooser::objectSize()
{
    if (ui->byteButton->isChecked())
    {
        return BYTE_OBJECTS;
    }
    if (ui->wordButton->isChecked())
    {
        return WORD_OBJECTS;
    }
    if (ui->dwordButton->isChecked())
    {
        return DWORD_OBJECTS;
    }
    if (ui->qwordButton->isChecked())
    {
        return QWORD_OBJECTS;
    }

    // TBD: Is there a default size or is there an error
    return DWORD_OBJECTS;
}

void MemViewChooser::on_cbText_clicked()
{
    ui->sizeGroup->setEnabled(!ui->cbText->isChecked());
    ui->endianGroup->setEnabled(!ui->cbText->isChecked());
}
