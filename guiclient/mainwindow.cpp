#include "mainwindow.h"

#include <QtGui/QApplication>
#include <QFileDialog>
#include <QMdiSubWindow>

#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "memviewchooser.h"
#include "qmemview.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      server(-1),
      currentFilename(""),
      env(QProcessEnvironment::systemEnvironment())
{
    setupUI();
}

MainWindow::~MainWindow()
{
    
}

void MainWindow::retranslateUI()
{
    setWindowTitle(QApplication::translate("MainWindow", "MemView", 0, QApplication::UnicodeUTF8));
    menu_File->setTitle(QApplication::translate("MainWindow", "&File", 0, QApplication::UnicodeUTF8));
    menu_Mem->setTitle(QApplication::translate("MainWindow", "&Memory", 0, QApplication::UnicodeUTF8));
    menu_Help->setTitle(QApplication::translate("MainWindow", "&Help", 0, QApplication::UnicodeUTF8));
    action_Open->setText(QApplication::translate("MainWindow", "&Open", 0, QApplication::UnicodeUTF8));
    action_MemView->setText(QApplication::translate("MainWindow", "&View", 0, QApplication::UnicodeUTF8));
    actionE_xit->setText(QApplication::translate("MainWindow", "E&xit", 0, QApplication::UnicodeUTF8));
    action_About->setText(QApplication::translate("MainWindow", "&About", 0, QApplication::UnicodeUTF8));
}

void MainWindow::setupUI()
{
    if (objectName().isEmpty())
        setObjectName(QString::fromUtf8("MainWindow"));

    resize(460, 378);

    action_Open = new QAction(this);
    action_Open->setObjectName(QString::fromUtf8("action_Open"));
    action_MemView = new QAction(this);
    action_MemView->setObjectName(QString::fromUtf8("action_MemView"));
    actionE_xit = new QAction(this);
    actionE_xit->setObjectName(QString::fromUtf8("actionE_xit"));
    action_About = new QAction(this);
    action_About->setObjectName(QString::fromUtf8("action_About"));

    mdiView = new QMdiArea(this);
    mdiView->setObjectName(QString::fromUtf8("mdiView"));
    setCentralWidget(mdiView);

    menuBar = new QMenuBar(this);
    menuBar->setObjectName(QString::fromUtf8("menuBar"));
    menuBar->setGeometry(QRect(0, 0, width(), 20));

    menu_File = new QMenu(menuBar);
    menu_File->setObjectName(QString::fromUtf8("menu_File"));

    menu_Mem = new QMenu(menuBar);
    menu_Mem->setObjectName(QString::fromUtf8("menu_Mem"));

    menu_Help = new QMenu(menuBar);
    menu_Help->setObjectName(QString::fromUtf8("menu_Help"));

    setMenuBar(menuBar);

    statusBar = new QStatusBar(this);
    statusBar->setObjectName(QString::fromUtf8("statusBar"));
    setStatusBar(statusBar);

    menuBar->addAction(menu_File->menuAction());
    menuBar->addAction(menu_Mem->menuAction());
    menuBar->addAction(menu_Help->menuAction());
    menu_File->addAction(action_Open);
    menu_File->addSeparator();
    menu_File->addAction(actionE_xit);
    menu_Mem->addAction(action_MemView);
    menu_Help->addAction(action_About);

    retranslateUI();

    QObject::connect(actionE_xit, SIGNAL(triggered()), this, SLOT(close()));
    QObject::connect(action_Open, SIGNAL(triggered()), this, SLOT(on_fileOpen()));
    QObject::connect(action_MemView, SIGNAL(triggered()), this, SLOT(on_MemView()));
}

void MainWindow::on_fileOpen()
{
    QMdiSubWindow *memframe;
    QMemView *memview;

    currentFilename = "";
    currentFilename = QFileDialog::getOpenFileName(this,
         tr("Open File"), env.value("HOME"), tr("Files (*)"));
    if (!currentFilename.isEmpty())
    {
        memview = new QMemView;
        memview->setFileName(currentFilename);
        memframe = mdiView->addSubWindow(memview);
        memframe->show();
    }
}

void MainWindow::on_MemView()
{
    int addr;
    QMdiSubWindow *memframe;
    QMemView *memview;
    MemViewChooser settings;

    if (settings.exec() == QDialog::Accepted)
    {
        addr = settings.addr();
        memview = new QMemView;
        memview->setFileName(currentFilename);
        memview->setAddr(0);
        memframe = mdiView->addSubWindow(memview);
        memframe->show();
    }
}

bool MainWindow::openServer(QString path)
{
    size_t sz = offsetof(struct sockaddr_un, sun_path) + path.length() + 1;
    struct sockaddr_un *sun;
    int fd;
    bool connected = false;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
      goto err;
    }

    if (!(sun = (struct sockaddr_un *)malloc(sz)))
    {
      goto err_close;
    }

    sun->sun_family = AF_UNIX;
    strcpy(sun->sun_path, path.toAscii());

    if (::connect(fd, (struct sockaddr *)sun, sz) == 0)
    {
      connected = true;
    }

    free(sun);
    if (connected)
    {
        server = fd;
        return true;
    }

err_close:
    ::close(fd);

err:
    return connected;
}

bool MainWindow::closeServer()
{
    if ((server != -1) && ::close(server) != -1)
        server = -1;

    return (server == -1);
}

QString MainWindow::sendCommand(QString cmd, QString Args)
{
    int bufLen;
    int replyEnd;
    unsigned char buf[100];
    int buflen = sizeof(buf);
    QString cmdLine;
    QString result;

    if (server != -1)
    {
        cmdLine = cmd;
        cmdLine += ' ';
        cmdLine += Args;
        cmdLine += "\r\n";

        if (::write(server, cmdLine.toAscii(), cmdLine.length()) == cmdLine.length())
        {
            replyEnd = ::read(server, buf, buflen);
        }
    }

    return result;
}
