#include "mainwindow.h"

#include <QtGui/QApplication>
#include <QFileDialog>
#include <QMdiSubWindow>

#include <QDebug>

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "memviewchooser.h"
#include "qmemview.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      server(-1),
      f(NULL),
      currentFilename(""),
      line(NULL),
      env(QProcessEnvironment::systemEnvironment())
{
    setupUI();
}

MainWindow::~MainWindow()
{
    if (line)
    {
        free(line);
        line = NULL;
    }

    closeServer();
}

void MainWindow::retranslateUI()
{
    setWindowTitle(QApplication::translate("MainWindow", "MemView", 0, QApplication::UnicodeUTF8));
    menu_File->setTitle(QApplication::translate("MainWindow", "&File", 0, QApplication::UnicodeUTF8));
    menu_Mem->setTitle(QApplication::translate("MainWindow", "&Memory", 0, QApplication::UnicodeUTF8));
    menu_Help->setTitle(QApplication::translate("MainWindow", "&Help", 0, QApplication::UnicodeUTF8));
    action_New->setText(QApplication::translate("MainWindow", "&New", 0, QApplication::UnicodeUTF8));
    action_Open->setText(QApplication::translate("MainWindow", "&Open", 0, QApplication::UnicodeUTF8));
    action_Close->setText(QApplication::translate("MainWindow", "&Close", 0, QApplication::UnicodeUTF8));
    action_Term->setText(QApplication::translate("MainWindow", "&Terminate Server", 0, QApplication::UnicodeUTF8));
    action_MemView->setText(QApplication::translate("MainWindow", "&View", 0, QApplication::UnicodeUTF8));
    actionE_xit->setText(QApplication::translate("MainWindow", "E&xit", 0, QApplication::UnicodeUTF8));
    action_About->setText(QApplication::translate("MainWindow", "&About", 0, QApplication::UnicodeUTF8));
}

void MainWindow::setupUI()
{
    if (objectName().isEmpty())
        setObjectName(QString::fromUtf8("MainWindow"));

//    resize(460, 378);

    action_New = new QAction(this);
    action_New->setObjectName(QString::fromUtf8("action_New"));
    action_Open = new QAction(this);
    action_Open->setObjectName(QString::fromUtf8("action_Open"));
    action_Close = new QAction(this);
    action_Close->setObjectName(QString::fromUtf8("action_Close"));
    action_Term = new QAction(this);
    action_Term->setObjectName(QString::fromUtf8("action_Term"));
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
    menu_File->addAction(action_New);
    menu_File->addAction(action_Open);
    menu_File->addAction(action_Close);
    menu_File->addAction(action_Term);
    menu_File->addSeparator();
    menu_File->addAction(actionE_xit);
    menu_Mem->addAction(action_MemView);
    menu_Help->addAction(action_About);

    retranslateUI();

    QObject::connect(actionE_xit, SIGNAL(triggered()), this, SLOT(close()));
    QObject::connect(action_New, SIGNAL(triggered()), this, SLOT(on_fileNew()));
    QObject::connect(action_Open, SIGNAL(triggered()), this, SLOT(on_fileOpen()));
    QObject::connect(action_Close, SIGNAL(triggered()), this, SLOT(on_fileClose()));
    QObject::connect(action_Term, SIGNAL(triggered()), this, SLOT(on_fileTerm()));
    QObject::connect(action_MemView, SIGNAL(triggered()), this, SLOT(on_MemView()));
}

void MainWindow::on_fileNew()
{
}

void MainWindow::on_fileOpen()
{
    closeServer();
    currentFilename = QFileDialog::getOpenFileName(this,
         tr("Open File"), env.value("HOME"), tr("Files (*)"));
    if (!currentFilename.isEmpty())
    {
        openServer(currentFilename);
    }
}

void MainWindow::on_fileClose()
{
    closeServer();
}

void MainWindow::on_fileTerm()
{
    terminateServer();
}

void MainWindow::on_MemView()
{
    unsigned long long addr;
    OBJECT_SIZE objSize;
    OBJECT_ENDIANITY endianity;
    MEM_TYPE mt;
    bool charView;
    QString symbolName;
    QMdiSubWindow *memframe;
    QMemView *memview;
    MemViewChooser settings;

    if (settings.exec() == QDialog::Accepted)
    {
        objSize = settings.objectSize();
        endianity = settings.objectEndianity();
        charView = settings.charView();
        mt = settings.memoryType();

        if (currentFilename.length() == 0)
        {
            openServer(currentFilename);
        }

        addr = settings.addr();
        if (addr == BAD_SYMBOL)
        {
            symbolName = settings.symbol();
            addr = symbolAddress(symbolName);
        }

        if (addr != BAD_SYMBOL)
        {
            memview = new QMemView;
            qDebug() << "Server is: " << server;
            memview->setMainWindow(this);
            memview->setFileName(currentFilename);
            memview->setAddr(addr);
            if (charView)
                memview->setCharView();
            else
            {
                memview->setCharView(false);
                memview->setObjectSize(objSize);
                memview->setEndianity(endianity);
                memview->setMemType(mt);
            }
            memframe = mdiView->addSubWindow(memview);
            memframe->show();
            memview->do_refresh();
        }
        else
        {
            qDebug() << "ERROR ADDRESS WITH MEMVIEWER";
        }
    }
}

bool MainWindow::openServer(QString path)
{
    size_t sz = offsetof(struct sockaddr_un, sun_path) + path.length() + 1;
    struct sockaddr_un *sun;
    int fd;
    QString greeting;
    bool connected = false;

    qDebug() << "openServer: " << path;
    qDebug() << "current fd is " << QString::number(server, 10);

    if (server == -1)
    {
        qDebug() << "Trying to connect";

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
        {
            qDebug() << "socket failed";
            goto err;
        }
        else
        {
            qDebug() << "socket succeeds, fd is " << QString::number(fd, 10);
        }

        if (!(sun = (struct sockaddr_un *)malloc(sz)))
        {
            qDebug() << "malloc failed";
            goto err_close;
        }
        else
        {
            qDebug() << "sockaddr malloc succeeds";
        }

        sun->sun_family = AF_UNIX;
        strcpy(sun->sun_path, path.toAscii());

        if (::connect(fd, (struct sockaddr *)sun, sz) == 0)
        {
            qDebug() << "connect succeeds";

            f = ::fdopen(fd, "r+");
            if (fd)
            {
                qDebug() << "fd duplicated";
                connected = true;
            }
        }
        else
            qDebug() << "connect failed";

        free(sun);
        if (connected)
        {
            server = fd;

            qDebug() << "Verifying the greeting";

            // Receive and verify the greeting
            greeting = getReply();
            qDebug() << "Greeting is: " << greeting;
            if ((greeting.length() > 0)
                    && (greeting.indexOf("OK") > 0)
                    && (greeting.indexOf("crashgui server ready.") > 0))
            {
                qDebug() << "Handled greeting";
                return true;
            }
        }

err_close:
        ::close(fd);
    }
    else
    {
        qDebug() << "Already connected";
        connected = true;
    }

err:
    return connected;
}

bool MainWindow::closeServer()
{
    QString result;

    if (server != -1)
    {
        qDebug() << "Terminating server...";
        result = sendCommand(QString("DISCONNECT"), QString(""));

        if (::fclose(f) == 0)
        {
            f = NULL;
            server = -1;
            currentFilename = "";
        }

        qDebug() << "Done";
    }

    return (server == -1);
}

bool MainWindow::terminateServer()
{
    QString result;

    if (server != -1)
    {
        qDebug() << "Terminating server...";
        result = sendCommand(QString("TERMINATE"), QString(""));

        if (::fclose(f) == 0)
        {
            f = NULL;
            server = -1;
        }

        qDebug() << "Done";
    }

    return (server == -1);
}

QString MainWindow::sendCommand(const QString &cmd, const QString &Args)
{
    QString cmdLine;
    QString reply;

    qDebug() << "sendCommand to server: " << QString::number(server, 10);

    if (server != -1)
    {
        // TBD: Add a tag first
        cmdLine = "* ";
        cmdLine += cmd;
        if (Args.length() > 0)
        {
            cmdLine += ' ';
            cmdLine += Args;
        }
        cmdLine += "\r\n";

        qDebug() << "Sending command: " << cmdLine;

        if (::fwrite(cmdLine.toAscii(), 1, cmdLine.length(), f) == (size_t)cmdLine.length())
        {
            reply = getReply();
        }
        else
            qDebug() << "Write didn\'t match command line length\n";
    }

    return reply;
}

QString MainWindow::getReply()
{
    ssize_t length;
    QString reply;

    if (server != -1)
    {
        length = getline(&line, &linealloc, f);
        if (length > 0)
        {
            if (line[--length] == '\n')
            {
                if ((length > 0) && (line[length - 1] == '\r'))
                {
                    line[--length] = 0;
                    reply = line;
                }
            }
        }
    }

    return reply;
}

QString MainWindow::readAtom(QString &cmd)
{
    int spacePos;
    QString result;

    qDebug() << "Getting an atom from: " << cmd;

    spacePos = cmd.indexOf(" ");
    if (spacePos >= 0)
    {
        result = cmd.left(spacePos);
        cmd = cmd.right(cmd.length() - spacePos - 1);
    }
    else
    {
        spacePos = 0;
        result = cmd;
        cmd = QString("");
    }

    qDebug() << "Reducing cmd to: " << cmd;
    qDebug() << "Returning atom: " << result;

    return result;
}

int MainWindow::getRaw(unsigned char **buf, int length)
{
    ssize_t rdlen;

    if (server != -1)
    {
        if (! *buf)
        {
            *buf = (unsigned char *)malloc(length);
            if (! *buf)
            {
                return -1;
            }
        }
        rdlen = ::fread(*buf, 1, length, f);
    }

    return rdlen;
}

QByteArray MainWindow::readMemory(QString &addr, unsigned int length, MEM_TYPE mt)
{
    QString cmdLine;
    QString ws;
    QString reply;
    QString atom;
    bool ok;
    int byteCount = 0;
    int rdLen;
    int n;
    unsigned char *buf = NULL;
    // TBD: Is this safe to use for unsigned char content?
    QByteArray result;

    qDebug() << "Read memory: " << addr << QString::number(length, 16);

    cmdLine += addr;
    cmdLine += " ";
    ws += QString::number(length, 16);
    cmdLine += ws;
    switch (mt)
    {
    case KVADDR:
        cmdLine += " KVADDR";
        break;

    case UVADDR:
        cmdLine += " UVADDR";
        break;

    case PHYSADDR:
        cmdLine += " PHYSADDR";
        break;

    case XENMACHADDR:
        cmdLine += XENMACHADDR;
        break;

    case FILEADDR:
        cmdLine += FILEADDR;
        break;

    default:
        cmdLine += " KVADDR";
        break;
    }

    qDebug() << "READMEM " << cmdLine;

    reply = sendCommand(QString("READMEM"), cmdLine);

    qDebug() << "Reply length is " << reply.length();
    qDebug() << "Reply is " << reply;

    if (reply.length() > 0)
    {
        // Check for a DUMP response
        while ((byteCount == 0) && (reply.length() > 0))
        {
            atom = readAtom(reply);
            if (atom.startsWith("DUMP"))
            {
                // Replace the supplied address with the one in the DUMP response
                addr = readAtom(reply);

                atom = readAtom(reply);
                if (atom.startsWith("{") && atom.endsWith("}"))
                {
                    atom = atom.mid(1, atom.length() - 2);
                    byteCount = atom.toInt(&ok);
                    qDebug() << "Byte count from atom is " << byteCount;
                    if (!ok)
                        byteCount = 0;
                    qDebug() << "Byte count adjusted to " << byteCount;
                }
                else
                    qDebug() << "This is not a bytecount atom: " << atom;
            }
        }

        if (byteCount > 0)
        {
            // Got a byte count, read that much raw
            rdLen = getRaw(&buf, byteCount);
            if (rdLen == byteCount)
            {
                for (n = 0; n < byteCount; n++)
                {
                    result.append(buf[n]);
                }
            }
            if (buf != NULL)
            {
                free(buf);
                buf = NULL;
            }
        }
        qDebug() << "Binary data length: " << byteCount << " (" << result.length() << ")";

        // Get the remainder of the second line
        reply = getReply();
        qDebug() << "Second line reply length is " << reply.length();
    }

    return result;
}

unsigned long long MainWindow::symbolAddress(QString symName)
{
    QString reply;
    QString atom;
    QString symAddr;
    bool ok;
    unsigned long long result = BAD_SYMBOL;

    reply = sendCommand(QString("SYMBOL"), symName);
    qDebug() << "SYMBOL reply is " << reply;
    if (reply.length() > 0)
    {
        // Skip the tag
        atom = readAtom(reply);

        // Get the command
        atom = readAtom(reply);
        if (atom.startsWith("SYMBOL"))
        {
            // Get the address in the response
            symAddr = readAtom(reply);
            qDebug() << "Address atom is " << symAddr;

            // Get the rest of the reply
            reply = getReply();

            // Is it OK?
            atom = readAtom(reply);
            atom = readAtom(reply);
            if (atom != "OK")
            {
                result = BAD_SYMBOL;
            }
            else
            {
                result = symAddr.toULongLong(&ok, 16);
                qDebug() << "Address converts to " << result;
                if (!ok)
                    result = BAD_SYMBOL;
            }
        }
    }

    return result;
}
