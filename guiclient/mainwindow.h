#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include <QtGui/QMenuBar>
#include <QtGui/QMenu>
#include <QtGui/QAction>
#include <QtGui/QStatusBar>
#include <QMdiArea>
#include <QProcessEnvironment>
#include <QByteArray>


typedef enum mem_type
{
    KVADDR,
    UVADDR,
    PHYSADDR,
    XENMACHADDR,
    FILEADDR
}MEM_TYPE;

class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    MainWindow(QWidget *parent = 0);
    ~MainWindow();

    QByteArray readMemory(const QString &addr, unsigned int length, MEM_TYPE mt = KVADDR);

protected:
    int server;
    FILE *f;
    QString currentFilename;

    size_t linealloc;
    char *line;

    void retranslateUI();
    void setupUI();
    
    bool openServer(QString path);
    bool closeServer();

    QString sendCommand(const QString &cmd, const QString &Args);
    QString getReply();
    int getRaw(unsigned char **buf, int length);

    QString readAtom(QString &cmd);

private slots:
    void on_fileOpen();
    void on_MemView();

private:
    // UI
    QMdiArea *mdiView;
    QMenuBar *menuBar;
    QMenu *menu_File;
    QMenu *menu_Mem;
    QMenu *menu_Help;
    QAction *action_Open;
    QAction *action_MemView;
    QAction *actionE_xit;
    QAction *action_About;
    QStatusBar *statusBar;

    QProcessEnvironment env;
};

#endif // MAINWINDOW_H
