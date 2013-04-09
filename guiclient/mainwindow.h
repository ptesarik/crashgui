#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include <QtGui/QMenuBar>
#include <QtGui/QMenu>
#include <QtGui/QAction>
#include <QtGui/QStatusBar>
#include <QMdiArea>
#include <QProcessEnvironment>


class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    MainWindow(QWidget *parent = 0);
    ~MainWindow();

protected:
    int server;
    QString currentFilename;

    void retranslateUI();
    void setupUI();
    
    bool openServer(QString path);
    bool closeServer();
    QString sendCommand(QString cmd, QString Args);

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
