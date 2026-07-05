#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

class QTextEdit;
class QPushButton;
class QLineEdit;
class QCheckBox;
class QTabWidget;
class QWidget;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

private:
    QTabWidget *tabs;

    QWidget *copyTab;
    QLineEdit *sourcePath;
    QLineEdit *destPath;
    QCheckBox *recursiveCheck;
    QCheckBox *forceCheck;
    QTextEdit *outputLog;

    QWidget *lyzerTab;
    QTextEdit *lyzerOutputLog;

    void buildCopyTab();
    void buildLyzerTab();
    void runCopyCommand();
};

#endif
