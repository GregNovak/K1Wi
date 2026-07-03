#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

class QTextEdit;
class QPushButton;
class QLineEdit;
class QCheckBox;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

private:
    QLineEdit *sourcePath;
    QLineEdit *destPath;
    QCheckBox *recursiveCheck;
    QCheckBox *forceCheck;
    QTextEdit *outputLog;

    void runCopyCommand();
};

#endif
