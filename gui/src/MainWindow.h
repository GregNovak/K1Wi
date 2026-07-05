#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

class QTextEdit;
class QPushButton;
class QLineEdit;
class QCheckBox;
class QTabWidget;
class QWidget;
class QComboBox;

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
    QLineEdit *lyzerTargetPath;
    QComboBox *lyzerModeCombo;
    QTextEdit *lyzerOutputLog;

    QWidget *extractTab;
    QLineEdit *extractTargetPath;
    QTextEdit *extractOutputLog;

    void buildExtractTab();
    void buildCopyTab();
    void buildLyzerTab();
    void runCopyCommand();
    void runLyzerCommand();
    
};

#endif
