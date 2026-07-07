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
    QComboBox *copyModeCombo;
    QCheckBox *forceCheck;
    QTextEdit *outputLog;

    QWidget *lyzerTab;
    QLineEdit *lyzerTargetPath;
    QComboBox *lyzerModeCombo;
    QTextEdit *lyzerOutputLog;

    QWidget *extractTab;
    QLineEdit *extractTargetPath;
    QCheckBox *extractRecursiveCheck;
    QTextEdit *extractOutputLog;
    
    QWidget *delTab;
    QLineEdit *delTargetPath;
    QComboBox *delStandardCombo;
    QLineEdit *delCustomPassCount;
    QTextEdit *delOutputLog;
    
    QWidget *hashTab;
    QComboBox *hashAlgorithmCombo;
    QComboBox *hashModeCombo;
    QLineEdit *hashFilePath;
    QLineEdit *hashExpectedValue;
    QLineEdit *hashCompareFilePath;
    QTextEdit *hashOutputLog;

    void buildCopyTab();
    void buildLyzerTab();
    void buildExtractTab();
    void buildDelTab();
    void buildHashTab();
    
    void runCopyCommand();
    void runLyzerCommand();
    void runExtractCommand();
    void runDelCommand();
    void runHashCommand();
};

#endif
