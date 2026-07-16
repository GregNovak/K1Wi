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
    
    QWidget *stringTab;
    QComboBox *stringInputModeCombo;
    QLineEdit *stringTextInput;
    QLineEdit *stringFilePath;
    QCheckBox *stringDecodeCheck;
    QLineEdit *stringMinLength;
    QTextEdit *stringOutputLog;
    
    QWidget *magicTab;
    QLineEdit *magicTargetPath;
    QTextEdit *magicOutputLog;
    
    QWidget *entropyTab;
    QComboBox *entropyModeCombo;
    QLineEdit *entropyTargetPath;
    QTextEdit *entropyOutputLog;
    
    QWidget *pcapTab;
    QTabWidget *pcapDetailsTabs;
    QComboBox *pcapModeCombo;
    QLineEdit *pcapTargetPath;
    QTextEdit *pcapFindingsLog;
    QTextEdit *pcapNetworkLog;
    QTextEdit *pcapTransportLog;
    QTextEdit *pcapPayloadLog;
    QTextEdit *pcapOutputLog;

    void buildCopyTab();
    void buildLyzerTab();
    void buildExtractTab();
    void buildDelTab();
    void buildHashTab();
    void buildStringTab();
    void buildMagicTab();
    void buildEntropyTab();
    void buildPcapTab();
    
    void runCopyCommand();
    void runLyzerCommand();
    void runExtractCommand();
    void runDelCommand();
    void runHashCommand();
    void runStringCommand();
    void runMagicCommand();
    void runEntropyCommand();
    void runPcapCommand();
};

#endif
