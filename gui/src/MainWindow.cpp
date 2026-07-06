#include "MainWindow.h"
#include <QRegularExpression>
#include <QCheckBox>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QWidget>
#include <QDir>
#include <QFileInfo>
#include <QComboBox>

static const QString k1wiBinary = QStringLiteral("../bin/k1wi");

static QString stripAnsiCodes(const QString &text)
{
    static const QRegularExpression ansiPattern(
        QStringLiteral("\\x1B\\[[0-?]*[ -/]*[@-~]")
    );

    QString cleaned = text;
    cleaned.remove(ansiPattern);
    return cleaned;
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle("K1Wi Framework GUI");
    resize(900, 600);

    tabs = new QTabWidget(this);

    buildCopyTab();
    buildLyzerTab();
    buildExtractTab();
    buildDelTab();

    tabs->addTab(copyTab, "COPY");
    tabs->addTab(lyzerTab, "LYZER");
    tabs->addTab(extractTab, "EXTRACT");
    tabs->addTab(delTab, "DEL");

    setCentralWidget(tabs);
}

void MainWindow::buildCopyTab()
{
    copyTab = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(copyTab);

    QLabel *title = new QLabel("K1Wi Framework - COPY Prototype", copyTab);
    mainLayout->addWidget(title);

    QHBoxLayout *sourceLayout = new QHBoxLayout();
    sourcePath = new QLineEdit(copyTab);
    QPushButton *sourceBrowse = new QPushButton("Browse Source", copyTab);
    sourceLayout->addWidget(new QLabel("Source:", copyTab));
    sourceLayout->addWidget(sourcePath);
    sourceLayout->addWidget(sourceBrowse);
    mainLayout->addLayout(sourceLayout);

    QHBoxLayout *destLayout = new QHBoxLayout();
    destPath = new QLineEdit(copyTab);
    QPushButton *destBrowse = new QPushButton("Browse Destination", copyTab);
    destLayout->addWidget(new QLabel("Destination:", copyTab));
    destLayout->addWidget(destPath);
    destLayout->addWidget(destBrowse);
    mainLayout->addLayout(destLayout);

    QHBoxLayout *modeLayout = new QHBoxLayout();
    copyModeCombo = new QComboBox(copyTab);
    copyModeCombo->addItem("File copy", "file");
    copyModeCombo->addItem("Recursive directory copy", "recursive");
    modeLayout->addWidget(new QLabel("COPY mode:", copyTab));
    modeLayout->addWidget(copyModeCombo);
    mainLayout->addLayout(modeLayout);

    forceCheck = new QCheckBox("Force overwrite / merge existing destination", copyTab);
    mainLayout->addWidget(forceCheck);

    QPushButton *runButton = new QPushButton("Run COPY", copyTab);
    QPushButton *clearButton = new QPushButton("Clear Output", copyTab);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(runButton);
    buttonLayout->addWidget(clearButton);
    mainLayout->addLayout(buttonLayout);

    outputLog = new QTextEdit(copyTab);
    outputLog->setReadOnly(true);
    mainLayout->addWidget(outputLog);

    connect(sourceBrowse, &QPushButton::clicked, this, [this]() {
        QString path = QFileDialog::getExistingDirectory(this, "Select Source");
        if (!path.isEmpty()) {
            sourcePath->setText(path);
        }
    });

    connect(destBrowse, &QPushButton::clicked, this, [this]() {
        QString path = QFileDialog::getExistingDirectory(this, "Select Destination");
        if (!path.isEmpty()) {
            destPath->setText(path);
        }
    });

    connect(runButton, &QPushButton::clicked, this, &MainWindow::runCopyCommand);
    connect(clearButton, &QPushButton::clicked, outputLog, &QTextEdit::clear);
}

void MainWindow::buildLyzerTab()
{
    lyzerTab = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(lyzerTab);

    QLabel *title = new QLabel("K1Wi Framework - LYZER Prototype", lyzerTab);
    mainLayout->addWidget(title);

    QHBoxLayout *targetLayout = new QHBoxLayout();
    lyzerTargetPath = new QLineEdit(lyzerTab);
    QPushButton *targetBrowse = new QPushButton("Browse Target", lyzerTab);
    targetLayout->addWidget(new QLabel("Target:", lyzerTab));
    targetLayout->addWidget(lyzerTargetPath);
    targetLayout->addWidget(targetBrowse);
    mainLayout->addLayout(targetLayout);

    QHBoxLayout *modeLayout = new QHBoxLayout();
    lyzerModeCombo = new QComboBox(lyzerTab);
    lyzerModeCombo->addItem("Default analysis", "");
    lyzerModeCombo->addItem("Summary report", "--summary");
    lyzerModeCombo->addItem("Quiet report", "--quiet");
    lyzerModeCombo->addItem("JSON summary", "--json");
    lyzerModeCombo->addItem("Full analysis", "--full");
    lyzerModeCombo->addItem("Verbose analysis", "--verbose");
    lyzerModeCombo->addItem("ALL full analysis", "ALL");
    modeLayout->addWidget(new QLabel("LYZER mode:", lyzerTab));
    modeLayout->addWidget(lyzerModeCombo);
    mainLayout->addLayout(modeLayout);

    QPushButton *runButton = new QPushButton("Run LYZER", lyzerTab);
    QPushButton *clearButton = new QPushButton("Clear Output", lyzerTab);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(runButton);
    buttonLayout->addWidget(clearButton);
    mainLayout->addLayout(buttonLayout);

    lyzerOutputLog = new QTextEdit(lyzerTab);
    lyzerOutputLog->setReadOnly(true);
    lyzerOutputLog->append("[GUI] LYZER panel ready.");
    mainLayout->addWidget(lyzerOutputLog);

    connect(targetBrowse, &QPushButton::clicked, this, [this]() {
        QString path = QFileDialog::getOpenFileName(this, "Select LYZER Target");
        if (!path.isEmpty()) {
            lyzerTargetPath->setText(path);
        }
    });

    connect(runButton, &QPushButton::clicked, this, &MainWindow::runLyzerCommand);
    connect(clearButton, &QPushButton::clicked, lyzerOutputLog, &QTextEdit::clear);

}

void MainWindow::buildExtractTab()
{
    extractTab = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(extractTab);

    QLabel *title = new QLabel("K1Wi Framework - EXTRACT Prototype", extractTab);
    mainLayout->addWidget(title);

    QHBoxLayout *targetLayout = new QHBoxLayout();
    extractTargetPath = new QLineEdit(extractTab);
    QPushButton *targetBrowse = new QPushButton("Browse Target", extractTab);
    targetLayout->addWidget(new QLabel("Target:", extractTab));
    targetLayout->addWidget(extractTargetPath);
    targetLayout->addWidget(targetBrowse);
    mainLayout->addLayout(targetLayout);

    extractRecursiveCheck = new QCheckBox("Recursive extraction", extractTab);
    mainLayout->addWidget(extractRecursiveCheck);

    QPushButton *runButton = new QPushButton("Run EXTRACT", extractTab);
    QPushButton *clearButton = new QPushButton("Clear Output", extractTab);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(runButton);
    buttonLayout->addWidget(clearButton);
    mainLayout->addLayout(buttonLayout);

    extractOutputLog = new QTextEdit(extractTab);
    extractOutputLog->setReadOnly(true);
    extractOutputLog->append("[GUI] EXTRACT panel ready.");
    mainLayout->addWidget(extractOutputLog);

    connect(targetBrowse, &QPushButton::clicked, this, [this]() {
        QString path = QFileDialog::getOpenFileName(this, "Select EXTRACT Target");
        if (!path.isEmpty()) {
            extractTargetPath->setText(path);
        }
    });

    connect(runButton, &QPushButton::clicked, this, &MainWindow::runExtractCommand);

    connect(clearButton, &QPushButton::clicked, extractOutputLog, &QTextEdit::clear);
}

void MainWindow::buildDelTab()
{
    delTab = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(delTab);

    QLabel *title = new QLabel("K1Wi Framework - DEL Prototype", delTab);
    mainLayout->addWidget(title);

    QLabel *warning = new QLabel(
    "DEL permanently removes the selected file using the chosen deletion standard. "
    "Select the target carefully before continuing.",
    delTab
    );
    warning->setWordWrap(true);
    mainLayout->addWidget(warning);

    QHBoxLayout *targetLayout = new QHBoxLayout();
    delTargetPath = new QLineEdit(delTab);
    QPushButton *targetBrowse = new QPushButton("Browse Target", delTab);
    targetLayout->addWidget(new QLabel("Target:", delTab));
    targetLayout->addWidget(delTargetPath);
    targetLayout->addWidget(targetBrowse);
    mainLayout->addLayout(targetLayout);

    QHBoxLayout *standardLayout = new QHBoxLayout();
    
    delStandardCombo = new QComboBox(delTab);
    delStandardCombo->addItem("DoD-style 3-pass overwrite", "1");
    delStandardCombo->addItem("NIST-style single-pass zero overwrite", "2");
    delStandardCombo->addItem("Custom pass count", "3");
    standardLayout->addWidget(new QLabel("Deletion standard:", delTab));
    standardLayout->addWidget(delStandardCombo);
    mainLayout->addLayout(standardLayout);

    QHBoxLayout *customPassLayout = new QHBoxLayout();
    delCustomPassCount = new QLineEdit(delTab);
    delCustomPassCount->setPlaceholderText("1-33");
    delCustomPassCount->setEnabled(false);
    customPassLayout->addWidget(new QLabel("Custom passes:", delTab));
    customPassLayout->addWidget(delCustomPassCount);
    mainLayout->addLayout(customPassLayout);

    delConfirmCheck = new QCheckBox("Confirm file deletion", delTab);
    mainLayout->addWidget(delConfirmCheck);

    QHBoxLayout *confirmLayout = new QHBoxLayout();
    delConfirmText = new QLineEdit(delTab);
    delConfirmText->setPlaceholderText("Type DELETE to enable Run DEL");
    confirmLayout->addWidget(new QLabel("Confirm:", delTab));
    confirmLayout->addWidget(delConfirmText);
    mainLayout->addLayout(confirmLayout);

    QPushButton *runButton = new QPushButton("Run DEL", delTab);
    QPushButton *clearButton = new QPushButton("Clear Output", delTab);

    runButton->setEnabled(false);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(runButton);
    buttonLayout->addWidget(clearButton);
    mainLayout->addLayout(buttonLayout);

    delOutputLog = new QTextEdit(delTab);
    delOutputLog->setReadOnly(true);
    delOutputLog->append("[GUI] DEL panel ready.");
    delOutputLog->append("[GUI] DEL command wiring will be added after safety controls are verified.");
    mainLayout->addWidget(delOutputLog);

    connect(targetBrowse, &QPushButton::clicked, this, [this]() {
        QString path = QFileDialog::getOpenFileName(this, "Select DEL Target");
        if (!path.isEmpty()) {
            delTargetPath->setText(path);
        }
    });

    connect(delStandardCombo, &QComboBox::currentIndexChanged, this, [this](int) {
        const bool customSelected =
            delStandardCombo->currentData().toString() == QStringLiteral("3");

        delCustomPassCount->setEnabled(customSelected);

        if (!customSelected) {
            delCustomPassCount->clear();
        }
    });

    auto updateDelRunButton = [this, runButton]() {
        const bool confirmed =
            delConfirmCheck->isChecked() &&
            delConfirmText->text().trimmed() == QStringLiteral("DELETE");

        runButton->setEnabled(confirmed);
    };

    connect(delConfirmCheck, &QCheckBox::toggled, this, updateDelRunButton);
    connect(delConfirmText, &QLineEdit::textChanged, this, updateDelRunButton);

    connect(runButton, &QPushButton::clicked, this, &MainWindow::runDelCommand);

    connect(clearButton, &QPushButton::clicked, delOutputLog, &QTextEdit::clear);
}

void MainWindow::runCopyCommand()
{
    outputLog->clear();

    const QString source = sourcePath->text().trimmed();
    const QString destination = destPath->text().trimmed();

    if (source.isEmpty()) {
        QMessageBox::warning(this, "K1Wi COPY", "Please select a source path.");
        return;
    }

    if (destination.isEmpty()) {
        QMessageBox::warning(this, "K1Wi COPY", "Please select a destination path.");
        return;
    }

    if (!QFileInfo::exists(source)) {
        QMessageBox::warning(
            this,
            "K1Wi COPY",
            "Source path does not exist.\n\nPlease select a valid source file or directory."
        );

        outputLog->append("[GUI] Source path does not exist.");
        outputLog->append("[GUI] Please select a valid source file or directory.");
        return;
    }
    
    const QFileInfo sourceInfo(source);
const bool recursiveMode =
    copyModeCombo->currentData().toString() == QStringLiteral("recursive");

if (recursiveMode && !sourceInfo.isDir()) {
    QMessageBox::warning(
        this,
        "K1Wi COPY",
        "Recursive directory copy requires a source directory."
    );

    outputLog->append("[GUI] Recursive directory copy requires a source directory.");
    return;
    }

    if (!recursiveMode && !sourceInfo.isFile()) {
        QMessageBox::warning(
        this,
        "K1Wi COPY",
        "File copy requires a regular source file."
        );

        outputLog->append("[GUI] File copy requires a regular source file.");
        return;
    } 

    if (QFileInfo::exists(destination) && !forceCheck->isChecked()) {
        QMessageBox::warning(
            this,
            "K1Wi COPY",
            "Destination already exists.\n\nCheck \"Force overwrite\" to intentionally merge into the existing destination."
        );

        outputLog->append("[GUI] Destination already exists.");
        outputLog->append("[GUI] Check \"Force overwrite\" to intentionally merge into the existing destination.");
        return;
    }

    if (!QFileInfo::exists(k1wiBinary) || !QFileInfo(k1wiBinary).isExecutable()) {
        QMessageBox::critical(
            this,
            "K1Wi COPY",
            "K1Wi CLI binary was not found or is not executable.\n\n"
            "Expected: ../bin/k1wi\n\n"
            "Build the CLI first from the project root."
        );

        outputLog->append("[GUI] K1Wi CLI binary was not found or is not executable.");
        outputLog->append("[GUI] Expected: ../bin/k1wi");
        outputLog->append("[GUI] Build the CLI first from the project root.");
        return;
    }

    QStringList args;
    args << "COPY";
    args << source;
    args << destination;

    if (forceCheck->isChecked()) {
        args << "--force";
    }

    if (recursiveMode) {
    args << "--recursive";
    } 
    
    outputLog->append("[GUI] COPY run summary");
    outputLog->append("[GUI] Source: " + source);
    outputLog->append("[GUI] Destination: " + destination);
    outputLog->append("[GUI] Mode: " + copyModeCombo->currentText());
    outputLog->append("[GUI] Force overwrite / merge: " + QString(forceCheck->isChecked() ? "enabled" : "disabled"));
    
    outputLog->append("");
    outputLog->append("Running: " + k1wiBinary + " " + args.join(" "));

    QProcess *process = new QProcess(this);

    connect(process, &QProcess::readyReadStandardOutput, this, [this, process]() {
        outputLog->append(stripAnsiCodes(QString::fromLocal8Bit(process->readAllStandardOutput())));
    });

    connect(process, &QProcess::readyReadStandardError, this, [this, process]() {
        outputLog->append(stripAnsiCodes(QString::fromLocal8Bit(process->readAllStandardError())));
    });

    connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this, process](int exitCode, QProcess::ExitStatus) {
        outputLog->append(QString("\nProcess finished with exit code %1").arg(exitCode));
        process->deleteLater();
    });

    process->start(k1wiBinary, args);
}

void MainWindow::runLyzerCommand()
{
    lyzerOutputLog->clear();

    const QString target = lyzerTargetPath->text().trimmed();

    if (target.isEmpty()) {
        QMessageBox::warning(this, "K1Wi LYZER", "Please select a target file.");
        return;
    }

    if (!QFileInfo::exists(target)) {
        QMessageBox::warning(
            this,
            "K1Wi LYZER",
            "Target file does not exist.\n\nPlease select a valid file."
        );

        lyzerOutputLog->append("[GUI] LYZER target file does not exist.");
        lyzerOutputLog->append("[GUI] Please select a valid file.");
        return;
    }

    if (!QFileInfo(target).isFile()) {
        QMessageBox::warning(
            this,
            "K1Wi LYZER",
            "Target path is not a regular file.\n\nPlease select a valid file."
        );

        lyzerOutputLog->append("[GUI] LYZER target path is not a regular file.");
        lyzerOutputLog->append("[GUI] Please select a valid file.");
        return;
    }

    if (!QFileInfo::exists(k1wiBinary) || !QFileInfo(k1wiBinary).isExecutable()) {
        QMessageBox::critical(
            this,
            "K1Wi LYZER",
            "K1Wi CLI binary was not found or is not executable.\n\n"
            "Expected: ../bin/k1wi\n\n"
            "Build the CLI first from the project root."
        );

        lyzerOutputLog->append("[GUI] K1Wi CLI binary was not found or is not executable.");
        lyzerOutputLog->append("[GUI] Expected: ../bin/k1wi");
        lyzerOutputLog->append("[GUI] Build the CLI first from the project root.");
        return;
    }

    QStringList args;
    args << "LYZER";
    args << target;

    const QString lyzerMode = lyzerModeCombo->currentData().toString();
    if (!lyzerMode.isEmpty()) {
       args << lyzerMode;
    }

    lyzerOutputLog->append("[GUI] LYZER run summary");
    lyzerOutputLog->append("[GUI] Target: " + target);
    lyzerOutputLog->append("[GUI] Mode: " + lyzerModeCombo->currentText());
    lyzerOutputLog->append("");
    lyzerOutputLog->append("Running: " + k1wiBinary + " " + args.join(" "));

    QProcess *process = new QProcess(this);

    connect(process, &QProcess::readyReadStandardOutput, this, [this, process]() {
        lyzerOutputLog->append(stripAnsiCodes(QString::fromLocal8Bit(process->readAllStandardOutput())));
    });

    connect(process, &QProcess::readyReadStandardError, this, [this, process]() {
        lyzerOutputLog->append(stripAnsiCodes(QString::fromLocal8Bit(process->readAllStandardError())));
    });

    connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this, process](int exitCode, QProcess::ExitStatus) {
        lyzerOutputLog->append(QString("\nProcess finished with exit code %1").arg(exitCode));
        process->deleteLater();
    });

    process->start(k1wiBinary, args);
}

void MainWindow::runExtractCommand()
{
    extractOutputLog->clear();

    const QString target = extractTargetPath->text().trimmed();

    if (target.isEmpty()) {
        QMessageBox::warning(this, "K1Wi EXTRACT", "Please select a target file.");
        return;
    }

    if (!QFileInfo::exists(target)) {
        QMessageBox::warning(
            this,
            "K1Wi EXTRACT",
            "Target file does not exist.\n\nPlease select a valid file."
        );

        extractOutputLog->append("[GUI] EXTRACT target file does not exist.");
        extractOutputLog->append("[GUI] Please select a valid file.");
        return;
    }

    if (!QFileInfo(target).isFile()) {
        QMessageBox::warning(
            this,
            "K1Wi EXTRACT",
            "Target path is not a regular file.\n\nPlease select a valid file."
        );

        extractOutputLog->append("[GUI] EXTRACT target path is not a regular file.");
        extractOutputLog->append("[GUI] Please select a valid file.");
        return;
    }

    if (!QFileInfo::exists(k1wiBinary) || !QFileInfo(k1wiBinary).isExecutable()) {
        QMessageBox::critical(
            this,
            "K1Wi EXTRACT",
            "K1Wi CLI binary was not found or is not executable.\n\n"
            "Expected: ../bin/k1wi\n\n"
            "Build the CLI first from the project root."
        );

        extractOutputLog->append("[GUI] K1Wi CLI binary was not found or is not executable.");
        extractOutputLog->append("[GUI] Expected: ../bin/k1wi");
        extractOutputLog->append("[GUI] Build the CLI first from the project root.");
        return;
    }

    QStringList args;
    args << "EXTRACT";

    if (extractRecursiveCheck->isChecked()) {
        args << "--recursive";
    }

    args << target;

    extractOutputLog->append("[GUI] EXTRACT run summary");
    extractOutputLog->append("[GUI] Target: " + target);
    extractOutputLog->append("[GUI] Recursive: " + QString(extractRecursiveCheck->isChecked() ? "enabled" : "disabled"));
    extractOutputLog->append("");
    extractOutputLog->append("Running: " + k1wiBinary + " " + args.join(" "));

    QProcess *process = new QProcess(this);  

    connect(process, &QProcess::readyReadStandardOutput, this, [this, process]() {
        extractOutputLog->append(stripAnsiCodes(QString::fromLocal8Bit(process->readAllStandardOutput())));
    });

    connect(process, &QProcess::readyReadStandardError, this, [this, process]() {
        extractOutputLog->append(stripAnsiCodes(QString::fromLocal8Bit(process->readAllStandardError())));
    });

    connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this, process](int exitCode, QProcess::ExitStatus) {
        extractOutputLog->append(QString("\nProcess finished with exit code %1").arg(exitCode));
        process->deleteLater();
    });

    process->start(k1wiBinary, args);
}

void MainWindow::runDelCommand()
{
    delOutputLog->clear();

    const QString target = delTargetPath->text().trimmed();
    const QString standard = delStandardCombo->currentData().toString();
    const QString customPasses = delCustomPassCount->text().trimmed();

    if (target.isEmpty()) {
        QMessageBox::warning(this, "K1Wi DEL", "Please select a target file.");
        return;
    }

    QFileInfo targetInfo(target);

    if (!targetInfo.exists()) {
        QMessageBox::warning(
            this,
            "K1Wi DEL",
            "Target file does not exist.\n\nPlease select a valid file."
        );

        delOutputLog->append("[GUI] DEL target file does not exist.");
        delOutputLog->append("[GUI] Please select a valid file.");
        return;
    }

    if (!targetInfo.isFile()) {
        QMessageBox::warning(
            this,
            "K1Wi DEL",
            "DEL GUI currently supports files only.\n\nDirectory deletion is intentionally disabled."
        );

        delOutputLog->append("[GUI] DEL GUI currently supports files only.");
        delOutputLog->append("[GUI] Directory deletion is intentionally disabled.");
        return;
    }

    if (!delConfirmCheck->isChecked() ||
        delConfirmText->text().trimmed() != QStringLiteral("DELETE")) {
        QMessageBox::warning(
            this,
            "K1Wi DEL",
            "DEL confirmation is incomplete.\n\nCheck Confirm file deletion and type DELETE."
        );

        delOutputLog->append("[GUI] DEL confirmation is incomplete.");
        delOutputLog->append("[GUI] Check Confirm file deletion and type DELETE.");
        return;
    }

    if (standard == QStringLiteral("3")) {
        bool ok = false;
        const int passCount = customPasses.toInt(&ok);

        if (!ok || passCount < 1 || passCount > 33) {
            QMessageBox::warning(
                this,
                "K1Wi DEL",
                "Custom pass count must be a number from 1 to 33."
            );

            delOutputLog->append("[GUI] Invalid custom pass count.");
            delOutputLog->append("[GUI] Custom pass count must be 1-33.");
            return;
        }
    }

    QFileInfo binaryInfo(k1wiBinary);
    const QString binaryPath = binaryInfo.absoluteFilePath();

    if (!binaryInfo.exists() || !binaryInfo.isExecutable()) {
        QMessageBox::critical(
            this,
            "K1Wi DEL",
            "K1Wi CLI binary was not found or is not executable.\n\n"
            "Expected: ../bin/k1wi\n\n"
            "Build the CLI first from the project root."
        );

        delOutputLog->append("[GUI] K1Wi CLI binary was not found or is not executable.");
        delOutputLog->append("[GUI] Expected: ../bin/k1wi");
        delOutputLog->append("[GUI] Build the CLI first from the project root.");
        return;
    }

    QString standardLabel = delStandardCombo->currentText();
    if (standard == QStringLiteral("3")) {
        standardLabel += " (" + customPasses + " pass(es))";
    }

    QMessageBox::StandardButton confirm = QMessageBox::warning(
        this,
        "Confirm K1Wi DEL",
        "This will securely delete the selected file.\n\n"
        "Target:\n" + targetInfo.absoluteFilePath() + "\n\n"
        "Deletion standard:\n" + standardLabel + "\n\n"
        "This operation is destructive. Continue?",
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No
    );

    if (confirm != QMessageBox::Yes) {
        delOutputLog->append("[GUI] DEL cancelled by user.");
        return;
    }

    QStringList inputLines;
    inputLines << "DEL";
    inputLines << targetInfo.fileName();
    inputLines << standard;

    if (standard == QStringLiteral("3")) {
        inputLines << customPasses;
    }

    inputLines << "Y";
    inputLines << "EXIT";

    const QString inputScript = inputLines.join("\n") + "\n";

    delOutputLog->append("[GUI] DEL run summary");
    delOutputLog->append("[GUI] Target: " + targetInfo.absoluteFilePath());
    delOutputLog->append("[GUI] Working directory: " + targetInfo.absolutePath());
    delOutputLog->append("[GUI] Filename passed to DEL: " + targetInfo.fileName());
    delOutputLog->append("[GUI] Deletion standard: " + standardLabel);
    delOutputLog->append("");
    delOutputLog->append("Running interactive: " + binaryPath);

    QProcess *process = new QProcess(this);
    process->setWorkingDirectory(targetInfo.absolutePath());

    connect(process, &QProcess::readyReadStandardOutput, this, [this, process]() {
        delOutputLog->append(stripAnsiCodes(QString::fromLocal8Bit(process->readAllStandardOutput())));
    });

    connect(process, &QProcess::readyReadStandardError, this, [this, process]() {
        delOutputLog->append(stripAnsiCodes(QString::fromLocal8Bit(process->readAllStandardError())));
    });

    connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this, process](int exitCode, QProcess::ExitStatus) {
        delOutputLog->append(QString("\nProcess finished with exit code %1").arg(exitCode));
        process->deleteLater();
    });

    connect(process, &QProcess::started, this, [process, inputScript]() {
        process->write(inputScript.toLocal8Bit());
        process->closeWriteChannel();
    });

    process->start(binaryPath);
}
