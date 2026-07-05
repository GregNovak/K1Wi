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

    tabs->addTab(copyTab, "COPY");
    tabs->addTab(lyzerTab, "LYZER");
    tabs->addTab(extractTab, "EXTRACT");

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

    recursiveCheck = new QCheckBox("Recursive", copyTab);
    recursiveCheck->setChecked(true);

    forceCheck = new QCheckBox("Force overwrite", copyTab);
    mainLayout->addWidget(recursiveCheck);
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
    lyzerModeCombo->addItem("Summary");
    lyzerModeCombo->addItem("Full");
    modeLayout->addWidget(new QLabel("Mode:", lyzerTab));
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

    connect(runButton, &QPushButton::clicked, this, [this]() {
        extractOutputLog->append("[GUI] Run EXTRACT wiring will be added next.");
    });

    connect(clearButton, &QPushButton::clicked, extractOutputLog, &QTextEdit::clear);
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

    if (recursiveCheck->isChecked()) {
        args << "--recursive";
    }

    outputLog->append("[GUI] COPY run summary");
    outputLog->append("[GUI] Source: " + source);
    outputLog->append("[GUI] Destination: " + destination);
    outputLog->append("[GUI] Recursive: " + QString(recursiveCheck->isChecked() ? "enabled" : "disabled"));
    outputLog->append("[GUI] Force overwrite: " + QString(forceCheck->isChecked() ? "enabled" : "disabled"));
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

    if (lyzerModeCombo->currentText() == "Summary") {
        args << "--summary";
    } else {
        args << "--full";
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
