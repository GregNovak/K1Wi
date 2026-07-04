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

    QWidget *central = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(central);

    QLabel *title = new QLabel("K1Wi Framework - COPY Prototype", central);
    mainLayout->addWidget(title);

    QHBoxLayout *sourceLayout = new QHBoxLayout();
    sourcePath = new QLineEdit(central);
    QPushButton *sourceBrowse = new QPushButton("Browse Source", central);
    sourceLayout->addWidget(new QLabel("Source:", central));
    sourceLayout->addWidget(sourcePath);
    sourceLayout->addWidget(sourceBrowse);
    mainLayout->addLayout(sourceLayout);

    QHBoxLayout *destLayout = new QHBoxLayout();
    destPath = new QLineEdit(central);
    QPushButton *destBrowse = new QPushButton("Browse Destination", central);
    destLayout->addWidget(new QLabel("Destination:", central));
    destLayout->addWidget(destPath);
    destLayout->addWidget(destBrowse);
    mainLayout->addLayout(destLayout);

    recursiveCheck = new QCheckBox("Recursive", central);
    recursiveCheck->setChecked(true);

    forceCheck = new QCheckBox("Force overwrite", central);
    mainLayout->addWidget(recursiveCheck);
    mainLayout->addWidget(forceCheck);

    QPushButton *runButton = new QPushButton("Run COPY", central);
    QPushButton *clearButton = new QPushButton("Clear Output", central);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(runButton);
    buttonLayout->addWidget(clearButton);
    mainLayout->addLayout(buttonLayout);

    outputLog = new QTextEdit(central);
    outputLog->setReadOnly(true);
    mainLayout->addWidget(outputLog);

    setCentralWidget(central);

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

void MainWindow::runCopyCommand()
{
    outputLog->clear();

    if (sourcePath->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, "K1Wi COPY", "Please select a source path.");
        return;
    }

    if (destPath->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, "K1Wi COPY", "Please select a destination path.");
        return;
    }

    QStringList args;
    args << "COPY";
    args << sourcePath->text();
    args << destPath->text();

    if (forceCheck->isChecked()) {
        args << "--force";
    }

    if (recursiveCheck->isChecked()) {
        args << "--recursive";
    }

    outputLog->append("Running: ../bin/k1wi " + args.join(" "));

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

    process->start("../bin/k1wi", args);
}
