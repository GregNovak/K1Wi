#include "MainWindow.h"

#include <QCheckBox>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QProcess>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QWidget>

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
    forceCheck = new QCheckBox("Force overwrite", central);
    mainLayout->addWidget(recursiveCheck);
    mainLayout->addWidget(forceCheck);

    QPushButton *runButton = new QPushButton("Run COPY", central);
    mainLayout->addWidget(runButton);

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
}

void MainWindow::runCopyCommand()
{
    outputLog->clear();

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
        outputLog->append(QString::fromLocal8Bit(process->readAllStandardOutput()));
    });

    connect(process, &QProcess::readyReadStandardError, this, [this, process]() {
        outputLog->append(QString::fromLocal8Bit(process->readAllStandardError()));
    });

    connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this, process](int exitCode, QProcess::ExitStatus) {
        outputLog->append(QString("\nProcess finished with exit code %1").arg(exitCode));
        process->deleteLater();
    });

    process->start("../bin/k1wi", args);
}
