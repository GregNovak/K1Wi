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
#include <QCoreApplication>
#include <QStandardPaths>

static QString resolveK1wiBinary()
{
    const QString applicationDirectory =
        QCoreApplication::applicationDirPath();

    const QStringList candidates = {
        QDir(applicationDirectory).absoluteFilePath(
            QStringLiteral("../../bin/k1wi")
        ),
        QDir(applicationDirectory).absoluteFilePath(
            QStringLiteral("../bin/k1wi")
        ),
        QDir::current().absoluteFilePath(
            QStringLiteral("../../bin/k1wi")
        ),
        QDir::current().absoluteFilePath(
            QStringLiteral("../bin/k1wi")
        )
    };

    for (const QString &candidate : candidates) {
        const QFileInfo info(candidate);

        if (info.exists() &&
            info.isFile() &&
            info.isExecutable()) {
            return info.canonicalFilePath();
        }
    }

    const QString pathBinary =
        QStandardPaths::findExecutable(QStringLiteral("k1wi"));

    if (!pathBinary.isEmpty()) {
        return pathBinary;
    }

    return candidates.first();
}

static int pcapReportCount(
    const QString &output,
    const QString &label
)
{
    const QRegularExpression pattern(
        QRegularExpression::escape(label) +
        QStringLiteral(R"(\s*([0-9]+))")
    );

    const QRegularExpressionMatch match = pattern.match(output);

    if (!match.hasMatch()) {
        return -1;
    }

    bool ok = false;
    const int value = match.captured(1).toInt(&ok);

    return ok ? value : -1;
}


static QString pcapReportValue(
    const QString &output,
    const QString &label
)
{
    const QRegularExpression pattern(
        QStringLiteral(R"((?:^|\n))") +
        QRegularExpression::escape(label) +
        QStringLiteral(R"(\s*([^\r\n]+))")
    );

    const QRegularExpressionMatch match = pattern.match(output);

    if (!match.hasMatch()) {
        return QString();
    }

    return match.captured(1).trimmed();
}

static QString stripAnsiCodes(const QString &text)
{
    static const QRegularExpression ansiPattern(
        QStringLiteral("\\x1B\\[[0-?]*[ -/]*[@-~]")
    );

    QString cleaned = text;
    cleaned.remove(ansiPattern);
    return cleaned;
}

static void appendStyledLine(
    QTextEdit *log,
    const QString &text,
    const QString &color,
    bool bold = false
)
{
    QString style = QStringLiteral("color: %1;").arg(color);

    if (bold) {
        style += QStringLiteral(" font-weight: bold;");
    }

    log->append(
        QStringLiteral("<span style=\"%1\">%2</span>")
            .arg(style, text.toHtmlEscaped())
    );
}


static void appendPcapFinding(
    QTextEdit *log,
    const QString &label,
    int value
)
{
    if (value < 0) {
        return;
    }

    appendStyledLine(
        log,
        QStringLiteral("[FINDING] %1: %2")
            .arg(label)
            .arg(value),
        QStringLiteral("#0057b8"),
        false
    );
}


static void appendPcapOptionalFinding(
    QTextEdit *log,
    const QString &label,
    int value,
    const QString &message
)
{
    if (value <= 0) {
        return;
    }

    appendStyledLine(
        log,
        QStringLiteral("[FINDING] %1: %2")
            .arg(label)
            .arg(value),
        QStringLiteral("#b35c00"),
        true
    );

    if (!message.isEmpty()) {
        appendStyledLine(
            log,
            QStringLiteral("[NOTE] ") + message,
            QStringLiteral("#b35c00"),
            false
        );
    }
}

static void appendStyledBlock(QTextEdit *log, const QString &text, const QString &color, bool bold = false)
{
    const QStringList lines = text.split('\n');

    for (const QString &line : lines) {
        appendStyledLine(log, line, color, bold);
    }
}

static QString resultColorForSummary(const QString &summary, int exitCode)
{
    if (summary.contains(QStringLiteral("failed"), Qt::CaseInsensitive) ||
        summary.contains(QStringLiteral("differ"), Qt::CaseInsensitive) ||
        summary.contains(QStringLiteral("does not match"), Qt::CaseInsensitive)) {
        return QStringLiteral("#b00020");
    }

    if (exitCode != 0) {
        return QStringLiteral("#b26a00");
    }

    return QStringLiteral("#0b7a0b");
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
    buildHashTab();
    buildStringTab();
    buildMagicTab();
    buildEntropyTab();
    buildPcapTab();
    

    tabs->addTab(copyTab, "COPY");
    tabs->addTab(lyzerTab, "LYZER");
    tabs->addTab(extractTab, "EXTRACT");
    tabs->addTab(delTab, "DEL");
    tabs->addTab(hashTab, "HASH");
    tabs->addTab(stringTab, "STRING");
    tabs->addTab(magicTab, "MAGIC");
    tabs->addTab(entropyTab, "ENTROPY");
    tabs->addTab(pcapTab, "PCAP");
    
    setCentralWidget(tabs);
}

static QString hashFriendlySummary(const QString &output)
{
    if (output.contains(QStringLiteral("MD5 OK")) ||
        output.contains(QStringLiteral("SHA256 OK"))) {
        return QStringLiteral(
            "[RESULT] Verification passed.\n"
            "[RESULT] The selected file matches the expected hash."
        );
    }

    if (output.contains(QStringLiteral("MD5 FAIL")) ||
        output.contains(QStringLiteral("SHA256 FAIL"))) {
        return QStringLiteral(
            "[RESULT] Verification failed.\n"
            "[RESULT] The selected file does not match the expected hash."
        );
    }

    if (output.contains(QStringLiteral("MD5 MATCH")) ||
        output.contains(QStringLiteral("SHA256 MATCH"))) {
        return QStringLiteral(
            "[RESULT] Files match.\n"
            "[RESULT] The two selected files have the same hash."
        );
    }

    if (output.contains(QStringLiteral("MD5 DIFFER")) ||
        output.contains(QStringLiteral("SHA256 DIFFER"))) {
        return QStringLiteral(
            "[RESULT] Files differ.\n"
            "[RESULT] The two selected files do not have the same hash."
        );
    }

    if (output.contains(QStringLiteral("MD5(")) ||
        output.contains(QStringLiteral("SHA256("))) {
        return QStringLiteral(
            "[RESULT] Hash computed successfully.\n"
            "[RESULT] The computed hash is shown in the detailed output below."
        );
    }

    return QString();
}

static QString copyFriendlySummary(
    const QString &output,
    int exitCode,
    const QString &destination,
    bool recursiveMode
)
{
    if (exitCode == 0) {
        QString summary;

        summary += QStringLiteral("[RESULT] COPY completed successfully.\n");

        if (recursiveMode) {
            summary += QStringLiteral(
                "[RESULT] Recursive directory copy finished and K1Wi verification completed.\n"
            );
        } else {
            summary += QStringLiteral(
                "[RESULT] File copy finished and K1Wi verification completed.\n"
            );
        }

        summary += QStringLiteral("[RESULT] Destination: ") + destination;

        return summary;
    }

    if (exitCode != 0 ||
    output.contains(QStringLiteral("failed"), Qt::CaseInsensitive) ||
    output.contains(QStringLiteral("fatal"), Qt::CaseInsensitive) ||
    output.contains(QStringLiteral("error:"), Qt::CaseInsensitive) ||
    output.contains(QStringLiteral("[ERROR]"), Qt::CaseInsensitive)) {
    return QStringLiteral(
        "[RESULT] LYZER did not complete successfully.\n"
        "[RESULT] K1Wi reported an error or failure. Check the detailed output above."
    );
}

    return QStringLiteral(
        "[RESULT] COPY finished with a non-zero exit code.\n"
        "[RESULT] Check the detailed K1Wi output above before trusting the destination."
    );
}

static QString delFriendlySummary(const QString &output, int exitCode, const QString &target, const QString &standardLabel)
{
    if (exitCode == 0 &&
        output.contains(QStringLiteral("Secure deletion complete"), Qt::CaseInsensitive)) {
        return QStringLiteral(
            "[RESULT] Secure deletion completed successfully.\n"
            "[RESULT] Target deleted: "
        ) + target + QStringLiteral("\n") +
        QStringLiteral("[RESULT] Deletion method: ") + standardLabel;
    }

    if (output.contains(QStringLiteral("aborted"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("failed"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("error"), Qt::CaseInsensitive)) {
        return QStringLiteral(
            "[RESULT] Secure deletion did not complete successfully.\n"
            "[RESULT] K1Wi reported an error, failure, or abort. Check the detailed output above."
        );
    }

    if (exitCode != 0) {
        return QStringLiteral(
            "[RESULT] DEL finished with a non-zero exit code.\n"
            "[RESULT] Check the detailed K1Wi output above before assuming the file was deleted."
        );
    }

    return QStringLiteral(
        "[RESULT] DEL finished.\n"
        "[RESULT] Review the detailed K1Wi output above to confirm the deletion result."
    );
}

static QString extractFriendlySummary(
    const QString &output,
    int exitCode,
    const QString &target,
    bool recursiveMode
)
{
    if (exitCode == 0 &&
        output.contains(QStringLiteral("EXTRACT COMPLETE"), Qt::CaseInsensitive)) {
        QString summary;

        summary += QStringLiteral("[RESULT] EXTRACT completed successfully.\n");

        if (recursiveMode) {
            summary += QStringLiteral(
                "[RESULT] Recursive extraction finished without reported errors.\n"
            );
        } else {
            summary += QStringLiteral(
                "[RESULT] Extraction finished without reported errors.\n"
            );
        }

        summary += QStringLiteral("[RESULT] Target analyzed: ") + target;

        return summary;
    }

    if (exitCode == 0) {
        QString summary;

        summary += QStringLiteral("[RESULT] EXTRACT finished.\n");

        if (recursiveMode) {
            summary += QStringLiteral(
                "[RESULT] Recursive mode completed. Review the detailed output above for recovered content.\n"
            );
        } else {
            summary += QStringLiteral(
                "[RESULT] Review the detailed output above for recovered content.\n"
            );
        }

        summary += QStringLiteral("[RESULT] Target analyzed: ") + target;

        return summary;
    }

    if (output.contains(QStringLiteral("failed"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("error"), Qt::CaseInsensitive)) {
        return QStringLiteral(
            "[RESULT] EXTRACT did not complete successfully.\n"
            "[RESULT] K1Wi reported an error or failure. Check the detailed output above."
        );
    }

    return QStringLiteral(
        "[RESULT] EXTRACT finished with a non-zero exit code.\n"
        "[RESULT] Check the detailed K1Wi output above before trusting the extraction result."
    );
}

static QString lyzerFriendlySummary(
    const QString &output,
    int exitCode,
    const QString &target,
    const QString &modeLabel
)
{
    if (output.contains(QStringLiteral("Assessment: LOW"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("LOW entropy"), Qt::CaseInsensitive)) {
        return QStringLiteral(
            "[RESULT] LYZER completed successfully.\n"
            "[RESULT] Assessment: LOW.\n"
            "[RESULT] No major risk indicators were reported in the summary output.\n"
            "[RESULT] Target analyzed: "
        ) + target + QStringLiteral("\n") +
        QStringLiteral("[RESULT] Mode: ") + modeLabel;
    }

    if (output.contains(QStringLiteral("Assessment: MEDIUM"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("MEDIUM"), Qt::CaseInsensitive)) {
        return QStringLiteral(
            "[RESULT] LYZER completed with a medium-risk assessment.\n"
            "[RESULT] Review the detailed output above and consider running Full or Verbose analysis.\n"
            "[RESULT] Target analyzed: "
        ) + target + QStringLiteral("\n") +
        QStringLiteral("[RESULT] Mode: ") + modeLabel;
    }

    if (output.contains(QStringLiteral("Assessment: HIGH"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("HIGH"), Qt::CaseInsensitive)) {
        return QStringLiteral(
            "[RESULT] LYZER reported a high-risk assessment.\n"
            "[RESULT] Review the detailed findings above before trusting the file.\n"
            "[RESULT] Target analyzed: "
        ) + target + QStringLiteral("\n") +
        QStringLiteral("[RESULT] Mode: ") + modeLabel;
    }

    if (output.contains(QStringLiteral("failed"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("error"), Qt::CaseInsensitive)) {
        return QStringLiteral(
            "[RESULT] LYZER did not complete successfully.\n"
            "[RESULT] K1Wi reported an error or failure. Check the detailed output above."
        );
    }

    if (exitCode == 0) {
        return QStringLiteral(
            "[RESULT] LYZER completed successfully.\n"
            "[RESULT] Review the detailed output above for findings and recommended next steps.\n"
            "[RESULT] Target analyzed: "
        ) + target + QStringLiteral("\n") +
        QStringLiteral("[RESULT] Mode: ") + modeLabel;
    }

    return QStringLiteral(
        "[RESULT] LYZER finished with a non-zero exit code.\n"
        "[RESULT] Check the detailed K1Wi output above before trusting the analysis result."
    );
}

static QString lyzerColorForSummary(const QString &summary, int exitCode)
{
    if (summary.contains(QStringLiteral("reported a high-risk assessment"), Qt::CaseInsensitive) ||
    summary.contains(QStringLiteral("did not complete"), Qt::CaseInsensitive) ||
    summary.contains(QStringLiteral("non-zero"), Qt::CaseInsensitive)) {
    return QStringLiteral("#b00020");
    }

    if (summary.contains(QStringLiteral("medium-risk"), Qt::CaseInsensitive)) {
        return QStringLiteral("#b26a00");
    }

    if (exitCode != 0) {
        return QStringLiteral("#b26a00");
    }

    return QStringLiteral("#0b7a0b");
}

static QString stringFriendlySummary(
    const QString &output,
    int exitCode,
    bool fileMode,
    bool decodeEnabled,
    const QString &targetLabel
)
{
    if (output.contains(QStringLiteral("failed"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("fatal"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("error:"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("[ERROR]"), Qt::CaseInsensitive)) {
        return QStringLiteral(
            "[RESULT] STRING analysis did not complete successfully.\n"
            "[RESULT] K1Wi reported an error or failure. Check the detailed output above."
        );
    }

    if (exitCode != 0) {
        return QStringLiteral(
            "[RESULT] STRING finished with a non-zero exit code.\n"
            "[RESULT] Check the detailed K1Wi output above before trusting the analysis result."
        );
    }

    QString summary;

    summary += QStringLiteral("[RESULT] STRING analysis completed successfully.\n");

    if (fileMode) {
        summary += QStringLiteral(
            "[RESULT] File mode analyzed printable strings inside the selected file.\n"
        );
    } else {
        summary += QStringLiteral(
            "[RESULT] Direct text mode analyzed the provided input string.\n"
        );
    }

    if (decodeEnabled) {
        summary += QStringLiteral("[RESULT] Decode output was requested.\n");
    }

    summary += QStringLiteral("[RESULT] Target: ") + targetLabel;

    return summary;
}
static QString magicFriendlySummary(
    const QString &output,
    int exitCode,
    const QString &target
)
{
    if (output.contains(QStringLiteral("failed"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("fatal"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("error:"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("[ERROR]"), Qt::CaseInsensitive)) {
        return QStringLiteral(
            "[RESULT] MAGIC analysis did not complete successfully.\n"
            "[RESULT] K1Wi reported an error or failure. Check the detailed output above."
        );
    }

    if (exitCode != 0) {
        return QStringLiteral(
            "[RESULT] MAGIC finished with a non-zero exit code.\n"
            "[RESULT] Check the detailed K1Wi output above before trusting the file identification."
        );
    }

    return QStringLiteral(
        "[RESULT] MAGIC analysis completed successfully.\n"
        "[RESULT] K1Wi inspected the file signature / magic bytes.\n"
        "[RESULT] Target analyzed: "
    ) + target;
}

static QString entropyFriendlySummary(
    const QString &output,
    int exitCode,
    const QString &target,
    const QString &modeLabel
)
{
    if (output.contains(QStringLiteral("failed"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("fatal"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("error:"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("[ERROR]"), Qt::CaseInsensitive)) {
        return QStringLiteral(
            "[RESULT] ENTROPY analysis did not complete successfully.\n"
            "[RESULT] K1Wi reported an error or failure. Check the detailed output above."
        );
    }

    if (exitCode != 0) {
        return QStringLiteral(
            "[RESULT] ENTROPY finished with a non-zero exit code.\n"
            "[RESULT] Check the detailed K1Wi output above before trusting the entropy result."
        );
    }

    QString summary;

    summary += QStringLiteral("[RESULT] ENTROPY analysis completed successfully.\n");
    summary += QStringLiteral("[RESULT] Mode: ") + modeLabel + QStringLiteral("\n");
    summary += QStringLiteral("[RESULT] Target analyzed: ") + target;

    if (output.contains(QStringLiteral("high"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("encrypted"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("compressed"), Qt::CaseInsensitive)) {
        summary += QStringLiteral(
            "\n[RESULT] Review high-entropy regions carefully; they may indicate compressed, encrypted, or packed content."
        );
    }

    return summary;
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

void MainWindow::buildStringTab()
{
    stringTab = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(stringTab);

    QLabel *title = new QLabel("K1Wi Framework - STRING Analyzer", stringTab);
    mainLayout->addWidget(title);

    QLabel *description = new QLabel(
        "STRING analyzes direct text or printable strings inside a file. "
        "It can detect Base64, hex, URLs, hashes, credentials, JWTs, emails, UTF-8, ROT13, and more.",
        stringTab
    );
    description->setWordWrap(true);
    mainLayout->addWidget(description);

    QHBoxLayout *modeLayout = new QHBoxLayout();
    stringInputModeCombo = new QComboBox(stringTab);
    stringInputModeCombo->addItem("Direct text", "text");
    stringInputModeCombo->addItem("File mode", "file");
    modeLayout->addWidget(new QLabel("Input mode:", stringTab));
    modeLayout->addWidget(stringInputModeCombo);
    mainLayout->addLayout(modeLayout);

    QHBoxLayout *textLayout = new QHBoxLayout();
    stringTextInput = new QLineEdit(stringTab);
    stringTextInput->setPlaceholderText("Example: SGVsbG8= or 48656c6c6f");
    textLayout->addWidget(new QLabel("Text:", stringTab));
    textLayout->addWidget(stringTextInput);
    mainLayout->addLayout(textLayout);

    QHBoxLayout *fileLayout = new QHBoxLayout();
    stringFilePath = new QLineEdit(stringTab);
    QPushButton *fileBrowse = new QPushButton("Browse File", stringTab);
    fileLayout->addWidget(new QLabel("File:", stringTab));
    fileLayout->addWidget(stringFilePath);
    fileLayout->addWidget(fileBrowse);
    mainLayout->addLayout(fileLayout);

    stringDecodeCheck = new QCheckBox("Force decoded output", stringTab);
    mainLayout->addWidget(stringDecodeCheck);

    QHBoxLayout *minLayout = new QHBoxLayout();
    stringMinLength = new QLineEdit(stringTab);
    stringMinLength->setPlaceholderText("Optional, file mode only");
    minLayout->addWidget(new QLabel("Minimum string length:", stringTab));
    minLayout->addWidget(stringMinLength);
    mainLayout->addLayout(minLayout);

    QPushButton *runButton = new QPushButton("Run STRING", stringTab);
    QPushButton *clearButton = new QPushButton("Clear Output", stringTab);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(runButton);
    buttonLayout->addWidget(clearButton);
    mainLayout->addLayout(buttonLayout);

    stringOutputLog = new QTextEdit(stringTab);
    stringOutputLog->setReadOnly(true);
    stringOutputLog->append("[GUI] STRING panel ready.");
    stringOutputLog->append("[GUI] Analyze direct text or printable strings inside a file.");
    mainLayout->addWidget(stringOutputLog);

    auto updateStringModeFields = [this]() {
        const QString mode = stringInputModeCombo->currentData().toString();
        const bool fileMode = mode == QStringLiteral("file");

        stringTextInput->setEnabled(!fileMode);
        stringFilePath->setEnabled(fileMode);
        stringMinLength->setEnabled(fileMode);

        if (fileMode) {
            stringTextInput->clear();
        } else {
            stringFilePath->clear();
            stringMinLength->clear();
        }
    };

    connect(stringInputModeCombo, &QComboBox::currentIndexChanged, this, updateStringModeFields);

    connect(fileBrowse, &QPushButton::clicked, this, [this]() {
        QString path = QFileDialog::getOpenFileName(this, "Select STRING File");
        if (!path.isEmpty()) {
            stringFilePath->setText(path);
        }
    });

    connect(runButton, &QPushButton::clicked, this, &MainWindow::runStringCommand);

    connect(clearButton, &QPushButton::clicked, stringOutputLog, &QTextEdit::clear);

    updateStringModeFields();
}

void MainWindow::buildMagicTab()
{
    magicTab = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(magicTab);

    QLabel *title = new QLabel("K1Wi Framework - MAGIC Detector", magicTab);
    mainLayout->addWidget(title);

    QLabel *description = new QLabel(
        "MAGIC identifies file types by checking file signatures and magic bytes.",
        magicTab
    );
    description->setWordWrap(true);
    mainLayout->addWidget(description);

    QHBoxLayout *targetLayout = new QHBoxLayout();
    magicTargetPath = new QLineEdit(magicTab);
    QPushButton *browseButton = new QPushButton("Browse Target", magicTab);

    targetLayout->addWidget(new QLabel("Target file:", magicTab));
    targetLayout->addWidget(magicTargetPath);
    targetLayout->addWidget(browseButton);
    mainLayout->addLayout(targetLayout);

    QPushButton *runButton = new QPushButton("Run MAGIC", magicTab);
    QPushButton *clearButton = new QPushButton("Clear Output", magicTab);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(runButton);
    buttonLayout->addWidget(clearButton);
    mainLayout->addLayout(buttonLayout);

    magicOutputLog = new QTextEdit(magicTab);
    magicOutputLog->setReadOnly(true);
    magicOutputLog->append("[GUI] MAGIC panel ready.");
    magicOutputLog->append("[GUI] Select a file to inspect its signature / magic bytes.");
    mainLayout->addWidget(magicOutputLog);

    connect(browseButton, &QPushButton::clicked, this, [this]() {
        QString path = QFileDialog::getOpenFileName(this, "Select MAGIC Target");
        if (!path.isEmpty()) {
            magicTargetPath->setText(path);
        }
    });

    connect(runButton, &QPushButton::clicked, this, &MainWindow::runMagicCommand);
    connect(clearButton, &QPushButton::clicked, magicOutputLog, &QTextEdit::clear);
}

void MainWindow::buildEntropyTab()
{
    entropyTab = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(entropyTab);

    QLabel *title = new QLabel("K1Wi Framework - ENTROPY Analyzer", entropyTab);
    mainLayout->addWidget(title);

    QLabel *description = new QLabel(
        "ENTROPY computes Shannon entropy for files and binary regions. "
        "It supports default file entropy, global entropy, sliding-window analysis, and heatmap output.",
        entropyTab
    );
    description->setWordWrap(true);
    mainLayout->addWidget(description);

    QHBoxLayout *modeLayout = new QHBoxLayout();
    entropyModeCombo = new QComboBox(entropyTab);
    entropyModeCombo->addItem("Default file entropy", "default");
    entropyModeCombo->addItem("Global entropy", "--global");
    entropyModeCombo->addItem("Sliding-window entropy", "--window");
    entropyModeCombo->addItem("Heatmap entropy", "--heatmap");

    modeLayout->addWidget(new QLabel("ENTROPY mode:", entropyTab));
    modeLayout->addWidget(entropyModeCombo);
    mainLayout->addLayout(modeLayout);

    QHBoxLayout *targetLayout = new QHBoxLayout();
    entropyTargetPath = new QLineEdit(entropyTab);
    QPushButton *browseButton = new QPushButton("Browse Target", entropyTab);

    targetLayout->addWidget(new QLabel("Target file:", entropyTab));
    targetLayout->addWidget(entropyTargetPath);
    targetLayout->addWidget(browseButton);
    mainLayout->addLayout(targetLayout);

    QPushButton *runButton = new QPushButton("Run ENTROPY", entropyTab);
    QPushButton *clearButton = new QPushButton("Clear Output", entropyTab);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(runButton);
    buttonLayout->addWidget(clearButton);
    mainLayout->addLayout(buttonLayout);

    entropyOutputLog = new QTextEdit(entropyTab);
    entropyOutputLog->setReadOnly(true);
    entropyOutputLog->append("[GUI] ENTROPY panel ready.");
    entropyOutputLog->append("[GUI] Select a file and entropy mode to analyze.");
    mainLayout->addWidget(entropyOutputLog);

    connect(browseButton, &QPushButton::clicked, this, [this]() {
        QString path = QFileDialog::getOpenFileName(this, "Select ENTROPY Target");
        if (!path.isEmpty()) {
            entropyTargetPath->setText(path);
        }
    });

    connect(runButton, &QPushButton::clicked, this, &MainWindow::runEntropyCommand);
    connect(clearButton, &QPushButton::clicked, entropyOutputLog, &QTextEdit::clear);
}

void MainWindow::buildPcapTab()
{
    pcapTab = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(pcapTab);

    QLabel *title = new QLabel("K1Wi Framework - PCAP Analyzer", pcapTab);
    mainLayout->addWidget(title);

    QLabel *description = new QLabel(
        "Analyze classic PCAP and PCAPNG captures. K1Wi reports Ethernet, "
        "VLAN, IPv4, IPv6, TCP, UDP, ICMP, ARP, payload details, and "
        "directional TCP stream reconstruction.",
        pcapTab
    );
    description->setWordWrap(true);
    mainLayout->addWidget(description);

    QHBoxLayout *modeLayout = new QHBoxLayout();
    pcapModeCombo = new QComboBox(pcapTab);
    pcapModeCombo->addItem("Summary", "--summary");
    pcapModeCombo->addItem("Full packet view", "--full");

    modeLayout->addWidget(new QLabel("PCAP mode:", pcapTab));
    modeLayout->addWidget(pcapModeCombo);
    mainLayout->addLayout(modeLayout);

    QHBoxLayout *targetLayout = new QHBoxLayout();
    pcapTargetPath = new QLineEdit(pcapTab);
    pcapTargetPath->setPlaceholderText(
        "Select a .pcap or .pcapng capture file"
    );

    QPushButton *browseButton =
        new QPushButton("Browse Capture", pcapTab);

    targetLayout->addWidget(new QLabel("Capture file:", pcapTab));
    targetLayout->addWidget(pcapTargetPath);
    targetLayout->addWidget(browseButton);
    mainLayout->addLayout(targetLayout);

    QPushButton *runButton = new QPushButton("Run PCAP", pcapTab);
    QPushButton *clearButton = new QPushButton("Clear Output", pcapTab);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(runButton);
    buttonLayout->addWidget(clearButton);
    mainLayout->addLayout(buttonLayout);

    QLabel *findingsLabel =
        new QLabel("Key Findings", pcapTab);
    mainLayout->addWidget(findingsLabel);

    pcapFindingsLog = new QTextEdit(pcapTab);
    pcapFindingsLog->setReadOnly(true);
    pcapFindingsLog->setMaximumHeight(230);
    pcapFindingsLog->append(
        "[GUI] Findings will appear here after analysis."
    );
    mainLayout->addWidget(pcapFindingsLog);

    QLabel *detailedOutputLabel =
        new QLabel("Detailed CLI Output", pcapTab);
    mainLayout->addWidget(detailedOutputLabel);

    pcapOutputLog = new QTextEdit(pcapTab);
    pcapOutputLog->setReadOnly(true);
    pcapOutputLog->append("[GUI] Packet capture analyzer ready.");
    pcapOutputLog->append(
        "[GUI] Select a PCAP or PCAPNG file and choose Summary or Full packet view."
    );
    mainLayout->addWidget(pcapOutputLog);

    connect(browseButton, &QPushButton::clicked, this, [this]() {
        const QString path = QFileDialog::getOpenFileName(
            this,
            "Select Packet Capture",
            QString(),
            "Packet captures (*.pcap *.pcapng);;Classic PCAP (*.pcap);;"
            "PCAPNG (*.pcapng);;All files (*)"
        );

        if (!path.isEmpty()) {
            pcapTargetPath->setText(path);
        }
    });

    connect(runButton, &QPushButton::clicked, this, &MainWindow::runPcapCommand);
    connect(clearButton, &QPushButton::clicked, this, [this]() {
        pcapFindingsLog->clear();
        pcapOutputLog->clear();
    });
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
    "DEL securely deletes one selected file using the chosen overwrite method. "
    "Directory deletion is intentionally disabled in this GUI. "
    "You will be asked to confirm before deletion begins.",
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

    QPushButton *runButton = new QPushButton("Run DEL", delTab);
    QPushButton *clearButton = new QPushButton("Clear Output", delTab);

    

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

    

    connect(runButton, &QPushButton::clicked, this, &MainWindow::runDelCommand);

    connect(clearButton, &QPushButton::clicked, delOutputLog, &QTextEdit::clear);
}

void MainWindow::buildHashTab()
{
    hashTab = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(hashTab);

    QLabel *title = new QLabel("K1Wi Framework - HASH Prototype", hashTab);
    mainLayout->addWidget(title);

    QLabel *description = new QLabel(
        "HASH combines the K1Wi MD5 and SHA256 modules in one GUI panel.",
        hashTab
    );
    description->setWordWrap(true);
    mainLayout->addWidget(description);

    QHBoxLayout *algorithmLayout = new QHBoxLayout();
    hashAlgorithmCombo = new QComboBox(hashTab);
    hashAlgorithmCombo->addItem("MD5", "MD5");
    hashAlgorithmCombo->addItem("SHA-256", "SHA256");
    algorithmLayout->addWidget(new QLabel("Algorithm:", hashTab));
    algorithmLayout->addWidget(hashAlgorithmCombo);
    mainLayout->addLayout(algorithmLayout);

    QHBoxLayout *modeLayout = new QHBoxLayout();
    hashModeCombo = new QComboBox(hashTab);
    hashModeCombo->addItem("Compute hash", "compute");
    hashModeCombo->addItem("Verify hash", "verify");
    hashModeCombo->addItem("Compare files", "compare");
    modeLayout->addWidget(new QLabel("Mode:", hashTab));
    modeLayout->addWidget(hashModeCombo);
    mainLayout->addLayout(modeLayout);

    QHBoxLayout *fileLayout = new QHBoxLayout();
    hashFilePath = new QLineEdit(hashTab);
    QPushButton *fileBrowse = new QPushButton("Browse File", hashTab);
    fileLayout->addWidget(new QLabel("File:", hashTab));
    fileLayout->addWidget(hashFilePath);
    fileLayout->addWidget(fileBrowse);
    mainLayout->addLayout(fileLayout);

    QHBoxLayout *expectedLayout = new QHBoxLayout();
    hashExpectedValue = new QLineEdit(hashTab);
    hashExpectedValue->setPlaceholderText("Expected hash for verify mode");
    expectedLayout->addWidget(new QLabel("Expected hash:", hashTab));
    expectedLayout->addWidget(hashExpectedValue);
    mainLayout->addLayout(expectedLayout);

    QHBoxLayout *compareLayout = new QHBoxLayout();
    hashCompareFilePath = new QLineEdit(hashTab);
    QPushButton *compareBrowse = new QPushButton("Browse Compare File", hashTab);
    compareLayout->addWidget(new QLabel("Compare file:", hashTab));
    compareLayout->addWidget(hashCompareFilePath);
    compareLayout->addWidget(compareBrowse);
    mainLayout->addLayout(compareLayout);

    QPushButton *runButton = new QPushButton("Run HASH", hashTab);
    QPushButton *clearButton = new QPushButton("Clear Output", hashTab);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(runButton);
    buttonLayout->addWidget(clearButton);
    mainLayout->addLayout(buttonLayout);

    hashOutputLog = new QTextEdit(hashTab);
    hashOutputLog->setReadOnly(true);
    hashOutputLog->append("[GUI] HASH panel ready.");
    hashOutputLog->append("[GUI] Select MD5 or SHA-256, then choose Compute, Verify, or Compare.");
    mainLayout->addWidget(hashOutputLog);

    auto updateHashModeFields = [this]() {
        const QString mode = hashModeCombo->currentData().toString();

        hashExpectedValue->setEnabled(mode == QStringLiteral("verify"));
        hashCompareFilePath->setEnabled(mode == QStringLiteral("compare"));

        if (mode != QStringLiteral("verify")) {
            hashExpectedValue->clear();
        }

        if (mode != QStringLiteral("compare")) {
            hashCompareFilePath->clear();
        }
    };

    connect(hashModeCombo, &QComboBox::currentIndexChanged, this, updateHashModeFields);

    connect(fileBrowse, &QPushButton::clicked, this, [this]() {
        QString path = QFileDialog::getOpenFileName(this, "Select HASH File");
        if (!path.isEmpty()) {
            hashFilePath->setText(path);
        }
    });

    connect(compareBrowse, &QPushButton::clicked, this, [this]() {
        QString path = QFileDialog::getOpenFileName(this, "Select Compare File");
        if (!path.isEmpty()) {
            hashCompareFilePath->setText(path);
        }
    });

    connect(runButton, &QPushButton::clicked, this, &MainWindow::runHashCommand);

    connect(clearButton, &QPushButton::clicked, hashOutputLog, &QTextEdit::clear);

    updateHashModeFields();
}

void MainWindow::runHashCommand()
{
    hashOutputLog->clear();

    const QString algorithm = hashAlgorithmCombo->currentData().toString();
    const QString algorithmLabel = hashAlgorithmCombo->currentText();
    const QString mode = hashModeCombo->currentData().toString();
    const QString modeLabel = hashModeCombo->currentText();

    const QString filePath = hashFilePath->text().trimmed();
    const QString expectedHash = hashExpectedValue->text().trimmed();
    const QString compareFilePath = hashCompareFilePath->text().trimmed();

    if (filePath.isEmpty()) {
        QMessageBox::warning(
            this,
            "K1Wi HASH",
            "Select a file before running HASH."
        );

        hashOutputLog->append("[GUI] HASH cancelled: no file selected.");
        return;
    }

    QFileInfo fileInfo(filePath);

    if (!fileInfo.exists()) {
        QMessageBox::warning(
            this,
            "K1Wi HASH",
            "The selected file does not exist."
        );

        hashOutputLog->append("[GUI] HASH cancelled: selected file does not exist.");
        hashOutputLog->append("[GUI] File: " + filePath);
        return;
    }

    if (!fileInfo.isFile()) {
        QMessageBox::warning(
            this,
            "K1Wi HASH",
            "The selected path is not a regular file."
        );

        hashOutputLog->append("[GUI] HASH cancelled: selected path is not a regular file.");
        hashOutputLog->append("[GUI] File: " + filePath);
        return;
    }

    if (mode == QStringLiteral("verify") && expectedHash.isEmpty()) {
        QMessageBox::warning(
            this,
            "K1Wi HASH",
            "Enter the expected hash before running verify mode."
        );

        hashOutputLog->append("[GUI] HASH cancelled: expected hash is empty.");
        return;
    }

    QFileInfo compareFileInfo(compareFilePath);

    if (mode == QStringLiteral("compare")) {
        if (compareFilePath.isEmpty()) {
            QMessageBox::warning(
                this,
                "K1Wi HASH",
                "Select a compare file before running compare mode."
            );

            hashOutputLog->append("[GUI] HASH cancelled: no compare file selected.");
            return;
        }

        if (!compareFileInfo.exists()) {
            QMessageBox::warning(
                this,
                "K1Wi HASH",
                "The selected compare file does not exist."
            );

            hashOutputLog->append("[GUI] HASH cancelled: compare file does not exist.");
            hashOutputLog->append("[GUI] Compare file: " + compareFilePath);
            return;
        }

        if (!compareFileInfo.isFile()) {
            QMessageBox::warning(
                this,
                "K1Wi HASH",
                "The selected compare path is not a regular file."
            );

            hashOutputLog->append("[GUI] HASH cancelled: compare path is not a regular file.");
            hashOutputLog->append("[GUI] Compare file: " + compareFilePath);
            return;
        }
    }

    QFileInfo cliInfo(resolveK1wiBinary());

    if (!cliInfo.exists() || !cliInfo.isFile() || !cliInfo.isExecutable()) {
        QMessageBox::critical(
            this,
            "K1Wi HASH",
            "The K1Wi CLI binary was not found or is not executable.\n\n"
            "Expected path:\n" + cliInfo.absoluteFilePath()
        );

        hashOutputLog->append("[GUI] HASH cancelled: K1Wi CLI binary is missing or not executable.");
        hashOutputLog->append("[GUI] Expected CLI path: " + cliInfo.absoluteFilePath());
        return;
    }

    QStringList arguments;
    arguments << algorithm;

    if (mode == QStringLiteral("compute")) {
        arguments << filePath;
    } else if (mode == QStringLiteral("verify")) {
        arguments << "-verify" << filePath << expectedHash;
    } else if (mode == QStringLiteral("compare")) {
        arguments << "-compare" << filePath << compareFilePath;
    } else {
        QMessageBox::critical(
            this,
            "K1Wi HASH",
            "Unknown HASH mode selected."
        );

        hashOutputLog->append("[GUI] HASH cancelled: unknown mode selected.");
        return;
    }

    hashOutputLog->append("[GUI] HASH run summary");
    hashOutputLog->append("[GUI] Algorithm: " + algorithmLabel);
    hashOutputLog->append("[GUI] Mode: " + modeLabel);
    hashOutputLog->append("[GUI] File: " + filePath);

    if (mode == QStringLiteral("verify")) {
        hashOutputLog->append("[GUI] Expected hash: " + expectedHash);
    }

    if (mode == QStringLiteral("compare")) {
        hashOutputLog->append("[GUI] Compare file: " + compareFilePath);
    }

    hashOutputLog->append("");
    hashOutputLog->append("Running: " + cliInfo.absoluteFilePath() + " " + arguments.join(" "));
    hashOutputLog->append("");

    QProcess *process = new QProcess(this);
QString *combinedOutput = new QString();

connect(
    process,
    &QProcess::readyReadStandardOutput,
    this,
    [this, process, combinedOutput]() {
        const QString output = stripAnsiCodes(
            QString::fromLocal8Bit(process->readAllStandardOutput())
        );

        combinedOutput->append(output);
        hashOutputLog->append(output);
    }
);

    connect(
        process,
        &QProcess::readyReadStandardError,
        this,
        [this, process, combinedOutput]() {
            const QString output = stripAnsiCodes(
                QString::fromLocal8Bit(process->readAllStandardError())
            );

            combinedOutput->append(output);
            hashOutputLog->append(output);
        }
    );

    connect(
        process,
        QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
        this,
        [this, process, combinedOutput](int exitCode, QProcess::ExitStatus exitStatus) {
            hashOutputLog->append("");

            if (exitStatus == QProcess::NormalExit) {
                const QString summary = hashFriendlySummary(*combinedOutput);

                if (!summary.isEmpty()) {
                    appendStyledLine(hashOutputLog, "Summary", "#0057b8", true);
			appendStyledLine(hashOutputLog, "-------", "#0057b8", true);
			appendStyledBlock(hashOutputLog, summary, resultColorForSummary(summary, exitCode),true); hashOutputLog->append("");
                }

                hashOutputLog->append(
                    QString("Process finished with exit code %1").arg(exitCode)
                );
            } else {
                hashOutputLog->append("[GUI] HASH process crashed or was terminated.");
            }

            delete combinedOutput;
            process->deleteLater();
        }
    );

    process->start(cliInfo.absoluteFilePath(), arguments);

    if (!process->waitForStarted()) {
        hashOutputLog->append("[GUI] Failed to start HASH process.");
        delete combinedOutput;
        process->deleteLater();
    }
}

void MainWindow::runStringCommand()
{
    stringOutputLog->clear();

    const QString inputMode = stringInputModeCombo->currentData().toString();
    const bool fileMode = inputMode == QStringLiteral("file");
    const bool decodeEnabled = stringDecodeCheck->isChecked();

    const QString textInput = stringTextInput->text().trimmed();
    const QString filePath = stringFilePath->text().trimmed();
    const QString minLengthText = stringMinLength->text().trimmed();

    if (!fileMode && textInput.isEmpty()) {
        QMessageBox::warning(
            this,
            "K1Wi STRING",
            "Enter text before running STRING in direct text mode."
        );

        stringOutputLog->append("[GUI] STRING cancelled: no direct text input provided.");
        return;
    }

    if (fileMode && filePath.isEmpty()) {
        QMessageBox::warning(
            this,
            "K1Wi STRING",
            "Select a file before running STRING in file mode."
        );

        stringOutputLog->append("[GUI] STRING cancelled: no file selected.");
        return;
    }

    QFileInfo fileInfo(filePath);

    if (fileMode) {
        if (!fileInfo.exists()) {
            QMessageBox::warning(
                this,
                "K1Wi STRING",
                "The selected file does not exist."
            );

            stringOutputLog->append("[GUI] STRING cancelled: selected file does not exist.");
            stringOutputLog->append("[GUI] File: " + filePath);
            return;
        }

        if (!fileInfo.isFile()) {
            QMessageBox::warning(
                this,
                "K1Wi STRING",
                "The selected path is not a regular file."
            );

            stringOutputLog->append("[GUI] STRING cancelled: selected path is not a regular file.");
            stringOutputLog->append("[GUI] File: " + filePath);
            return;
        }
    }

    int minLength = 0;

    if (fileMode && !minLengthText.isEmpty()) {
        bool ok = false;
        minLength = minLengthText.toInt(&ok);

        if (!ok || minLength < 1) {
            QMessageBox::warning(
                this,
                "K1Wi STRING",
                "Minimum string length must be a positive number."
            );

            stringOutputLog->append("[GUI] STRING cancelled: invalid minimum string length.");
            stringOutputLog->append("[GUI] Minimum string length must be 1 or greater.");
            return;
        }
    }

    const QFileInfo cliInfo(resolveK1wiBinary());

    if (!cliInfo.exists() || !cliInfo.isFile() || !cliInfo.isExecutable()) {
        QMessageBox::critical(
            this,
            "K1Wi STRING",
            "K1Wi CLI binary was not found or is not executable.\n\n"
            "Checked the GUI build layout and system PATH.\n\n"
            "Build the CLI first from the project root."
        );

        stringOutputLog->append("[GUI] STRING cancelled: K1Wi CLI binary was not found or is not executable.");
        stringOutputLog->append("[GUI] Expected: " + cliInfo.absoluteFilePath());
        stringOutputLog->append("[GUI] Build the CLI first from the project root.");
        return;
    }

    QStringList args;
    args << "STRING";

    if (fileMode) {
        args << "--file" << filePath;

        if (decodeEnabled) {
            args << "--decode";
        }

        if (minLength > 0) {
            args << "--min" << QString::number(minLength);
        }
    } else {
        if (decodeEnabled) {
            args << "--decode";
        }

        args << textInput;
    }

    const QString targetLabel = fileMode ? filePath : textInput;

    stringOutputLog->append("[GUI] STRING run summary");
    stringOutputLog->append("[GUI] Input mode: " + stringInputModeCombo->currentText());

    if (fileMode) {
        stringOutputLog->append("[GUI] File: " + filePath);

        if (minLength > 0) {
            stringOutputLog->append("[GUI] Minimum string length: " + QString::number(minLength));
        } else {
            stringOutputLog->append("[GUI] Minimum string length: default");
        }
    } else {
        stringOutputLog->append("[GUI] Text: " + textInput);
    }

    stringOutputLog->append(
        "[GUI] Force decoded output: " +
        QString(decodeEnabled ? "enabled" : "disabled")
    );

    stringOutputLog->append("");
    stringOutputLog->append("Running: " + cliInfo.absoluteFilePath() + " " + args.join(" "));
    stringOutputLog->append("");

    QProcess *process = new QProcess(this);
    QString *combinedOutput = new QString();

    connect(
        process,
        &QProcess::readyReadStandardOutput,
        this,
        [this, process, combinedOutput]() {
            const QString output = stripAnsiCodes(
                QString::fromLocal8Bit(process->readAllStandardOutput())
            );

            combinedOutput->append(output);
            stringOutputLog->append(output);
        }
    );

    connect(
        process,
        &QProcess::readyReadStandardError,
        this,
        [this, process, combinedOutput]() {
            const QString output = stripAnsiCodes(
                QString::fromLocal8Bit(process->readAllStandardError())
            );

            combinedOutput->append(output);
            stringOutputLog->append(output);
        }
    );

    connect(
        process,
        QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
        this,
        [this, process, combinedOutput, fileMode, decodeEnabled, targetLabel](
            int exitCode,
            QProcess::ExitStatus exitStatus
        ) {
            stringOutputLog->append("");

            if (exitStatus == QProcess::NormalExit) {
                const QString summary = stringFriendlySummary(
                    *combinedOutput,
                    exitCode,
                    fileMode,
                    decodeEnabled,
                    targetLabel
                );

                if (!summary.isEmpty()) {
                    appendStyledLine(stringOutputLog, "Summary", "#0057b8", true);
                    appendStyledLine(stringOutputLog, "-------", "#0057b8", true);
                    appendStyledBlock(
                        stringOutputLog,
                        summary,
                        resultColorForSummary(summary, exitCode),
                        true
                    );
                    stringOutputLog->append("");
                }

                stringOutputLog->append(
                    QString("Process finished with exit code %1").arg(exitCode)
                );
            } else {
                appendStyledLine(
                    stringOutputLog,
                    "[RESULT] STRING process crashed or was terminated.",
                    "#b00020",
                    true
                );
            }

            delete combinedOutput;
            process->deleteLater();
        }
    );

    process->start(cliInfo.absoluteFilePath(), args);

    if (!process->waitForStarted()) {
        appendStyledLine(
            stringOutputLog,
            "[RESULT] Failed to start STRING process.",
            "#b00020",
            true
        );

        delete combinedOutput;
        process->deleteLater();
    }
}

void MainWindow::runMagicCommand()
{
    magicOutputLog->clear();

    const QString target = magicTargetPath->text().trimmed();

    if (target.isEmpty()) {
        QMessageBox::warning(this, "K1Wi MAGIC", "Please select a target file.");

        magicOutputLog->append("[GUI] MAGIC cancelled: no target file selected.");
        return;
    }

    const QFileInfo targetInfo(target);

    if (!targetInfo.exists()) {
        QMessageBox::warning(
            this,
            "K1Wi MAGIC",
            "Target file does not exist.\n\nPlease select a valid file."
        );

        magicOutputLog->append("[GUI] MAGIC cancelled: target file does not exist.");
        magicOutputLog->append("[GUI] Target: " + target);
        return;
    }

    if (!targetInfo.isFile()) {
        QMessageBox::warning(
            this,
            "K1Wi MAGIC",
            "Target path is not a regular file.\n\nPlease select a valid file."
        );

        magicOutputLog->append("[GUI] MAGIC cancelled: target path is not a regular file.");
        magicOutputLog->append("[GUI] Target: " + target);
        return;
    }

    const QFileInfo cliInfo(resolveK1wiBinary());

    if (!cliInfo.exists() || !cliInfo.isFile() || !cliInfo.isExecutable()) {
        QMessageBox::critical(
            this,
            "K1Wi MAGIC",
            "K1Wi CLI binary was not found or is not executable.\n\n"
            "Checked the GUI build layout and system PATH.\n\n"
            "Build the CLI first from the project root."
        );

        magicOutputLog->append("[GUI] MAGIC cancelled: K1Wi CLI binary was not found or is not executable.");
        magicOutputLog->append("[GUI] Expected: " + cliInfo.absoluteFilePath());
        magicOutputLog->append("[GUI] Build the CLI first from the project root.");
        return;
    }

    QStringList args;
    args << "MAGIC";
    args << target;

    magicOutputLog->append("[GUI] MAGIC run summary");
    magicOutputLog->append("[GUI] Target: " + target);
    magicOutputLog->append("");
    magicOutputLog->append("Running: " + cliInfo.absoluteFilePath() + " " + args.join(" "));
    magicOutputLog->append("");

    QProcess *process = new QProcess(this);
    QString *combinedOutput = new QString();

    connect(
        process,
        &QProcess::readyReadStandardOutput,
        this,
        [this, process, combinedOutput]() {
            const QString output = stripAnsiCodes(
                QString::fromLocal8Bit(process->readAllStandardOutput())
            );

            combinedOutput->append(output);
            magicOutputLog->append(output);
        }
    );

    connect(
        process,
        &QProcess::readyReadStandardError,
        this,
        [this, process, combinedOutput]() {
            const QString output = stripAnsiCodes(
                QString::fromLocal8Bit(process->readAllStandardError())
            );

            combinedOutput->append(output);
            magicOutputLog->append(output);
        }
    );

    connect(
        process,
        QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
        this,
        [this, process, combinedOutput, target](int exitCode, QProcess::ExitStatus exitStatus) {
            magicOutputLog->append("");

            if (exitStatus == QProcess::NormalExit) {
                const QString summary = magicFriendlySummary(
                    *combinedOutput,
                    exitCode,
                    target
                );

                if (!summary.isEmpty()) {
                    appendStyledLine(magicOutputLog, "Summary", "#0057b8", true);
                    appendStyledLine(magicOutputLog, "-------", "#0057b8", true);
                    appendStyledBlock(
                        magicOutputLog,
                        summary,
                        resultColorForSummary(summary, exitCode),
                        true
                    );
                    magicOutputLog->append("");
                }

                magicOutputLog->append(
                    QString("Process finished with exit code %1").arg(exitCode)
                );
            } else {
                appendStyledLine(
                    magicOutputLog,
                    "[RESULT] MAGIC process crashed or was terminated.",
                    "#b00020",
                    true
                );
            }

            delete combinedOutput;
            process->deleteLater();
        }
    );

    process->start(cliInfo.absoluteFilePath(), args);

    if (!process->waitForStarted()) {
        appendStyledLine(
            magicOutputLog,
            "[RESULT] Failed to start MAGIC process.",
            "#b00020",
            true
        );

        delete combinedOutput;
        process->deleteLater();
    }
}

void MainWindow::runEntropyCommand()
{
    entropyOutputLog->clear();

    const QString target = entropyTargetPath->text().trimmed();
    const QString entropyMode = entropyModeCombo->currentData().toString();
    const QString modeLabel = entropyModeCombo->currentText();

    if (target.isEmpty()) {
        QMessageBox::warning(this, "K1Wi ENTROPY", "Please select a target file.");

        entropyOutputLog->append("[GUI] ENTROPY cancelled: no target file selected.");
        return;
    }

    const QFileInfo targetInfo(target);

    if (!targetInfo.exists()) {
        QMessageBox::warning(
            this,
            "K1Wi ENTROPY",
            "Target file does not exist.\n\nPlease select a valid file."
        );

        entropyOutputLog->append("[GUI] ENTROPY cancelled: target file does not exist.");
        entropyOutputLog->append("[GUI] Target: " + target);
        return;
    }

    if (!targetInfo.isFile()) {
        QMessageBox::warning(
            this,
            "K1Wi ENTROPY",
            "Target path is not a regular file.\n\nPlease select a valid file."
        );

        entropyOutputLog->append("[GUI] ENTROPY cancelled: target path is not a regular file.");
        entropyOutputLog->append("[GUI] Target: " + target);
        return;
    }

    const QFileInfo cliInfo(resolveK1wiBinary());

    if (!cliInfo.exists() || !cliInfo.isFile() || !cliInfo.isExecutable()) {
        QMessageBox::critical(
            this,
            "K1Wi ENTROPY",
            "K1Wi CLI binary was not found or is not executable.\n\n"
            "Checked the GUI build layout and system PATH.\n\n"
            "Build the CLI first from the project root."
        );

        entropyOutputLog->append("[GUI] ENTROPY cancelled: K1Wi CLI binary was not found or is not executable.");
        entropyOutputLog->append("[GUI] Expected: " + cliInfo.absoluteFilePath());
        entropyOutputLog->append("[GUI] Build the CLI first from the project root.");
        return;
    }

    QStringList args;
    args << "ENTROPY";
    args << target;

    if (entropyMode != QStringLiteral("default")) {
        args << entropyMode;
    }

    entropyOutputLog->append("[GUI] ENTROPY run summary");
    entropyOutputLog->append("[GUI] Target: " + target);
    entropyOutputLog->append("[GUI] Mode: " + modeLabel);
    entropyOutputLog->append("");
    entropyOutputLog->append("Running: " + cliInfo.absoluteFilePath() + " " + args.join(" "));
    entropyOutputLog->append("");

    QProcess *process = new QProcess(this);
    QString *combinedOutput = new QString();

    connect(
        process,
        &QProcess::readyReadStandardOutput,
        this,
        [this, process, combinedOutput]() {
            const QString output = stripAnsiCodes(
                QString::fromLocal8Bit(process->readAllStandardOutput())
            );

            combinedOutput->append(output);
            entropyOutputLog->append(output);
        }
    );

    connect(
        process,
        &QProcess::readyReadStandardError,
        this,
        [this, process, combinedOutput]() {
            const QString output = stripAnsiCodes(
                QString::fromLocal8Bit(process->readAllStandardError())
            );

            combinedOutput->append(output);
            entropyOutputLog->append(output);
        }
    );

    connect(
        process,
        QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
        this,
        [this, process, combinedOutput, target, modeLabel](
            int exitCode,
            QProcess::ExitStatus exitStatus
        ) {
            entropyOutputLog->append("");

            if (exitStatus == QProcess::NormalExit) {
                const QString summary = entropyFriendlySummary(
                    *combinedOutput,
                    exitCode,
                    target,
                    modeLabel
                );

                if (!summary.isEmpty()) {
                    appendStyledLine(entropyOutputLog, "Summary", "#0057b8", true);
                    appendStyledLine(entropyOutputLog, "-------", "#0057b8", true);
                    appendStyledBlock(
                        entropyOutputLog,
                        summary,
                        resultColorForSummary(summary, exitCode),
                        true
                    );
                    entropyOutputLog->append("");
                }

                entropyOutputLog->append(
                    QString("Process finished with exit code %1").arg(exitCode)
                );
            } else {
                appendStyledLine(
                    entropyOutputLog,
                    "[RESULT] ENTROPY process crashed or was terminated.",
                    "#b00020",
                    true
                );
            }

            delete combinedOutput;
            process->deleteLater();
        }
    );

    process->start(cliInfo.absoluteFilePath(), args);

    if (!process->waitForStarted()) {
        appendStyledLine(
            entropyOutputLog,
            "[RESULT] Failed to start ENTROPY process.",
            "#b00020",
            true
        );

        delete combinedOutput;
        process->deleteLater();
    }
}

void MainWindow::runPcapCommand()
{
    pcapFindingsLog->clear();
    pcapOutputLog->clear();

    pcapFindingsLog->append("[GUI] Analysis in progress...");

    const QString target = pcapTargetPath->text().trimmed();
    const QString pcapMode = pcapModeCombo->currentData().toString();
    const QString modeLabel = pcapModeCombo->currentText();

    if (target.isEmpty()) {
        QMessageBox::warning(this, "K1Wi PCAP", "Please select a PCAP file.");

        pcapOutputLog->append("[GUI] PCAP cancelled: no target file selected.");
        return;
    }

    const QFileInfo targetInfo(target);

    if (!targetInfo.exists()) {
        QMessageBox::warning(
            this,
            "K1Wi PCAP",
            "PCAP file does not exist.\n\nPlease select a valid file."
        );

        pcapOutputLog->append("[GUI] PCAP cancelled: target file does not exist.");
        pcapOutputLog->append("[GUI] Target: " + target);
        return;
    }

    if (!targetInfo.isFile()) {
        QMessageBox::warning(
            this,
            "K1Wi PCAP",
            "Target path is not a regular file.\n\nPlease select a valid PCAP file."
        );

        pcapOutputLog->append("[GUI] PCAP cancelled: target path is not a regular file.");
        pcapOutputLog->append("[GUI] Target: " + target);
        return;
    }

    const QFileInfo cliInfo(resolveK1wiBinary());

    if (!cliInfo.exists() || !cliInfo.isFile() || !cliInfo.isExecutable()) {
        QMessageBox::critical(
            this,
            "K1Wi PCAP",
            "K1Wi CLI binary was not found or is not executable.\n\n"
            "Checked the GUI build layout and system PATH.\n\n"
            "Build the CLI first from the project root."
        );

        pcapOutputLog->append("[GUI] PCAP cancelled: K1Wi CLI binary was not found or is not executable.");
        pcapOutputLog->append("[GUI] Expected: " + cliInfo.absoluteFilePath());
        pcapOutputLog->append("[GUI] Build the CLI first from the project root.");
        return;
    }

    QStringList args;
    args << "PCAP";

    if (pcapMode == QStringLiteral("--full")) {
        args << "--full";
    } else {
        args << "--summary";
    }

    args << target;

    pcapOutputLog->append("[GUI] PCAP run summary");
    pcapOutputLog->append("[GUI] Target: " + target);
    pcapOutputLog->append("[GUI] Mode: " + modeLabel);
    pcapOutputLog->append("");
    pcapOutputLog->append("Running: " + cliInfo.absoluteFilePath() + " " + args.join(" "));
    pcapOutputLog->append("");

    QProcess *process = new QProcess(this);
    QString *combinedOutput = new QString();

    connect(
        process,
        &QProcess::readyReadStandardOutput,
        this,
        [this, process, combinedOutput]() {
            const QString output = stripAnsiCodes(
                QString::fromLocal8Bit(process->readAllStandardOutput())
            );

            combinedOutput->append(output);
            pcapOutputLog->append(output);
        }
    );

    connect(
        process,
        &QProcess::readyReadStandardError,
        this,
        [this, process, combinedOutput]() {
            const QString output = stripAnsiCodes(
                QString::fromLocal8Bit(process->readAllStandardError())
            );

            combinedOutput->append(output);
            pcapOutputLog->append(output);
        }
    );

    connect(
        process,
        QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
        this,
        [this, process, combinedOutput](int exitCode, QProcess::ExitStatus exitStatus) {
            pcapOutputLog->append("");

            if (exitStatus == QProcess::NormalExit) {
                if (exitCode == 0) {
                    pcapFindingsLog->clear();

                    appendStyledLine(
                        pcapFindingsLog,
                        "[RESULT] Packet capture analysis completed successfully.",
                        "#0b7a0b",
                        true
                    );

                    appendStyledLine(
                        pcapFindingsLog,
                        "[RESULT] Capture overview",
                        "#0057b8",
                        true
                    );

                    const QString captureFormat =
                        pcapReportValue(
                            *combinedOutput,
                            QStringLiteral("Format:")
                        );

                    const QString linkType =
                        pcapReportValue(
                            *combinedOutput,
                            QStringLiteral("Link type:")
                        );

                    const QString timestampPrecision =
                        pcapReportValue(
                            *combinedOutput,
                            QStringLiteral("Timestamp precision:")
                        );

                    const QString capturedBytes =
                        pcapReportValue(
                            *combinedOutput,
                            QStringLiteral("Captured bytes:")
                        );

                    const QString duration =
                        pcapReportValue(
                            *combinedOutput,
                            QStringLiteral("Duration:")
                        );

                    const QString averagePacketSize =
                        pcapReportValue(
                            *combinedOutput,
                            QStringLiteral(
                                "Average captured packet size:"
                            )
                        );

                    if (!captureFormat.isEmpty()) {
                        appendStyledLine(
                            pcapFindingsLog,
                            QStringLiteral("[FINDING] Format: ") +
                                captureFormat,
                            "#0057b8",
                            false
                        );
                    }

                    if (!linkType.isEmpty()) {
                        appendStyledLine(
                            pcapFindingsLog,
                            QStringLiteral("[FINDING] Link type: ") +
                                linkType,
                            "#0057b8",
                            false
                        );
                    }

                    if (!timestampPrecision.isEmpty()) {
                        appendStyledLine(
                            pcapFindingsLog,
                            QStringLiteral(
                                "[FINDING] Timestamp precision: "
                            ) + timestampPrecision,
                            "#0057b8",
                            false
                        );
                    }

                    appendPcapFinding(
                        pcapFindingsLog,
                        QStringLiteral("Packets"),
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("Packets:")
                        )
                    );

                    if (!capturedBytes.isEmpty()) {
                        appendStyledLine(
                            pcapFindingsLog,
                            QStringLiteral("[FINDING] Captured bytes: ") +
                                capturedBytes,
                            "#0057b8",
                            false
                        );
                    }

                    if (!duration.isEmpty()) {
                        appendStyledLine(
                            pcapFindingsLog,
                            QStringLiteral("[FINDING] Duration: ") +
                                duration,
                            "#0057b8",
                            false
                        );
                    }

                    if (!averagePacketSize.isEmpty()) {
                        appendStyledLine(
                            pcapFindingsLog,
                            QStringLiteral(
                                "[FINDING] Average packet size: "
                            ) + averagePacketSize,
                            "#0057b8",
                            false
                        );
                    }

                    appendStyledLine(
                        pcapFindingsLog,
                        "[RESULT] Core traffic counts",
                        "#0057b8",
                        true
                    );

                    appendPcapFinding(
                        pcapFindingsLog,
                        QStringLiteral("IPv4 packets"),
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("IPv4 packets:")
                        )
                    );

                    appendPcapFinding(
                        pcapFindingsLog,
                        QStringLiteral("TCP packets"),
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("TCP packets:")
                        )
                    );

                    appendPcapFinding(
                        pcapFindingsLog,
                        QStringLiteral("UDP packets"),
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("UDP packets:")
                        )
                    );

                    appendPcapFinding(
                        pcapFindingsLog,
                        QStringLiteral("ICMP packets"),
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("ICMP packets:")
                        )
                    );

                    const bool hasNotableActivity =
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("ARP frames:")
                        ) > 0 ||
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("IPv6 frames:")
                        ) > 0 ||
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("Tagged frames:")
                        ) > 0 ||
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("Directional flows:")
                        ) > 0 ||
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("TCP payload packets:")
                        ) > 0 ||
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("TCP payload bytes:")
                        ) > 0 ||
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral(
                                "Base64-like TCP payload packets:"
                            )
                        ) > 0;

                    if (hasNotableActivity) {
                        appendStyledLine(
                            pcapFindingsLog,
                            "[RESULT] Notable activity",
                            "#0057b8",
                            true
                        );
                    }

                    appendPcapOptionalFinding(
                        pcapFindingsLog,
                        QStringLiteral("ARP frames"),
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("ARP frames:")
                        ),
                        QStringLiteral(
                            "ARP traffic was observed in the capture."
                        )
                    );

                    appendPcapOptionalFinding(
                        pcapFindingsLog,
                        QStringLiteral("IPv6 frames"),
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("IPv6 frames:")
                        ),
                        QStringLiteral(
                            "IPv6 traffic was observed in the capture."
                        )
                    );

                    appendPcapOptionalFinding(
                        pcapFindingsLog,
                        QStringLiteral("VLAN-tagged frames"),
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("Tagged frames:")
                        ),
                        QStringLiteral(
                            "One or more VLAN-tagged Ethernet frames were found."
                        )
                    );

                    appendPcapOptionalFinding(
                        pcapFindingsLog,
                        QStringLiteral("Directional TCP flows"),
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("Directional flows:")
                        ),
                        QStringLiteral(
                            "TCP payload fragments were grouped by directional flow."
                        )
                    );

                    appendPcapOptionalFinding(
                        pcapFindingsLog,
                        QStringLiteral("TCP payload packets"),
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("TCP payload packets:")
                        ),
                        QStringLiteral(
                            "Application payload data was present in TCP packets."
                        )
                    );

                    appendPcapOptionalFinding(
                        pcapFindingsLog,
                        QStringLiteral("TCP payload bytes"),
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("TCP payload bytes:")
                        ),
                        QString()
                    );

                    appendPcapOptionalFinding(
                        pcapFindingsLog,
                        QStringLiteral("Base64-like TCP payload packets"),
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral(
                                "Base64-like TCP payload packets:"
                            )
                        ),
                        QStringLiteral(
                            "Base64-like data was detected in TCP payloads."
                        )
                    );

                    if (combinedOutput->contains(
                            "Decoded TCP Payload Reconstruction by Time"
                        )) {
                        appendStyledLine(
                            pcapFindingsLog,
                            "[NOTE] Time-order decoded TCP reconstruction is available.",
                            "#b35c00",
                            true
                        );
                    }

                } else {
                    pcapFindingsLog->clear();

                    appendStyledLine(
                        pcapFindingsLog,
                        "[RESULT] PCAP analysis finished with a non-zero exit code.",
                        "#b00020",
                        true
                    );
                }

                pcapOutputLog->append(
                    QString("Process finished with exit code %1").arg(exitCode)
                );
            } else {
                pcapFindingsLog->clear();

                appendStyledLine(
                    pcapFindingsLog,
                    "[RESULT] PCAP process crashed or was terminated.",
                    "#b00020",
                    true
                );
            }

            delete combinedOutput;
            process->deleteLater();
        }
    );

    process->start(cliInfo.absoluteFilePath(), args);

    if (!process->waitForStarted()) {
        pcapFindingsLog->clear();

        appendStyledLine(
            pcapFindingsLog,
            "[RESULT] Failed to start PCAP process.",
            "#b00020",
            true
        );

        delete combinedOutput;
        process->deleteLater();
    }
}


void MainWindow::runCopyCommand()
{
    outputLog->clear();

    const QString source = sourcePath->text().trimmed();
    const QString destination = destPath->text().trimmed();

    if (source.isEmpty()) {
        QMessageBox::warning(this, "K1Wi COPY", "Please select a source path.");

        outputLog->append("[GUI] COPY cancelled: no source path selected.");
        return;
    }

    if (destination.isEmpty()) {
        QMessageBox::warning(this, "K1Wi COPY", "Please select a destination path.");

        outputLog->append("[GUI] COPY cancelled: no destination path selected.");
        return;
    }

    if (!QFileInfo::exists(source)) {
        QMessageBox::warning(
            this,
            "K1Wi COPY",
            "Source path does not exist.\n\nPlease select a valid source file or directory."
        );

        outputLog->append("[GUI] COPY cancelled: source path does not exist.");
        outputLog->append("[GUI] Source: " + source);
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

        outputLog->append("[GUI] COPY cancelled: recursive mode requires a source directory.");
        outputLog->append("[GUI] Source: " + source);
        return;
    }

    if (!recursiveMode && !sourceInfo.isFile()) {
        QMessageBox::warning(
            this,
            "K1Wi COPY",
            "File copy requires a regular source file."
        );

        outputLog->append("[GUI] COPY cancelled: file mode requires a regular source file.");
        outputLog->append("[GUI] Source: " + source);
        return;
    }

    if (QFileInfo::exists(destination) && !forceCheck->isChecked()) {
        QMessageBox::warning(
            this,
            "K1Wi COPY",
            "Destination already exists.\n\nCheck \"Force overwrite\" to intentionally merge into the existing destination."
        );

        outputLog->append("[GUI] COPY cancelled: destination already exists.");
        outputLog->append("[GUI] Destination: " + destination);
        outputLog->append("[GUI] Check \"Force overwrite\" to intentionally merge into the existing destination.");
        return;
    }

    const QFileInfo cliInfo(resolveK1wiBinary());

    if (!cliInfo.exists() || !cliInfo.isFile() || !cliInfo.isExecutable()) {
        QMessageBox::critical(
            this,
            "K1Wi COPY",
            "K1Wi CLI binary was not found or is not executable.\n\n"
            "Checked the GUI build layout and system PATH.\n\n"
            "Build the CLI first from the project root."
        );

        outputLog->append("[GUI] COPY cancelled: K1Wi CLI binary was not found or is not executable.");
        outputLog->append("[GUI] Expected: " + cliInfo.absoluteFilePath());
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
    outputLog->append(
        "[GUI] Force overwrite / merge: " +
        QString(forceCheck->isChecked() ? "enabled" : "disabled")
    );

    outputLog->append("");
    outputLog->append("Running: " + cliInfo.absoluteFilePath() + " " + args.join(" "));
    outputLog->append("");

    QProcess *process = new QProcess(this);
    QString *combinedOutput = new QString();

    connect(
        process,
        &QProcess::readyReadStandardOutput,
        this,
        [this, process, combinedOutput]() {
            const QString output = stripAnsiCodes(
                QString::fromLocal8Bit(process->readAllStandardOutput())
            );

            combinedOutput->append(output);
            outputLog->append(output);
        }
    );

    connect(
        process,
        &QProcess::readyReadStandardError,
        this,
        [this, process, combinedOutput]() {
            const QString output = stripAnsiCodes(
                QString::fromLocal8Bit(process->readAllStandardError())
            );

            combinedOutput->append(output);
            outputLog->append(output);
        }
    );

    connect(
        process,
        QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
        this,
        [this, process, combinedOutput, destination, recursiveMode](
            int exitCode,
            QProcess::ExitStatus exitStatus
        ) {
            outputLog->append("");

            if (exitStatus == QProcess::NormalExit) {
                const QString summary = copyFriendlySummary(
                    *combinedOutput,
                    exitCode,
                    destination,
                    recursiveMode
                );

                if (!summary.isEmpty()) {
                    appendStyledLine(outputLog, "Summary", "#0057b8", true); 
                    appendStyledLine(outputLog, "-------", "#0057b8", true);
		    appendStyledBlock(outputLog, summary, resultColorForSummary(summary, exitCode), true); 
		    outputLog->append("");
                }

                outputLog->append(
                    QString("Process finished with exit code %1").arg(exitCode)
                );
            } else {
                outputLog->append("[GUI] COPY process crashed or was terminated.");
            }

            delete combinedOutput;
            process->deleteLater();
        }
    );

    process->start(cliInfo.absoluteFilePath(), args);

    if (!process->waitForStarted()) {
        outputLog->append("[GUI] Failed to start COPY process.");
        delete combinedOutput;
        process->deleteLater();
    }
}

void MainWindow::runLyzerCommand()
{
    lyzerOutputLog->clear();

    const QString target = lyzerTargetPath->text().trimmed();

    if (target.isEmpty()) {
        QMessageBox::warning(this, "K1Wi LYZER", "Please select a target file.");

        lyzerOutputLog->append("[GUI] LYZER cancelled: no target file selected.");
        return;
    }

    const QFileInfo targetInfo(target);

    if (!targetInfo.exists()) {
        QMessageBox::warning(
            this,
            "K1Wi LYZER",
            "Target file does not exist.\n\nPlease select a valid file."
        );

        lyzerOutputLog->append("[GUI] LYZER cancelled: target file does not exist.");
        lyzerOutputLog->append("[GUI] Target: " + target);
        return;
    }

    if (!targetInfo.isFile()) {
        QMessageBox::warning(
            this,
            "K1Wi LYZER",
            "Target path is not a regular file.\n\nPlease select a valid file."
        );

        lyzerOutputLog->append("[GUI] LYZER cancelled: target path is not a regular file.");
        lyzerOutputLog->append("[GUI] Target: " + target);
        return;
    }

    const QFileInfo cliInfo(resolveK1wiBinary());

    if (!cliInfo.exists() || !cliInfo.isFile() || !cliInfo.isExecutable()) {
        QMessageBox::critical(
            this,
            "K1Wi LYZER",
            "K1Wi CLI binary was not found or is not executable.\n\n"
            "Checked the GUI build layout and system PATH.\n\n"
            "Build the CLI first from the project root."
        );

        lyzerOutputLog->append("[GUI] LYZER cancelled: K1Wi CLI binary was not found or is not executable.");
        lyzerOutputLog->append("[GUI] Expected: " + cliInfo.absoluteFilePath());
        lyzerOutputLog->append("[GUI] Build the CLI first from the project root.");
        return;
    }

    QStringList args;
    args << "LYZER";
    args << target;

    const QString lyzerMode = lyzerModeCombo->currentData().toString();
    const QString modeLabel = lyzerModeCombo->currentText();

    if (!lyzerMode.isEmpty()) {
        args << lyzerMode;
    }

    lyzerOutputLog->append("[GUI] LYZER run summary");
    lyzerOutputLog->append("[GUI] Target: " + target);
    lyzerOutputLog->append("[GUI] Mode: " + modeLabel);
    lyzerOutputLog->append("");
    lyzerOutputLog->append("Running: " + cliInfo.absoluteFilePath() + " " + args.join(" "));
    lyzerOutputLog->append("");

    QProcess *process = new QProcess(this);
    QString *combinedOutput = new QString();

    connect(
        process,
        &QProcess::readyReadStandardOutput,
        this,
        [this, process, combinedOutput]() {
            const QString output = stripAnsiCodes(
                QString::fromLocal8Bit(process->readAllStandardOutput())
            );

            combinedOutput->append(output);
            lyzerOutputLog->append(output);
        }
    );

    connect(
        process,
        &QProcess::readyReadStandardError,
        this,
        [this, process, combinedOutput]() {
            const QString output = stripAnsiCodes(
                QString::fromLocal8Bit(process->readAllStandardError())
            );

            combinedOutput->append(output);
            lyzerOutputLog->append(output);
        }
    );

    connect(
        process,
        QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
        this,
        [this, process, combinedOutput, target, modeLabel](
            int exitCode,
            QProcess::ExitStatus exitStatus
        ) {
            lyzerOutputLog->append("");

            if (exitStatus == QProcess::NormalExit) {
                const QString summary = lyzerFriendlySummary(
                    *combinedOutput,
                    exitCode,
                    target,
                    modeLabel
                );

                if (!summary.isEmpty()) {
                    appendStyledLine(lyzerOutputLog, "Summary", "#0057b8", true);
                    appendStyledLine(lyzerOutputLog, "-------", "#0057b8", true);
                    appendStyledBlock(
                        lyzerOutputLog,
                        summary,
                        lyzerColorForSummary(summary, exitCode),
                        true
                    );
                    lyzerOutputLog->append("");
                }

                lyzerOutputLog->append(
                    QString("Process finished with exit code %1").arg(exitCode)
                );
            } else {
                appendStyledLine(
                    lyzerOutputLog,
                    "[RESULT] LYZER process crashed or was terminated.",
                    "#b00020",
                    true
                );
            }

            delete combinedOutput;
            process->deleteLater();
        }
    );

    process->start(cliInfo.absoluteFilePath(), args);

    if (!process->waitForStarted()) {
        appendStyledLine(
            lyzerOutputLog,
            "[RESULT] Failed to start LYZER process.",
            "#b00020",
            true
        );

        delete combinedOutput;
        process->deleteLater();
    }
}
void MainWindow::runExtractCommand()
{
    extractOutputLog->clear();

    const QString target = extractTargetPath->text().trimmed();

    if (target.isEmpty()) {
        QMessageBox::warning(this, "K1Wi EXTRACT", "Please select a target file.");

        extractOutputLog->append("[GUI] EXTRACT cancelled: no target file selected.");
        return;
    }

    const QFileInfo targetInfo(target);

    if (!targetInfo.exists()) {
        QMessageBox::warning(
            this,
            "K1Wi EXTRACT",
            "Target file does not exist.\n\nPlease select a valid file."
        );

        extractOutputLog->append("[GUI] EXTRACT cancelled: target file does not exist.");
        extractOutputLog->append("[GUI] Target: " + target);
        return;
    }

    if (!targetInfo.isFile()) {
        QMessageBox::warning(
            this,
            "K1Wi EXTRACT",
            "Target path is not a regular file.\n\nPlease select a valid file."
        );

        extractOutputLog->append("[GUI] EXTRACT cancelled: target path is not a regular file.");
        extractOutputLog->append("[GUI] Target: " + target);
        return;
    }

    const QFileInfo cliInfo(resolveK1wiBinary());

    if (!cliInfo.exists() || !cliInfo.isFile() || !cliInfo.isExecutable()) {
        QMessageBox::critical(
            this,
            "K1Wi EXTRACT",
            "K1Wi CLI binary was not found or is not executable.\n\n"
            "Checked the GUI build layout and system PATH.\n\n"
            "Build the CLI first from the project root."
        );

        extractOutputLog->append("[GUI] EXTRACT cancelled: K1Wi CLI binary was not found or is not executable.");
        extractOutputLog->append("[GUI] Expected: " + cliInfo.absoluteFilePath());
        extractOutputLog->append("[GUI] Build the CLI first from the project root.");
        return;
    }

    const bool recursiveMode = extractRecursiveCheck->isChecked();

    QStringList args;
    args << "EXTRACT";

    if (recursiveMode) {
        args << "--recursive";
    }

    args << target;

    extractOutputLog->append("[GUI] EXTRACT run summary");
    extractOutputLog->append("[GUI] Target: " + target);
    extractOutputLog->append(
        "[GUI] Recursive: " +
        QString(recursiveMode ? "enabled" : "disabled")
    );

    extractOutputLog->append("");
    extractOutputLog->append("Running: " + cliInfo.absoluteFilePath() + " " + args.join(" "));
    extractOutputLog->append("");

    QProcess *process = new QProcess(this);
    QString *combinedOutput = new QString();

    connect(
        process,
        &QProcess::readyReadStandardOutput,
        this,
        [this, process, combinedOutput]() {
            const QString output = stripAnsiCodes(
                QString::fromLocal8Bit(process->readAllStandardOutput())
            );

            combinedOutput->append(output);
            extractOutputLog->append(output);
        }
    );

    connect(
        process,
        &QProcess::readyReadStandardError,
        this,
        [this, process, combinedOutput]() {
            const QString output = stripAnsiCodes(
                QString::fromLocal8Bit(process->readAllStandardError())
            );

            combinedOutput->append(output);
            extractOutputLog->append(output);
        }
    );

    connect(
        process,
        QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
        this,
        [this, process, combinedOutput, target, recursiveMode](
            int exitCode,
            QProcess::ExitStatus exitStatus
        ) {
            extractOutputLog->append("");

            if (exitStatus == QProcess::NormalExit) {
                const QString summary = extractFriendlySummary(
                    *combinedOutput,
                    exitCode,
                    target,
                    recursiveMode
                );

                if (!summary.isEmpty()) {
                    appendStyledLine(extractOutputLog, "Summary", "#0057b8", true);
                    appendStyledLine(extractOutputLog, "-------", "#0057b8", true);
                    appendStyledBlock(
                        extractOutputLog,
                        summary,
                        resultColorForSummary(summary, exitCode),
                        true
                    );
                    extractOutputLog->append("");
                }

                extractOutputLog->append(
                    QString("Process finished with exit code %1").arg(exitCode)
                );
            } else {
                appendStyledLine(
                    extractOutputLog,
                    "[RESULT] EXTRACT process crashed or was terminated.",
                    "#b00020",
                    true
                );
            }

            delete combinedOutput;
            process->deleteLater();
        }
    );

    process->start(cliInfo.absoluteFilePath(), args);

    if (!process->waitForStarted()) {
        appendStyledLine(
            extractOutputLog,
            "[RESULT] Failed to start EXTRACT process.",
            "#b00020",
            true
        );

        delete combinedOutput;
        process->deleteLater();
    }
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

    QFileInfo binaryInfo(resolveK1wiBinary());
    const QString binaryPath = binaryInfo.absoluteFilePath();

    if (!binaryInfo.exists() || !binaryInfo.isExecutable()) {
        QMessageBox::critical(
            this,
            "K1Wi DEL",
            "K1Wi CLI binary was not found or is not executable.\n\n"
            "Checked the GUI build layout and system PATH.\n\n"
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
    appendStyledLine(delOutputLog, "Summary", "#0057b8", true);
    appendStyledLine(delOutputLog, "-------", "#0057b8", true);
    appendStyledLine(delOutputLog, "[RESULT] DEL cancelled by user.", "#b26a00", true);
    appendStyledLine(
        delOutputLog,
        "[RESULT] No file was deleted because the final confirmation was declined.",
        "#b26a00",
        true
    );
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
    QString *combinedOutput = new QString();

    process->setWorkingDirectory(targetInfo.absolutePath());

    connect(
        process,
        &QProcess::readyReadStandardOutput,
        this,
        [this, process, combinedOutput]() {
            const QString output = stripAnsiCodes(
                QString::fromLocal8Bit(process->readAllStandardOutput())
            );

            combinedOutput->append(output);
            delOutputLog->append(output);
        }
    );

    connect(
        process,
        &QProcess::readyReadStandardError,
        this,
        [this, process, combinedOutput]() {
            const QString output = stripAnsiCodes(
                QString::fromLocal8Bit(process->readAllStandardError())
            );

            combinedOutput->append(output);
            delOutputLog->append(output);
        }
    );

    connect(
        process,
        QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
        this,
        [this, process, combinedOutput, targetInfo, standardLabel](
            int exitCode,
            QProcess::ExitStatus exitStatus
        ) {
            delOutputLog->append("");

            if (exitStatus == QProcess::NormalExit) {
                const QString summary = delFriendlySummary(
                    *combinedOutput,
                    exitCode,
                    targetInfo.absoluteFilePath(),
                    standardLabel
                );

                if (!summary.isEmpty()) {
                    appendStyledLine(delOutputLog, "Summary", "#0057b8", true);
                    appendStyledLine(delOutputLog, "-------", "#0057b8", true);
                    appendStyledBlock(
                        delOutputLog,
                        summary,
                        resultColorForSummary(summary, exitCode),
                        true
                    );
                    delOutputLog->append("");
                }

                delOutputLog->append(
                    QString("Process finished with exit code %1").arg(exitCode)
                );
            } else {
                appendStyledLine(
                    delOutputLog,
                    "[RESULT] DEL process crashed or was terminated.",
                    "#b00020",
                    true
                );
            }

            delete combinedOutput;
            process->deleteLater();
        }
    );

    connect(process, &QProcess::started, this, [process, inputScript]() {
        process->write(inputScript.toLocal8Bit());
        process->closeWriteChannel();
    });

    process->start(binaryPath);

    if (!process->waitForStarted()) {
        appendStyledLine(delOutputLog, "[RESULT] Failed to start DEL process.", "#b00020", true);
        delete combinedOutput;
        process->deleteLater();
    }
}
