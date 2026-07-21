#include "MainWindow.h"
#include <QRegularExpression>
#include <QCheckBox>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QGroupBox>
#include <QStackedWidget>
#include <QList>
#include <QMap>
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
#include <QApplication>
#include <QClipboard>
#include <QSaveFile>
#include <QTextStream>
#include <QAction>
#include <QToolBar>

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


static QString pcapReportFollowingLine(
    const QString &output,
    const QString &label
)
{
    const QStringList lines = output.split('\n');

    for (qsizetype i = 0; i < lines.size(); ++i) {
        if (lines.at(i).trimmed() != label) {
            continue;
        }

        for (qsizetype next = i + 1; next < lines.size(); ++next) {
            const QString value = lines.at(next).trimmed();

            if (value.isEmpty()) {
                continue;
            }

            return value;
        }
    }

    return QString();
}

static QStringList pcapReportSectionLines(
    const QString &output,
    const QString &heading
)
{
    const QStringList lines = output.split('\n');

    for (qsizetype i = 0; i < lines.size(); ++i) {
        if (lines.at(i).trimmed() != heading) {
            continue;
        }

        QStringList section;
        qsizetype line = i + 1;

        if (line < lines.size() &&
            QRegularExpression(
                QStringLiteral(R"(^-+$)")
            ).match(lines.at(line).trimmed()).hasMatch()) {
            ++line;
        }

        for (; line < lines.size(); ++line) {
            const QString value = lines.at(line).trimmed();

            if (value.isEmpty()) {
                break;
            }

            section.append(value);
        }

        return section;
    }

    return QStringList();
}


static QStringList pcapDirectionalFlowSections(
    const QString &output
)
{
    static const QRegularExpression flowHeadingPattern(
        QStringLiteral(
            R"((?m)^Directional flow [0-9]+ of [0-9]+\s*$)"
        )
    );

    QStringList sections;
    QRegularExpressionMatchIterator matches =
        flowHeadingPattern.globalMatch(output);

    QList<QRegularExpressionMatch> headings;

    while (matches.hasNext()) {
        headings.append(matches.next());
    }

    for (qsizetype i = 0; i < headings.size(); ++i) {
        const qsizetype start = headings.at(i).capturedStart();
        const qsizetype end =
            (i + 1 < headings.size())
                ? headings.at(i + 1).capturedStart()
                : output.size();

        const QString section =
            output.mid(start, end - start).trimmed();

        if (!section.isEmpty()) {
            sections.append(section);
        }
    }

    return sections;
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


static QStringList pcapReportTableRows(
    const QString &output,
    const QString &heading
)
{
    const QStringList lines = output.split('\n');

    for (qsizetype i = 0; i < lines.size(); ++i) {
        if (lines.at(i).trimmed() != heading) {
            continue;
        }

        QStringList rows;
        qsizetype row = i + 1;

        if (row < lines.size() &&
            QRegularExpression(
                QStringLiteral(R"(^-+$)")
            ).match(lines.at(row).trimmed()).hasMatch()) {
            ++row;
        }

        for (; row < lines.size(); ++row) {
            const QString value = lines.at(row).trimmed();

            if (value.isEmpty()) {
                break;
            }

            rows.append(value);
        }

        return rows;
    }

    return QStringList();
}

static QStringList pcapReportMatchingLines(
    const QString &output,
    const QRegularExpression &pattern
)
{
    QStringList matches;
    const QStringList lines = output.split('\n');

    for (const QString &line : lines) {
        const QString trimmed = line.trimmed();

        if (pattern.match(trimmed).hasMatch()) {
            matches.append(trimmed);
        }
    }

    return matches;
}


static bool appendPcapReportTable(
    QTextEdit *log,
    const QString &output,
    const QString &reportHeading,
    const QString &displayHeading,
    const QString &category
)
{
    const QStringList rows =
        pcapReportTableRows(output, reportHeading);

    if (rows.isEmpty()) {
        return false;
    }

    if (rows.size() == 1) {
        const QString normalized = rows.first().trimmed().toLower();

        if (normalized == QStringLiteral("n/a") ||
            normalized == QStringLiteral("none")) {
            return false;
        }
    }

    appendStyledLine(
        log,
        QStringLiteral("[%1] %2")
            .arg(category, displayHeading),
        QStringLiteral("#0057b8"),
        true
    );

    for (const QString &row : rows) {
        appendStyledLine(
            log,
            QStringLiteral("  ") + row,
            QStringLiteral("#0057b8"),
            false
        );
    }

    return true;
}


static bool appendPcapTransportCount(
    QTextEdit *log,
    const QString &label,
    int value
)
{
    if (value <= 0) {
        return false;
    }

    appendStyledLine(
        log,
        QStringLiteral("[TRANSPORT] %1: %2")
            .arg(label)
            .arg(value),
        QStringLiteral("#0057b8"),
        false
    );

    return true;
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

    if (output.contains(QStringLiteral("MD5 MISMATCH")) ||
        output.contains(QStringLiteral("SHA256 MISMATCH"))) {
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

static QString extractReportValue(
    const QString &output,
    const QString &label
)
{
    const QRegularExpression pattern(
        QStringLiteral(R"((?:^|\n)\s*)") +
        QRegularExpression::escape(label) +
        QStringLiteral(R"(\s*([^\r\n]+))"),
        QRegularExpression::CaseInsensitiveOption
    );

    const QRegularExpressionMatch match = pattern.match(output);

    if (!match.hasMatch()) {
        return QString();
    }

    return match.captured(1).trimmed();
}

static QString extractStructuredFindings(
    const QString &output,
    int exitCode,
    const QString &target,
    bool recursiveMode
)
{
    const QString outputDirectory =
        extractReportValue(output, QStringLiteral("Output :"));

    const QString recoveredFiles =
        extractReportValue(output, QStringLiteral("Files  :"));

    const QString started =
        extractReportValue(output, QStringLiteral("Started   :"));

    const QString completed =
        extractReportValue(output, QStringLiteral("Completed :"));

    const QString duration =
        extractReportValue(output, QStringLiteral("Duration  :"));

    const bool completedSuccessfully =
        exitCode == 0 &&
        output.contains(
            QStringLiteral("EXTRACT COMPLETE"),
            Qt::CaseInsensitive
        );

    QString report;

    report += QStringLiteral("EXTRACT Findings\n");
    report += QStringLiteral("Target: ") + target + QStringLiteral("\n");
    report += QStringLiteral("Recursive mode: ") +
              QString(recursiveMode ? QStringLiteral("Yes")
                                    : QStringLiteral("No")) +
              QStringLiteral("\n");

    if (!outputDirectory.isEmpty()) {
        report += QStringLiteral("Output directory: ") +
                  outputDirectory +
                  QStringLiteral("\n");
    }

    if (!recoveredFiles.isEmpty()) {
        report += QStringLiteral("Files recovered: ") +
                  recoveredFiles +
                  QStringLiteral("\n");
    }

    if (!started.isEmpty()) {
        report += QStringLiteral("Started: ") +
                  started +
                  QStringLiteral("\n");
    }

    if (!completed.isEmpty()) {
        report += QStringLiteral("Completed: ") +
                  completed +
                  QStringLiteral("\n");
    }

    if (!duration.isEmpty()) {
        report += QStringLiteral("Duration: ") +
                  duration +
                  QStringLiteral("\n");
    }

    report += QStringLiteral("\nResult\n");

    if (completedSuccessfully) {
        report += QStringLiteral(
            "Extraction completed successfully.\n"
        );
    } else if (exitCode == 0) {
        report += QStringLiteral(
            "Extraction finished. Review the raw output for details.\n"
        );
    } else {
        report += QStringLiteral(
            "Extraction did not complete successfully.\n"
        );
    }

    report += QStringLiteral("Exit code: ") +
              QString::number(exitCode);

    return report;
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

static QString lyzerReportValue(
    const QString &output,
    const QString &label
)
{
    const QRegularExpression pattern(
        QStringLiteral(R"((?:^|\n)\s*)") +
        QRegularExpression::escape(label) +
        QStringLiteral(R"(\s*([^\r\n]+))"),
        QRegularExpression::CaseInsensitiveOption
    );

    const QRegularExpressionMatch match = pattern.match(output);

    if (!match.hasMatch()) {
        return QString();
    }

    return match.captured(1).trimmed();
}

static QString lyzerStructuredFindings(
    const QString &output,
    int exitCode,
    const QString &target,
    const QString &modeLabel
)
{
    const QFileInfo targetInfo(target);

    const QString format =
        lyzerReportValue(output, QStringLiteral("Detected format:"));

    QString bytesAnalyzed =
        lyzerReportValue(output, QStringLiteral("Bytes analyzed:"));

    const QString entropy =
        lyzerReportValue(output, QStringLiteral("Entropy:"));

    const QString chiSquare =
        lyzerReportValue(output, QStringLiteral("Chi-square:"));

    const QString assessment =
        lyzerReportValue(output, QStringLiteral("Assessment:"));

    QString nextStep =
        lyzerReportValue(output, QStringLiteral("Next step:"));

    if (nextStep.isEmpty()) {
        const QRegularExpression nextStepsPattern(
            QStringLiteral(R"(Next steps:\s*\n\s*([^\r\n]+))"),
            QRegularExpression::CaseInsensitiveOption
        );

        const QRegularExpressionMatch match =
            nextStepsPattern.match(output);

        if (match.hasMatch()) {
            nextStep = match.captured(1).trimmed();
        }
    }

    if (bytesAnalyzed.isEmpty() &&
        targetInfo.exists() &&
        targetInfo.isFile()) {
        bytesAnalyzed =
            QString::number(targetInfo.size()) +
            QStringLiteral(" bytes");
    } else if (
        QRegularExpression(
            QStringLiteral(R"(^\d+$)")
        ).match(bytesAnalyzed).hasMatch()
    ) {
        bytesAnalyzed += QStringLiteral(" bytes");
    }

    QString report;

    report += QStringLiteral("LYZER Analysis Findings\n");
    report += QStringLiteral("Target: ") + target + QStringLiteral("\n");
    report += QStringLiteral("Mode: ") + modeLabel + QStringLiteral("\n");

    if (!format.isEmpty()) {
        report +=
            QStringLiteral("Detected format: ") +
            format +
            QStringLiteral("\n");
    }

    if (!bytesAnalyzed.isEmpty()) {
        report +=
            QStringLiteral("Bytes analyzed: ") +
            bytesAnalyzed +
            QStringLiteral("\n");
    }

    if (!entropy.isEmpty()) {
        report +=
            QStringLiteral("Entropy: ") +
            entropy +
            QStringLiteral("\n");
    }

    if (!chiSquare.isEmpty()) {
        report +=
            QStringLiteral("Chi-square: ") +
            chiSquare +
            QStringLiteral("\n");
    }

    report += QStringLiteral("\nAssessment\n");

    if (!assessment.isEmpty()) {
        report += assessment + QStringLiteral("\n");
    } else if (exitCode == 0) {
        report += QStringLiteral(
            "LYZER completed successfully. Review the raw output "
            "for detailed findings.\n"
        );
    } else {
        report += QStringLiteral(
            "LYZER finished with a non-zero exit code.\n"
        );
    }

    if (!nextStep.isEmpty()) {
        report += QStringLiteral("\nRecommended next step\n");
        report += nextStep + QStringLiteral("\n");
    }

    report += QStringLiteral("\nResult\n");
    report += QStringLiteral("Exit code: ") +
              QString::number(exitCode);

    return report;
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
static QString magicReportValue(
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


static QString magicFindingsReport(
    const QString &output,
    const QString &target,
    bool recoveryEnabled,
    const QString &recoveryPath,
    int exitCode
)
{
    const QString detectedFormat =
        magicReportValue(output, QStringLiteral("Detected format:"));

    const QString rawFormat =
        magicReportValue(output, QStringLiteral("Detected raw format:"));

    const QString decodedFormat =
        magicReportValue(output, QStringLiteral("Decoded magic:"));

    const QString bitstreamLength =
        magicReportValue(output, QStringLiteral("Bitstream length:"));

    const QString byteAligned =
        magicReportValue(output, QStringLiteral("Byte aligned:"));

    const QString decodedBytes =
        magicReportValue(output, QStringLiteral("Decoded first bytes:"));

    const QString recoveredPath =
        magicReportValue(
            output,
            QStringLiteral("Recovered decoded bitstream to:")
        );

    const QString recoveredBytes =
        magicReportValue(output, QStringLiteral("Recovered bytes:"));

    const bool unknownFormat =
        output.contains(
            QStringLiteral("Unknown format."),
            Qt::CaseInsensitive
        );

    const bool recoverySkipped =
        output.contains(
            QStringLiteral("Recovery skipped:"),
            Qt::CaseInsensitive
        );

    const bool errorDetected =
        exitCode != 0 ||
        output.contains(QStringLiteral("failed"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("fatal"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("error:"), Qt::CaseInsensitive) ||
        output.contains(QStringLiteral("[ERROR]"), Qt::CaseInsensitive);

    QString classification;
    QString status;

    if (errorDetected) {
        classification =
            QStringLiteral("Process or recovery error");
        status =
            QStringLiteral("Review the raw output before using this result.");
    } else if (!recoveredPath.isEmpty()) {
        classification =
            QStringLiteral("Recovered ASCII bitstream");
        status =
            QStringLiteral("Recovery completed successfully.");
    } else if (recoverySkipped) {
        classification =
            QStringLiteral("Non-byte-aligned ASCII bitstream");
        status =
            QStringLiteral(
                "Recovery was skipped because the stream is not byte-aligned."
            );
    } else if (!rawFormat.isEmpty()) {
        classification =
            QStringLiteral("Encoded ASCII bitstream detected");
        status =
            recoveryEnabled
                ? QStringLiteral(
                    "The stream was inspected but no recovered output "
                    "was confirmed."
                )
                : QStringLiteral(
                    "Run recovery mode to write the decoded bytes to a file."
                );
    } else if (!detectedFormat.isEmpty()) {
        classification =
            QStringLiteral("Recognized file signature");
        status =
            QStringLiteral("No recovery is required.");
    } else if (unknownFormat) {
        classification =
            QStringLiteral("Unknown file signature");
        status =
            QStringLiteral(
                "K1Wi did not match the leading bytes to a known signature."
            );
    } else {
        classification =
            QStringLiteral("No structured result available");
        status =
            QStringLiteral("Review the raw output for details.");
    }

    QString report;

    report += QStringLiteral("MAGIC Analysis Findings\n");
    report += QStringLiteral("=======================\n\n");

    report += QStringLiteral("Target: ") + target + QStringLiteral("\n");
    report += QStringLiteral("Mode: ") +
        (recoveryEnabled
            ? QStringLiteral("Inspect and recover ASCII bitstream")
            : QStringLiteral("Inspect only")) +
        QStringLiteral("\n");

    report += QStringLiteral("Classification: ") +
        classification +
        QStringLiteral("\n");

    report += QStringLiteral("Status: ") +
        status +
        QStringLiteral("\n");

    if (!detectedFormat.isEmpty()) {
        report += QStringLiteral("Detected format: ") +
            detectedFormat +
            QStringLiteral("\n");
    }

    if (!rawFormat.isEmpty()) {
        report += QStringLiteral("Raw format: ") +
            rawFormat +
            QStringLiteral("\n");
    }

    if (!decodedFormat.isEmpty()) {
        report += QStringLiteral("Decoded format: ") +
            decodedFormat +
            QStringLiteral("\n");
    }

    if (!bitstreamLength.isEmpty()) {
        report += QStringLiteral("Bitstream length: ") +
            bitstreamLength +
            QStringLiteral("\n");
    }

    if (!byteAligned.isEmpty()) {
        report += QStringLiteral("Byte aligned: ") +
            byteAligned +
            QStringLiteral("\n");
    }

    if (!decodedBytes.isEmpty()) {
        report += QStringLiteral("Decoded first bytes: ") +
            decodedBytes +
            QStringLiteral("\n");
    }

    if (recoveryEnabled) {
        report += QStringLiteral("Requested recovery path: ") +
            recoveryPath +
            QStringLiteral("\n");
    }

    if (!recoveredPath.isEmpty()) {
        report += QStringLiteral("Recovered output: ") +
            recoveredPath +
            QStringLiteral("\n");
    }

    if (!recoveredBytes.isEmpty()) {
        report += QStringLiteral("Recovered bytes: ") +
            recoveredBytes +
            QStringLiteral("\n");
    }

    report += QStringLiteral("Process exit code: %1").arg(exitCode);

    return report;
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

static QString entropyFindingsReport(
    const QString &output,
    int exitCode,
    const QString &target,
    const QString &modeLabel
)
{
    QString report;

    report += QStringLiteral(
        "ENTROPY Analysis Findings\n"
        "=========================\n\n"
    );

    report += QStringLiteral("Target: %1\n").arg(target);
    report += QStringLiteral("Analysis mode: %1\n").arg(modeLabel);

    const QFileInfo targetInfo(target);

    if (targetInfo.exists() && targetInfo.isFile()) {
        report += QStringLiteral("File size: %1 bytes\n")
                      .arg(targetInfo.size());
    }

    if (exitCode != 0) {
        report += QStringLiteral(
            "Status: Analysis did not complete successfully.\n"
        );
        report += QStringLiteral(
            "Interpretation: Review Raw Output before trusting the result.\n"
        );
        report += QStringLiteral("Process exit code: %1\n")
                      .arg(exitCode);

        return report;
    }

    report += QStringLiteral(
        "Status: Analysis completed successfully.\n"
    );

    const QRegularExpression globalExpression(
        QStringLiteral(
            R"(Global entropy:\s*([0-9]+(?:\.[0-9]+)?)\s*bits/byte)"
        ),
        QRegularExpression::CaseInsensitiveOption
    );

    const QRegularExpressionMatch globalMatch =
        globalExpression.match(output);

    bool globalOk = false;
    double globalEntropy = 0.0;

    if (globalMatch.hasMatch()) {
        globalEntropy =
            globalMatch.captured(1).toDouble(&globalOk);

        if (globalOk) {
            report += QStringLiteral(
                "Global entropy: %1 bits/byte\n"
            ).arg(globalEntropy, 0, 'f', 6);
        }
    }

    const QRegularExpression blockSizeExpression(
        QStringLiteral(
            R"(block size\s+([0-9]+)\s+bytes)"
        ),
        QRegularExpression::CaseInsensitiveOption
    );

    const QRegularExpressionMatch blockSizeMatch =
        blockSizeExpression.match(output);

    if (blockSizeMatch.hasMatch()) {
        report += QStringLiteral(
            "Window size: %1 bytes\n"
        ).arg(blockSizeMatch.captured(1));
    }

    const QRegularExpression blockExpression(
        QStringLiteral(
            R"(\bblock\s+[0-9]+:\s*([0-9]+(?:\.[0-9]+)?)\s*bits/byte)"
        ),
        QRegularExpression::CaseInsensitiveOption
    );

    QRegularExpressionMatchIterator iterator =
        blockExpression.globalMatch(output);

    int blockCount = 0;
    double minimumEntropy = 0.0;
    double maximumEntropy = 0.0;
    double entropyTotal = 0.0;

    while (iterator.hasNext()) {
        const QRegularExpressionMatch match =
            iterator.next();

        bool valueOk = false;
        const double value =
            match.captured(1).toDouble(&valueOk);

        if (!valueOk) {
            continue;
        }

        if (blockCount == 0) {
            minimumEntropy = value;
            maximumEntropy = value;
        } else {
            minimumEntropy =
                qMin(minimumEntropy, value);

            maximumEntropy =
                qMax(maximumEntropy, value);
        }

        entropyTotal += value;
        ++blockCount;
    }

    double averageEntropy = 0.0;

    if (blockCount > 0) {
        averageEntropy =
            entropyTotal /
            static_cast<double>(blockCount);

        report += QStringLiteral(
            "Blocks analyzed: %1\n"
        ).arg(blockCount);

        report += QStringLiteral(
            "Minimum entropy: %1 bits/byte\n"
        ).arg(minimumEntropy, 0, 'f', 6);

        report += QStringLiteral(
            "Maximum entropy: %1 bits/byte\n"
        ).arg(maximumEntropy, 0, 'f', 6);

        report += QStringLiteral(
            "Average entropy: %1 bits/byte\n"
        ).arg(averageEntropy, 0, 'f', 6);
    }

    QString interpretation;

    if (blockCount > 0) {
        const double spread =
            maximumEntropy - minimumEntropy;

        if (
            maximumEntropy >= 7.50 &&
            minimumEntropy < 5.00 &&
            spread >= 2.00
        ) {
            interpretation = QStringLiteral(
                "Mixed-content file with high-entropy regions detected. "
                "Review elevated blocks for compressed, encrypted, packed, "
                "or embedded data."
            );
        } else if (averageEntropy >= 7.50) {
            interpretation = QStringLiteral(
                "Consistently high entropy. The content may be compressed, "
                "encrypted, packed, or strongly randomized."
            );
        } else if (maximumEntropy >= 7.50) {
            interpretation = QStringLiteral(
                "One or more high-entropy regions were detected."
            );
        } else if (averageEntropy < 3.50) {
            interpretation = QStringLiteral(
                "Low average entropy. The file likely contains repetitive, "
                "sparse, or highly structured data."
            );
        } else {
            interpretation = QStringLiteral(
                "Moderate or mixed entropy. No consistently extreme entropy "
                "pattern was detected."
            );
        }
    } else if (globalOk) {
        if (globalEntropy >= 7.50) {
            interpretation = QStringLiteral(
                "High global entropy. The file may be compressed, encrypted, "
                "packed, or strongly randomized."
            );
        } else if (globalEntropy >= 6.00) {
            interpretation = QStringLiteral(
                "Moderately high global entropy. The file may contain dense "
                "binary or partially compressed data."
            );
        } else if (globalEntropy < 3.50) {
            interpretation = QStringLiteral(
                "Low global entropy. The file likely contains repetitive, "
                "sparse, or highly structured data."
            );
        } else {
            interpretation = QStringLiteral(
                "Moderate global entropy. The file does not appear uniformly "
                "random from this measurement alone."
            );
        }
    } else {
        interpretation = QStringLiteral(
            "No numeric entropy value could be parsed. Review Raw Output."
        );
    }

    report += QStringLiteral(
        "Interpretation: %1\n"
    ).arg(interpretation);

    report += QStringLiteral(
        "Process exit code: %1\n"
    ).arg(exitCode);

    return report;
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
        QString path;

        const bool recursiveMode =
            copyModeCombo->currentData().toString() ==
            QStringLiteral("recursive");

        if (recursiveMode) {
            path = QFileDialog::getExistingDirectory(
                this,
                QStringLiteral("Select Source Directory")
            );
        } else {
            path = QFileDialog::getOpenFileName(
                this,
                QStringLiteral("Select Source File")
            );
        }

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

    QLabel *title = new QLabel(
        QStringLiteral("K1Wi Framework - STRING Analyzer"),
        stringTab
    );
    mainLayout->addWidget(title);

    QLabel *description = new QLabel(
        QStringLiteral(
            "Analyze direct text or extract printable strings from a file. "
            "STRING detects encoded data, URLs, email addresses, hashes, "
            "credentials, JWTs, UTF-8 text, ROT13, and other useful patterns."
        ),
        stringTab
    );
    description->setWordWrap(true);
    mainLayout->addWidget(description);

    /*
     * Input mode
     */
    QGroupBox *inputGroup = new QGroupBox(
        QStringLiteral("Analysis input"),
        stringTab
    );
    QVBoxLayout *inputGroupLayout = new QVBoxLayout(inputGroup);

    QHBoxLayout *modeLayout = new QHBoxLayout();
    modeLayout->addWidget(new QLabel(QStringLiteral("Input mode:"), inputGroup));

    stringInputModeCombo = new QComboBox(inputGroup);
    stringInputModeCombo->addItem(QStringLiteral("Direct text"), QStringLiteral("text"));
    stringInputModeCombo->addItem(QStringLiteral("File analysis"), QStringLiteral("file"));
    modeLayout->addWidget(stringInputModeCombo, 1);

    inputGroupLayout->addLayout(modeLayout);

    QStackedWidget *inputStack = new QStackedWidget(inputGroup);

    /*
     * Direct-text page
     */
    QWidget *textPage = new QWidget(inputStack);
    QVBoxLayout *textPageLayout = new QVBoxLayout(textPage);
    textPageLayout->setContentsMargins(0, 0, 0, 0);

    QLabel *textHelp = new QLabel(
        QStringLiteral(
            "Enter one value, token, URL, email address, encoded string, "
            "hash, or other text for analysis."
        ),
        textPage
    );
    textHelp->setWordWrap(true);
    textPageLayout->addWidget(textHelp);

    QHBoxLayout *textLayout = new QHBoxLayout();
    textLayout->addWidget(new QLabel(QStringLiteral("Text:"), textPage));

    stringTextInput = new QLineEdit(textPage);
    stringTextInput->setPlaceholderText(
        QStringLiteral("Example: SGVsbG8= or 48656c6c6f")
    );
    textLayout->addWidget(stringTextInput, 1);

    textPageLayout->addLayout(textLayout);
    inputStack->addWidget(textPage);

    /*
     * File-analysis page
     */
    QWidget *filePage = new QWidget(inputStack);
    QVBoxLayout *filePageLayout = new QVBoxLayout(filePage);
    filePageLayout->setContentsMargins(0, 0, 0, 0);

    QLabel *fileHelp = new QLabel(
        QStringLiteral(
            "Select a file to extract and classify its printable strings."
        ),
        filePage
    );
    fileHelp->setWordWrap(true);
    filePageLayout->addWidget(fileHelp);

    QHBoxLayout *fileLayout = new QHBoxLayout();
    fileLayout->addWidget(new QLabel(QStringLiteral("File:"), filePage));

    stringFilePath = new QLineEdit(filePage);
    stringFilePath->setPlaceholderText(
        QStringLiteral("Select a file to analyze")
    );
    fileLayout->addWidget(stringFilePath, 1);

    QPushButton *fileBrowse = new QPushButton(
        QStringLiteral("Browse File"),
        filePage
    );
    fileLayout->addWidget(fileBrowse);

    filePageLayout->addLayout(fileLayout);

    QHBoxLayout *minLayout = new QHBoxLayout();
    minLayout->addWidget(
        new QLabel(QStringLiteral("Minimum string length:"), filePage)
    );

    stringMinLength = new QLineEdit(filePage);
    stringMinLength->setPlaceholderText(
        QStringLiteral("Optional — use the CLI default when blank")
    );
    minLayout->addWidget(stringMinLength, 1);

    filePageLayout->addLayout(minLayout);
    inputStack->addWidget(filePage);

    inputGroupLayout->addWidget(inputStack);
    mainLayout->addWidget(inputGroup);

    /*
     * Analysis options
     */
    QGroupBox *optionsGroup = new QGroupBox(
        QStringLiteral("Analysis options"),
        stringTab
    );
    QHBoxLayout *optionsLayout = new QHBoxLayout(optionsGroup);

    stringDecodeCheck = new QCheckBox(
        QStringLiteral("Show decoded output when available"),
        optionsGroup
    );
    stringDecodeCheck->setToolTip(
        QStringLiteral(
            "Requests decoded previews for supported encoded values."
        )
    );
    optionsLayout->addWidget(stringDecodeCheck);
    optionsLayout->addStretch();

    mainLayout->addWidget(optionsGroup);

    /*
     * Actions
     */
    QPushButton *runButton = new QPushButton(
        QStringLiteral("Analyze with STRING"),
        stringTab
    );
    runButton->setDefault(true);

    QPushButton *clearButton = new QPushButton(
        QStringLiteral("Clear Results"),
        stringTab
    );

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(runButton, 1);
    buttonLayout->addWidget(clearButton, 1);
    mainLayout->addLayout(buttonLayout);

    /*
     * Results
     */
    stringDetailsTabs = new QTabWidget(stringTab);

    stringFindingsLog = new QTextEdit(stringDetailsTabs);
    stringFindingsLog->setReadOnly(true);
    stringFindingsLog->append(
        QStringLiteral("[GUI] Structured STRING findings will appear here.")
    );
    stringDetailsTabs->addTab(
        stringFindingsLog,
        QStringLiteral("Findings")
    );

    stringOutputLog = new QTextEdit(stringDetailsTabs);
    stringOutputLog->setReadOnly(true);
    stringOutputLog->append(QStringLiteral("[GUI] STRING panel ready."));
    stringOutputLog->append(
        QStringLiteral(
            "[GUI] Choose an input mode, provide a value, and run the analyzer."
        )
    );
    stringDetailsTabs->addTab(
        stringOutputLog,
        QStringLiteral("Raw Output")
    );

    mainLayout->addWidget(stringDetailsTabs, 1);

    auto updateStringModeFields =
        [this, inputStack]() {
            const bool fileMode =
                stringInputModeCombo->currentData().toString() ==
                QStringLiteral("file");

            inputStack->setCurrentIndex(fileMode ? 1 : 0);

            if (fileMode) {
                stringTextInput->clear();
                stringFilePath->setFocus();
            } else {
                stringFilePath->clear();
                stringMinLength->clear();
                stringTextInput->setFocus();
            }
        };

    connect(
        stringInputModeCombo,
        &QComboBox::currentIndexChanged,
        this,
        updateStringModeFields
    );

    connect(fileBrowse, &QPushButton::clicked, this, [this]() {
        const QString path = QFileDialog::getOpenFileName(
            this,
            QStringLiteral("Select STRING File")
        );

        if (!path.isEmpty()) {
            stringFilePath->setText(path);
        }
    });

    connect(
        stringTextInput,
        &QLineEdit::returnPressed,
        this,
        &MainWindow::runStringCommand
    );

    connect(
        runButton,
        &QPushButton::clicked,
        this,
        &MainWindow::runStringCommand
    );

    connect(clearButton, &QPushButton::clicked, this, [this]() {
        stringDetailsTabs->setCurrentIndex(0);

        stringFindingsLog->clear();
        stringOutputLog->clear();

        stringFindingsLog->append(
            QStringLiteral("[GUI] Structured STRING findings will appear here.")
        );

        stringOutputLog->append(QStringLiteral("[GUI] STRING panel ready."));
        stringOutputLog->append(
            QStringLiteral(
                "[GUI] Choose an input mode, provide a value, "
                "and run the analyzer."
            )
        );
    });

    updateStringModeFields();
}

void MainWindow::buildMagicTab()
{
    magicTab = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(magicTab);

    QLabel *title = new QLabel(
        QStringLiteral("K1Wi Framework - MAGIC Detector"),
        magicTab
    );
    mainLayout->addWidget(title);

    QLabel *description = new QLabel(
        QStringLiteral(
            "MAGIC identifies file types by checking file signatures and "
            "magic bytes. It can also recover byte-aligned ASCII binary "
            "digit streams."
        ),
        magicTab
    );
    description->setWordWrap(true);
    mainLayout->addWidget(description);

    QHBoxLayout *modeLayout = new QHBoxLayout();
    magicModeCombo = new QComboBox(magicTab);
    magicModeCombo->addItem(QStringLiteral("Inspect only"));
    magicModeCombo->addItem(
        QStringLiteral("Inspect and recover ASCII bitstream")
    );

    modeLayout->addWidget(
        new QLabel(QStringLiteral("MAGIC mode:"), magicTab)
    );
    modeLayout->addWidget(magicModeCombo);
    modeLayout->addStretch();
    mainLayout->addLayout(modeLayout);

    QHBoxLayout *targetLayout = new QHBoxLayout();
    magicTargetPath = new QLineEdit(magicTab);
    QPushButton *browseButton =
        new QPushButton(QStringLiteral("Browse Target"), magicTab);

    targetLayout->addWidget(
        new QLabel(QStringLiteral("Target file:"), magicTab)
    );
    targetLayout->addWidget(magicTargetPath);
    targetLayout->addWidget(browseButton);
    mainLayout->addLayout(targetLayout);

    QHBoxLayout *recoveryLayout = new QHBoxLayout();
    magicRecoveryPath = new QLineEdit(magicTab);
    magicRecoveryBrowseButton =
        new QPushButton(QStringLiteral("Browse Output"), magicTab);

    recoveryLayout->addWidget(
        new QLabel(QStringLiteral("Recovery output:"), magicTab)
    );
    recoveryLayout->addWidget(magicRecoveryPath);
    recoveryLayout->addWidget(magicRecoveryBrowseButton);
    mainLayout->addLayout(recoveryLayout);

    QPushButton *runButton =
        new QPushButton(QStringLiteral("Run MAGIC"), magicTab);
    QPushButton *clearButton =
        new QPushButton(QStringLiteral("Clear Output"), magicTab);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(runButton);
    buttonLayout->addWidget(clearButton);
    mainLayout->addLayout(buttonLayout);

    magicDetailsTabs = new QTabWidget(magicTab);

    magicFindingsLog = new QTextEdit(magicDetailsTabs);
    magicFindingsLog->setReadOnly(true);
    magicFindingsLog->append(
        QStringLiteral(
            "[GUI] Structured MAGIC findings will appear here."
        )
    );
    magicDetailsTabs->addTab(
        magicFindingsLog,
        QStringLiteral("Findings")
    );

    magicOutputLog = new QTextEdit(magicDetailsTabs);
    magicOutputLog->setReadOnly(true);
    magicOutputLog->append(
        QStringLiteral("[GUI] MAGIC panel ready.")
    );
    magicOutputLog->append(
        QStringLiteral(
            "[GUI] Select a file and choose inspection or recovery mode."
        )
    );
    magicDetailsTabs->addTab(
        magicOutputLog,
        QStringLiteral("Raw Output")
    );

    mainLayout->addWidget(magicDetailsTabs, 1);

    auto updateRecoveryControls = [this]() {
        const bool enabled = magicModeCombo->currentIndex() == 1;

        magicRecoveryPath->setEnabled(enabled);
        magicRecoveryBrowseButton->setEnabled(enabled);

        if (!enabled) {
            magicRecoveryPath->clear();
        }
    };

    connect(
        magicModeCombo,
        QOverload<int>::of(&QComboBox::currentIndexChanged),
        this,
        [updateRecoveryControls](int) {
            updateRecoveryControls();
        }
    );

    connect(browseButton, &QPushButton::clicked, this, [this]() {
        const QString path = QFileDialog::getOpenFileName(
            this,
            QStringLiteral("Select MAGIC Target")
        );

        if (!path.isEmpty()) {
            magicTargetPath->setText(path);
        }
    });

    connect(
        magicRecoveryBrowseButton,
        &QPushButton::clicked,
        this,
        [this]() {
            QString suggestedName = QStringLiteral("recovered.bin");

            const QString target =
                magicTargetPath->text().trimmed();

            if (!target.isEmpty()) {
                suggestedName =
                    QFileInfo(target).completeBaseName() +
                    QStringLiteral("_recovered.bin");
            }

            const QString path = QFileDialog::getSaveFileName(
                this,
                QStringLiteral("Select MAGIC Recovery Output"),
                QDir::current().absoluteFilePath(suggestedName),
                QStringLiteral("All files (*)")
            );

            if (!path.isEmpty()) {
                magicRecoveryPath->setText(path);
            }
        }
    );

    connect(
        runButton,
        &QPushButton::clicked,
        this,
        &MainWindow::runMagicCommand
    );

    connect(clearButton, &QPushButton::clicked, this, [this]() {
        magicDetailsTabs->setCurrentIndex(0);

        magicFindingsLog->clear();
        magicOutputLog->clear();

        magicFindingsLog->append(
            QStringLiteral(
                "[GUI] Structured MAGIC findings will appear here."
            )
        );

        magicOutputLog->append(
            QStringLiteral("[GUI] MAGIC panel ready.")
        );
        magicOutputLog->append(
            QStringLiteral(
                "[GUI] Select a file and choose inspection or recovery mode."
            )
        );
    });

    updateRecoveryControls();
}

void MainWindow::buildEntropyTab()
{
    entropyTab = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(entropyTab);

    QLabel *title = new QLabel(
        QStringLiteral("K1Wi Framework - ENTROPY Analyzer"),
        entropyTab
    );
    mainLayout->addWidget(title);

    QLabel *description = new QLabel(
        QStringLiteral(
            "ENTROPY computes Shannon entropy for files and binary regions. "
            "Use global analysis for one overall measurement, sliding-window "
            "analysis for block statistics, or heatmap analysis to locate "
            "changing and anomalous entropy regions."
        ),
        entropyTab
    );
    description->setWordWrap(true);
    mainLayout->addWidget(description);

    QHBoxLayout *modeLayout = new QHBoxLayout();

    entropyModeCombo = new QComboBox(entropyTab);
    entropyModeCombo->addItem(
        QStringLiteral("Default file entropy"),
        QStringLiteral("default")
    );
    entropyModeCombo->addItem(
        QStringLiteral("Global entropy"),
        QStringLiteral("--global")
    );
    entropyModeCombo->addItem(
        QStringLiteral("Sliding-window entropy"),
        QStringLiteral("--window")
    );
    entropyModeCombo->addItem(
        QStringLiteral("Heatmap entropy"),
        QStringLiteral("--heatmap")
    );

    modeLayout->addWidget(
        new QLabel(
            QStringLiteral("ENTROPY mode:"),
            entropyTab
        )
    );
    modeLayout->addWidget(entropyModeCombo);
    modeLayout->addStretch();
    mainLayout->addLayout(modeLayout);

    QHBoxLayout *targetLayout = new QHBoxLayout();

    entropyTargetPath = new QLineEdit(entropyTab);

    QPushButton *browseButton =
        new QPushButton(
            QStringLiteral("Browse Target"),
            entropyTab
        );

    targetLayout->addWidget(
        new QLabel(
            QStringLiteral("Target file:"),
            entropyTab
        )
    );
    targetLayout->addWidget(entropyTargetPath);
    targetLayout->addWidget(browseButton);
    mainLayout->addLayout(targetLayout);

    QPushButton *runButton =
        new QPushButton(
            QStringLiteral("Run ENTROPY"),
            entropyTab
        );

    QPushButton *clearButton =
        new QPushButton(
            QStringLiteral("Clear Output"),
            entropyTab
        );

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(runButton);
    buttonLayout->addWidget(clearButton);
    buttonLayout->addStretch();
    mainLayout->addLayout(buttonLayout);

    entropyDetailsTabs = new QTabWidget(entropyTab);

    entropyFindingsLog =
        new QTextEdit(entropyDetailsTabs);
    entropyFindingsLog->setReadOnly(true);
    entropyFindingsLog->append(
        QStringLiteral(
            "[GUI] Structured ENTROPY findings will appear here."
        )
    );

    entropyDetailsTabs->addTab(
        entropyFindingsLog,
        QStringLiteral("Findings")
    );

    entropyOutputLog =
        new QTextEdit(entropyDetailsTabs);
    entropyOutputLog->setReadOnly(true);
    entropyOutputLog->append(
        QStringLiteral("[GUI] ENTROPY panel ready.")
    );
    entropyOutputLog->append(
        QStringLiteral(
            "[GUI] Select a file and entropy mode to analyze."
        )
    );

    entropyDetailsTabs->addTab(
        entropyOutputLog,
        QStringLiteral("Raw Output")
    );

    mainLayout->addWidget(entropyDetailsTabs);

    connect(
        browseButton,
        &QPushButton::clicked,
        this,
        [this]() {
            const QString selectedPath =
                QFileDialog::getOpenFileName(
                    this,
                    QStringLiteral("Select ENTROPY Target")
                );

            if (!selectedPath.isEmpty()) {
                entropyTargetPath->setText(selectedPath);
            }
        }
    );

    connect(
        entropyTargetPath,
        &QLineEdit::returnPressed,
        this,
        &MainWindow::runEntropyCommand
    );

    connect(
        runButton,
        &QPushButton::clicked,
        this,
        &MainWindow::runEntropyCommand
    );

    connect(
        clearButton,
        &QPushButton::clicked,
        this,
        [this]() {
            entropyDetailsTabs->setCurrentIndex(0);

            entropyFindingsLog->clear();
            entropyOutputLog->clear();

            entropyFindingsLog->append(
                QStringLiteral(
                    "[GUI] Structured ENTROPY findings will appear here."
                )
            );

            entropyOutputLog->append(
                QStringLiteral("[GUI] ENTROPY panel ready.")
            );
            entropyOutputLog->append(
                QStringLiteral(
                    "[GUI] Select a file and entropy mode to analyze."
                )
            );
        }
    );
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

    QToolBar *reportToolBar =
        addToolBar(QStringLiteral("Report Tools"));

    reportToolBar->setObjectName(
        QStringLiteral("k1wiReportToolBar")
    );

    reportToolBar->setMovable(true);
    reportToolBar->setFloatable(false);

    QAction *copyViewAction =
        reportToolBar->addAction(
            QStringLiteral("Copy View")
        );

    QAction *saveViewAction =
        reportToolBar->addAction(
            QStringLiteral("Save View")
        );

    QAction *saveRawAction =
        reportToolBar->addAction(
            QStringLiteral("Save Raw")
        );

    copyViewAction->setToolTip(
        QStringLiteral(
            "Copy the currently selected PCAP results view"
        )
    );

    saveViewAction->setToolTip(
        QStringLiteral(
            "Save the currently selected PCAP results view"
        )
    );

    saveRawAction->setToolTip(
        QStringLiteral(
            "Save the complete PCAP Raw Output report"
        )
    );

    copyViewAction->setEnabled(false);
    saveViewAction->setEnabled(false);
    saveRawAction->setEnabled(false);

    pcapDetailsTabs = new QTabWidget(pcapTab);

    pcapFindingsLog = new QTextEdit(pcapDetailsTabs);
    pcapFindingsLog->setReadOnly(true);
    pcapFindingsLog->append(
        "[GUI] Findings will appear here after analysis."
    );
    pcapDetailsTabs->addTab(
        pcapFindingsLog,
        "Overview"
    );

    pcapNetworkLog = new QTextEdit(pcapDetailsTabs);
    pcapNetworkLog->setReadOnly(true);
    pcapNetworkLog->append(
        "[GUI] IP, MAC, and VLAN details will appear here."
    );
    pcapDetailsTabs->addTab(
        pcapNetworkLog,
        "Network"
    );

    pcapTransportLog = new QTextEdit(pcapDetailsTabs);
    pcapTransportLog->setReadOnly(true);
    pcapTransportLog->append(
        "[GUI] TCP, UDP, and ICMP details will appear here."
    );
    pcapDetailsTabs->addTab(
        pcapTransportLog,
        "Transport"
    );

    pcapPayloadLog = new QTextEdit(pcapDetailsTabs);
    pcapPayloadLog->setReadOnly(true);
    pcapPayloadLog->append(
        "[GUI] TCP payload and reconstruction details will appear here."
    );
    pcapDetailsTabs->addTab(
        pcapPayloadLog,
        "Payloads"
    );

    pcapOutputLog = new QTextEdit(pcapDetailsTabs);
    pcapOutputLog->setReadOnly(true);
    pcapOutputLog->append("[GUI] Packet capture analyzer ready.");
    pcapOutputLog->append(
        "[GUI] Select a PCAP or PCAPNG file and choose Summary or Full packet view."
    );
    pcapDetailsTabs->addTab(
        pcapOutputLog,
        "Raw Output"
    );

    mainLayout->addWidget(pcapDetailsTabs);

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

    const auto suggestedPcapExportPath =
        [this](const QString &suffix) {
            const QFileInfo captureInfo(
                pcapTargetPath->text().trimmed()
            );

            QString baseName = captureInfo.completeBaseName();

            if (baseName.isEmpty()) {
                baseName = QStringLiteral("k1wi_pcap");
            }

            const QString modeName =
                pcapModeCombo->currentData().toString() ==
                        QStringLiteral("--full")
                    ? QStringLiteral("full")
                    : QStringLiteral("summary");

            QString directory = QDir::currentPath();

            if (!captureInfo.absolutePath().isEmpty() &&
                captureInfo.absoluteDir().exists()) {
                directory = captureInfo.absolutePath();
            }

            return QDir(directory).absoluteFilePath(
                QStringLiteral("%1_%2_%3.txt")
                    .arg(baseName, modeName, suffix)
            );
        };

    const auto savePcapText =
        [this](
            const QString &textToSave,
            const QString &dialogTitle,
            const QString &suggestedPath
        ) {
            if (textToSave.trimmed().isEmpty()) {
                QMessageBox::warning(
                    this,
                    QStringLiteral("K1Wi PCAP"),
                    QStringLiteral(
                        "There is no report content to save."
                    )
                );

                return;
            }

            const QString destination =
                QFileDialog::getSaveFileName(
                    this,
                    dialogTitle,
                    suggestedPath,
                    QStringLiteral(
                        "Text reports (*.txt);;All files (*)"
                    )
                );

            if (destination.isEmpty()) {
                return;
            }

            QSaveFile outputFile(destination);

            if (!outputFile.open(
                    QIODevice::WriteOnly |
                    QIODevice::Text
                )) {
                QMessageBox::critical(
                    this,
                    QStringLiteral("K1Wi PCAP"),
                    QStringLiteral(
                        "Unable to open the selected report file.\n\n%1"
                    ).arg(outputFile.errorString())
                );

                return;
            }

            QTextStream stream(&outputFile);
            stream << textToSave;

            if (!textToSave.endsWith('\n')) {
                stream << '\n';
            }

            if (stream.status() != QTextStream::Ok ||
                !outputFile.commit()) {
                QMessageBox::critical(
                    this,
                    QStringLiteral("K1Wi PCAP"),
                    QStringLiteral(
                        "The report could not be saved completely.\n\n%1"
                    ).arg(outputFile.errorString())
                );

                return;
            }

            QMessageBox::information(
                this,
                QStringLiteral("K1Wi PCAP"),
                QStringLiteral(
                    "Report saved successfully.\n\n%1"
                ).arg(destination)
            );
        };

    const auto saveStringText =
        [this](
            const QString &textToSave,
            const QString &dialogTitle,
            const QString &suggestedPath
        ) {
            if (textToSave.trimmed().isEmpty()) {
                QMessageBox::warning(
                    this,
                    QStringLiteral("K1Wi STRING"),
                    QStringLiteral(
                        "There is no STRING report content to save."
                    )
                );
                return;
            }

            const QString destination =
                QFileDialog::getSaveFileName(
                    this,
                    dialogTitle,
                    suggestedPath,
                    QStringLiteral(
                        "Text reports (*.txt);;All files (*)"
                    )
                );

            if (destination.isEmpty()) {
                return;
            }

            QSaveFile outputFile(destination);

            if (!outputFile.open(
                    QIODevice::WriteOnly |
                    QIODevice::Text
                )) {
                QMessageBox::critical(
                    this,
                    QStringLiteral("K1Wi STRING"),
                    QStringLiteral(
                        "Unable to open the selected report file.\n\n%1"
                    ).arg(outputFile.errorString())
                );
                return;
            }

            QTextStream stream(&outputFile);
            stream << textToSave;

            if (!textToSave.endsWith(QChar('\n'))) {
                stream << QChar('\n');
            }

            if (
                stream.status() != QTextStream::Ok ||
                !outputFile.commit()
            ) {
                QMessageBox::critical(
                    this,
                    QStringLiteral("K1Wi STRING"),
                    QStringLiteral(
                        "The STRING report could not be saved completely.\n\n%1"
                    ).arg(outputFile.errorString())
                );
                return;
            }

            QMessageBox::information(
                this,
                QStringLiteral("K1Wi STRING"),
                QStringLiteral(
                    "STRING report saved successfully.\n\n%1"
                ).arg(destination)
            );
        };

    const auto suggestedStringExportPath =
        [this](const QString &suffix) {
            const bool fileMode =
                stringInputModeCombo->currentData().toString() ==
                QStringLiteral("file");

            QString baseName;
            QString directory = QDir::currentPath();

            if (fileMode) {
                const QFileInfo sourceInfo(
                    stringFilePath->text().trimmed()
                );

                baseName = sourceInfo.completeBaseName();

                if (
                    !sourceInfo.absolutePath().isEmpty() &&
                    sourceInfo.absoluteDir().exists()
                ) {
                    directory = sourceInfo.absolutePath();
                }
            } else {
                baseName = QStringLiteral("k1wi_string");
            }

            if (baseName.isEmpty()) {
                baseName = QStringLiteral("k1wi_string");
            }

            return QDir(directory).absoluteFilePath(
                QStringLiteral("%1_%2.txt")
                    .arg(baseName, suffix)
            );
        };

    const auto saveEntropyText =
        [this](
            const QString &textToSave,
            const QString &dialogTitle,
            const QString &suggestedPath
        ) {
            if (textToSave.trimmed().isEmpty()) {
                QMessageBox::warning(
                    this,
                    QStringLiteral("K1Wi ENTROPY"),
                    QStringLiteral(
                        "There is no ENTROPY report content to save."
                    )
                );
                return;
            }

            const QString destination =
                QFileDialog::getSaveFileName(
                    this,
                    dialogTitle,
                    suggestedPath,
                    QStringLiteral(
                        "Text reports (*.txt);;All files (*)"
                    )
                );

            if (destination.isEmpty()) {
                return;
            }

            QSaveFile outputFile(destination);

            if (!outputFile.open(
                    QIODevice::WriteOnly |
                    QIODevice::Text
                )) {
                QMessageBox::critical(
                    this,
                    QStringLiteral("K1Wi ENTROPY"),
                    QStringLiteral(
                        "Unable to open the selected report file.\n\n%1"
                    ).arg(outputFile.errorString())
                );
                return;
            }

            QTextStream stream(&outputFile);
            stream << textToSave;

            if (!textToSave.endsWith(QChar('\n'))) {
                stream << QChar('\n');
            }

            if (
                stream.status() != QTextStream::Ok ||
                !outputFile.commit()
            ) {
                QMessageBox::critical(
                    this,
                    QStringLiteral("K1Wi ENTROPY"),
                    QStringLiteral(
                        "The ENTROPY report could not be saved completely.\n\n%1"
                    ).arg(outputFile.errorString())
                );
                return;
            }

            QMessageBox::information(
                this,
                QStringLiteral("K1Wi ENTROPY"),
                QStringLiteral(
                    "ENTROPY report saved successfully.\n\n%1"
                ).arg(destination)
            );
        };

    const auto suggestedEntropyExportPath =
        [this](const QString &suffix) {
            const QFileInfo sourceInfo(
                entropyTargetPath->text().trimmed()
            );

            QString baseName = sourceInfo.completeBaseName();

            if (baseName.isEmpty()) {
                baseName = QStringLiteral("k1wi_entropy");
            }

            QString directory = QDir::currentPath();

            if (
                !sourceInfo.absolutePath().isEmpty() &&
                sourceInfo.absoluteDir().exists()
            ) {
                directory = sourceInfo.absolutePath();
            }

            QString modeName =
                entropyModeCombo->currentText().toLower();

            modeName.replace(QChar(' '), QChar('_'));
            modeName.remove(QChar('-'));

            return QDir(directory).absoluteFilePath(
                QStringLiteral("%1_%2_%3.txt")
                    .arg(baseName, modeName, suffix)
            );
        };

    const auto saveMagicText =
        [this](
            const QString &textToSave,
            const QString &dialogTitle,
            const QString &suggestedPath
        ) {
            if (textToSave.trimmed().isEmpty()) {
                QMessageBox::warning(
                    this,
                    QStringLiteral("K1Wi MAGIC"),
                    QStringLiteral(
                        "There is no MAGIC report content to save."
                    )
                );
                return;
            }

            const QString destination =
                QFileDialog::getSaveFileName(
                    this,
                    dialogTitle,
                    suggestedPath,
                    QStringLiteral(
                        "Text reports (*.txt);;All files (*)"
                    )
                );

            if (destination.isEmpty()) {
                return;
            }

            QSaveFile outputFile(destination);

            if (!outputFile.open(
                    QIODevice::WriteOnly |
                    QIODevice::Text
                )) {
                QMessageBox::critical(
                    this,
                    QStringLiteral("K1Wi MAGIC"),
                    QStringLiteral(
                        "Unable to open the selected report file.\n\n%1"
                    ).arg(outputFile.errorString())
                );
                return;
            }

            QTextStream stream(&outputFile);
            stream << textToSave;

            if (!textToSave.endsWith(QChar('\n'))) {
                stream << QChar('\n');
            }

            if (
                stream.status() != QTextStream::Ok ||
                !outputFile.commit()
            ) {
                QMessageBox::critical(
                    this,
                    QStringLiteral("K1Wi MAGIC"),
                    QStringLiteral(
                        "The MAGIC report could not be saved completely.\n\n%1"
                    ).arg(outputFile.errorString())
                );
                return;
            }

            QMessageBox::information(
                this,
                QStringLiteral("K1Wi MAGIC"),
                QStringLiteral(
                    "MAGIC report saved successfully.\n\n%1"
                ).arg(destination)
            );
        };

    const auto suggestedMagicExportPath =
        [this](const QString &suffix) {
            const QFileInfo sourceInfo(
                magicTargetPath->text().trimmed()
            );

            QString baseName = sourceInfo.completeBaseName();

            if (baseName.isEmpty()) {
                baseName = QStringLiteral("k1wi_magic");
            }

            QString directory = QDir::currentPath();

            if (
                !sourceInfo.absolutePath().isEmpty() &&
                sourceInfo.absoluteDir().exists()
            ) {
                directory = sourceInfo.absolutePath();
            }

            const QString modeName =
                magicModeCombo->currentIndex() == 1
                    ? QStringLiteral("recover")
                    : QStringLiteral("inspect");

            return QDir(directory).absoluteFilePath(
                QStringLiteral("%1_%2_%3.txt")
                    .arg(baseName, modeName, suffix)
            );
        };

    const auto suggestedExtractExportPath =
        [this](const QString &suffix) {
            const QFileInfo sourceInfo(
                extractTargetPath->text().trimmed()
            );

            QString baseName = sourceInfo.completeBaseName();

            if (baseName.isEmpty()) {
                baseName = QStringLiteral("k1wi_extract");
            }

            QString directory = QDir::currentPath();

            if (
                !sourceInfo.absolutePath().isEmpty() &&
                sourceInfo.absoluteDir().exists()
            ) {
                directory = sourceInfo.absolutePath();
            }

            return QDir(directory).absoluteFilePath(
                QStringLiteral("%1_extract_%2.txt")
                    .arg(baseName, suffix)
            );
        };

    const auto saveExtractText =
        [this](
            const QString &textToSave,
            const QString &dialogTitle,
            const QString &suggestedPath
        ) {
            if (textToSave.trimmed().isEmpty()) {
                QMessageBox::warning(
                    this,
                    QStringLiteral("K1Wi EXTRACT"),
                    QStringLiteral(
                        "There is no EXTRACT report content to save."
                    )
                );
                return;
            }

            const QString destination =
                QFileDialog::getSaveFileName(
                    this,
                    dialogTitle,
                    suggestedPath,
                    QStringLiteral(
                        "Text reports (*.txt);;All files (*)"
                    )
                );

            if (destination.isEmpty()) {
                return;
            }

            QSaveFile outputFile(destination);

            if (!outputFile.open(
                    QIODevice::WriteOnly |
                    QIODevice::Text
                )) {
                QMessageBox::critical(
                    this,
                    QStringLiteral("K1Wi EXTRACT"),
                    QStringLiteral(
                        "Unable to open the selected report file.\n\n%1"
                    ).arg(outputFile.errorString())
                );
                return;
            }

            QTextStream stream(&outputFile);
            stream << textToSave;

            if (!textToSave.endsWith(QChar('\n'))) {
                stream << QChar('\n');
            }

            if (
                stream.status() != QTextStream::Ok ||
                !outputFile.commit()
            ) {
                QMessageBox::critical(
                    this,
                    QStringLiteral("K1Wi EXTRACT"),
                    QStringLiteral(
                        "The EXTRACT report could not be saved completely.\n\n%1"
                    ).arg(outputFile.errorString())
                );
                return;
            }

            QMessageBox::information(
                this,
                QStringLiteral("K1Wi EXTRACT"),
                QStringLiteral(
                    "EXTRACT report saved successfully.\n\n%1"
                ).arg(destination)
            );
        };

    const auto suggestedLyzerExportPath =
        [this](const QString &suffix) {
            const QFileInfo sourceInfo(
                lyzerTargetPath->text().trimmed()
            );

            QString baseName = sourceInfo.completeBaseName();

            if (baseName.isEmpty()) {
                baseName = QStringLiteral("k1wi_lyzer");
            }

            QString directory = QDir::currentPath();

            if (
                !sourceInfo.absolutePath().isEmpty() &&
                sourceInfo.absoluteDir().exists()
            ) {
                directory = sourceInfo.absolutePath();
            }

            return QDir(directory).absoluteFilePath(
                QStringLiteral("%1_lyzer_%2.txt")
                    .arg(baseName, suffix)
            );
        };

    const auto saveLyzerText =
        [this](
            const QString &textToSave,
            const QString &dialogTitle,
            const QString &suggestedPath
        ) {
            if (textToSave.trimmed().isEmpty()) {
                QMessageBox::warning(
                    this,
                    QStringLiteral("K1Wi LYZER"),
                    QStringLiteral(
                        "There is no LYZER report content to save."
                    )
                );
                return;
            }

            const QString destination =
                QFileDialog::getSaveFileName(
                    this,
                    dialogTitle,
                    suggestedPath,
                    QStringLiteral(
                        "Text reports (*.txt);;All files (*)"
                    )
                );

            if (destination.isEmpty()) {
                return;
            }

            QSaveFile outputFile(destination);

            if (!outputFile.open(
                    QIODevice::WriteOnly |
                    QIODevice::Text
                )) {
                QMessageBox::critical(
                    this,
                    QStringLiteral("K1Wi LYZER"),
                    QStringLiteral(
                        "Unable to open the selected report file.\n\n%1"
                    ).arg(outputFile.errorString())
                );
                return;
            }

            QTextStream stream(&outputFile);
            stream << textToSave;

            if (!textToSave.endsWith(QChar('\n'))) {
                stream << QChar('\n');
            }

            if (
                stream.status() != QTextStream::Ok ||
                !outputFile.commit()
            ) {
                QMessageBox::critical(
                    this,
                    QStringLiteral("K1Wi LYZER"),
                    QStringLiteral(
                        "The LYZER report could not be saved completely.\n\n%1"
                    ).arg(outputFile.errorString())
                );
                return;
            }

            QMessageBox::information(
                this,
                QStringLiteral("K1Wi LYZER"),
                QStringLiteral(
                    "LYZER report saved successfully.\n\n%1"
                ).arg(destination)
            );
        };

    const auto suggestedHashExportPath =
        [this](const QString &suffix) {
            const QFileInfo sourceInfo(
                hashFilePath->text().trimmed()
            );

            QString baseName = sourceInfo.completeBaseName();

            if (baseName.isEmpty()) {
                baseName = QStringLiteral("k1wi_hash");
            }

            QString directory = QDir::currentPath();

            if (
                !sourceInfo.absolutePath().isEmpty() &&
                sourceInfo.absoluteDir().exists()
            ) {
                directory = sourceInfo.absolutePath();
            }

            const QString algorithmName =
                hashAlgorithmCombo
                    ->currentText()
                    .toLower()
                    .replace(QChar('-'), QChar('_'));

            const QString modeName =
                hashModeCombo->currentData().toString();

            return QDir(directory).absoluteFilePath(
                QStringLiteral("%1_%2_%3_%4.txt")
                    .arg(
                        baseName,
                        algorithmName,
                        modeName,
                        suffix
                    )
            );
        };

    const auto saveHashText =
        [this](
            const QString &textToSave,
            const QString &dialogTitle,
            const QString &suggestedPath
        ) {
            if (textToSave.trimmed().isEmpty()) {
                QMessageBox::warning(
                    this,
                    QStringLiteral("K1Wi HASH"),
                    QStringLiteral(
                        "There is no HASH report content to save."
                    )
                );
                return;
            }

            const QString destination =
                QFileDialog::getSaveFileName(
                    this,
                    dialogTitle,
                    suggestedPath,
                    QStringLiteral(
                        "Text reports (*.txt);;All files (*)"
                    )
                );

            if (destination.isEmpty()) {
                return;
            }

            QSaveFile outputFile(destination);

            if (!outputFile.open(
                    QIODevice::WriteOnly |
                    QIODevice::Text
                )) {
                QMessageBox::critical(
                    this,
                    QStringLiteral("K1Wi HASH"),
                    QStringLiteral(
                        "Unable to open the selected report file.\n\n%1"
                    ).arg(outputFile.errorString())
                );
                return;
            }

            QTextStream stream(&outputFile);
            stream << textToSave;

            if (!textToSave.endsWith(QChar('\n'))) {
                stream << QChar('\n');
            }

            if (
                stream.status() != QTextStream::Ok ||
                !outputFile.commit()
            ) {
                QMessageBox::critical(
                    this,
                    QStringLiteral("K1Wi HASH"),
                    QStringLiteral(
                        "The HASH report could not be saved completely.\n\n%1"
                    ).arg(outputFile.errorString())
                );
                return;
            }

            QMessageBox::information(
                this,
                QStringLiteral("K1Wi HASH"),
                QStringLiteral(
                    "HASH report saved successfully.\n\n%1"
                ).arg(destination)
            );
        };

    connect(
        copyViewAction,
        &QAction::triggered,
        this,
        [this]() {
            const QWidget *selectedModule =
                tabs->currentWidget();

            QTabWidget *detailsTabs = nullptr;
            QString moduleName;

            if (selectedModule == extractTab) {
                detailsTabs = extractDetailsTabs;
                moduleName = QStringLiteral("EXTRACT");
            } else if (selectedModule == lyzerTab) {
                detailsTabs = lyzerDetailsTabs;
                moduleName = QStringLiteral("LYZER");
            } else if (selectedModule == hashTab) {
                detailsTabs = hashDetailsTabs;
                moduleName = QStringLiteral("HASH");
            } else if (selectedModule == stringTab) {
                detailsTabs = stringDetailsTabs;
                moduleName = QStringLiteral("STRING");
            } else if (selectedModule == magicTab) {
                detailsTabs = magicDetailsTabs;
                moduleName = QStringLiteral("MAGIC");
            } else if (selectedModule == entropyTab) {
                detailsTabs = entropyDetailsTabs;
                moduleName = QStringLiteral("ENTROPY");
            } else if (selectedModule == pcapTab) {
                detailsTabs = pcapDetailsTabs;
                moduleName = QStringLiteral("PCAP");
            }

            if (detailsTabs == nullptr) {
                return;
            }

            QTextEdit *currentLog =
                qobject_cast<QTextEdit *>(
                    detailsTabs->currentWidget()
                );

            if (
                currentLog == nullptr ||
                currentLog->toPlainText().trimmed().isEmpty()
            ) {
                QMessageBox::warning(
                    this,
                    QStringLiteral("K1Wi %1").arg(moduleName),
                    QStringLiteral(
                        "The current %1 view has no content to copy."
                    ).arg(moduleName)
                );
                return;
            }

            QApplication::clipboard()->setText(
                currentLog->toPlainText()
            );

            QMessageBox::information(
                this,
                QStringLiteral("K1Wi %1").arg(moduleName),
                QStringLiteral(
                    "The current %1 view was copied to the clipboard."
                ).arg(moduleName)
            );
        }
    );

    connect(
        saveViewAction,
        &QAction::triggered,
        this,
        [
            this,
            savePcapText,
            suggestedPcapExportPath,
            saveStringText,
            suggestedStringExportPath,
            saveMagicText,
            suggestedMagicExportPath,
            saveEntropyText,
            suggestedEntropyExportPath,
            saveHashText,
            suggestedHashExportPath,
            saveExtractText,
            suggestedExtractExportPath,
            saveLyzerText,
            suggestedLyzerExportPath
        ]() {
            const QWidget *selectedModule =
                tabs->currentWidget();

            QTabWidget *detailsTabs = nullptr;
            QString moduleName;

            if (selectedModule == extractTab) {
                detailsTabs = extractDetailsTabs;
                moduleName = QStringLiteral("EXTRACT");
            } else if (selectedModule == lyzerTab) {
                detailsTabs = lyzerDetailsTabs;
                moduleName = QStringLiteral("LYZER");
            } else if (selectedModule == hashTab) {
                detailsTabs = hashDetailsTabs;
                moduleName = QStringLiteral("HASH");
            } else if (selectedModule == stringTab) {
                detailsTabs = stringDetailsTabs;
                moduleName = QStringLiteral("STRING");
            } else if (selectedModule == magicTab) {
                detailsTabs = magicDetailsTabs;
                moduleName = QStringLiteral("MAGIC");
            } else if (selectedModule == entropyTab) {
                detailsTabs = entropyDetailsTabs;
                moduleName = QStringLiteral("ENTROPY");
            } else if (selectedModule == pcapTab) {
                detailsTabs = pcapDetailsTabs;
                moduleName = QStringLiteral("PCAP");
            }

            if (detailsTabs == nullptr) {
                return;
            }

            QTextEdit *currentLog =
                qobject_cast<QTextEdit *>(
                    detailsTabs->currentWidget()
                );

            if (currentLog == nullptr) {
                QMessageBox::warning(
                    this,
                    QStringLiteral("K1Wi %1").arg(moduleName),
                    QStringLiteral(
                        "The current results tab cannot be exported."
                    )
                );
                return;
            }

            QString tabName =
                detailsTabs
                    ->tabText(detailsTabs->currentIndex())
                    .toLower();

            tabName.replace(QChar(' '), QChar('_'));

            if (selectedModule == extractTab) {
                saveExtractText(
                    currentLog->toPlainText(),
                    QStringLiteral("Save Current EXTRACT View"),
                    suggestedExtractExportPath(tabName)
                );
            } else if (selectedModule == lyzerTab) {
                saveLyzerText(
                    currentLog->toPlainText(),
                    QStringLiteral("Save Current LYZER View"),
                    suggestedLyzerExportPath(tabName)
                );
            } else if (selectedModule == hashTab) {
                saveHashText(
                    currentLog->toPlainText(),
                    QStringLiteral("Save Current HASH View"),
                    suggestedHashExportPath(tabName)
                );
            } else if (selectedModule == stringTab) {
                saveStringText(
                    currentLog->toPlainText(),
                    QStringLiteral("Save Current STRING View"),
                    suggestedStringExportPath(tabName)
                );
            } else if (selectedModule == magicTab) {
                saveMagicText(
                    currentLog->toPlainText(),
                    QStringLiteral("Save Current MAGIC View"),
                    suggestedMagicExportPath(tabName)
                );
            } else if (selectedModule == entropyTab) {
                saveEntropyText(
                    currentLog->toPlainText(),
                    QStringLiteral("Save Current ENTROPY View"),
                    suggestedEntropyExportPath(tabName)
                );
            } else {
                savePcapText(
                    currentLog->toPlainText(),
                    QStringLiteral("Save Current PCAP View"),
                    suggestedPcapExportPath(tabName)
                );
            }
        }
    );

    connect(
        saveRawAction,
        &QAction::triggered,
        this,
        [
            this,
            savePcapText,
            suggestedPcapExportPath,
            saveStringText,
            suggestedStringExportPath,
            saveMagicText,
            suggestedMagicExportPath,
            saveEntropyText,
            suggestedEntropyExportPath,
            saveHashText,
            suggestedHashExportPath,
            saveExtractText,
            suggestedExtractExportPath,
            saveLyzerText,
            suggestedLyzerExportPath
        ]() {
            const QWidget *selectedModule =
                tabs->currentWidget();

            if (selectedModule == extractTab) {
                saveExtractText(
                    extractOutputLog->toPlainText(),
                    QStringLiteral("Save Complete EXTRACT Raw Report"),
                    suggestedExtractExportPath(
                        QStringLiteral("raw_report")
                    )
                );
            } else if (selectedModule == lyzerTab) {
                saveLyzerText(
                    lyzerOutputLog->toPlainText(),
                    QStringLiteral("Save Complete LYZER Raw Report"),
                    suggestedLyzerExportPath(
                        QStringLiteral("raw_report")
                    )
                );
            } else if (selectedModule == hashTab) {
                saveHashText(
                    hashOutputLog->toPlainText(),
                    QStringLiteral("Save Complete HASH Raw Report"),
                    suggestedHashExportPath(
                        QStringLiteral("raw_report")
                    )
                );
            } else if (selectedModule == stringTab) {
                saveStringText(
                    stringOutputLog->toPlainText(),
                    QStringLiteral("Save Complete STRING Raw Report"),
                    suggestedStringExportPath(
                        QStringLiteral("raw_report")
                    )
                );
            } else if (selectedModule == magicTab) {
                saveMagicText(
                    magicOutputLog->toPlainText(),
                    QStringLiteral("Save Complete MAGIC Raw Report"),
                    suggestedMagicExportPath(
                        QStringLiteral("raw_report")
                    )
                );
            } else if (selectedModule == entropyTab) {
                saveEntropyText(
                    entropyOutputLog->toPlainText(),
                    QStringLiteral("Save Complete ENTROPY Raw Report"),
                    suggestedEntropyExportPath(
                        QStringLiteral("raw_report")
                    )
                );
            } else if (selectedModule == pcapTab) {
                savePcapText(
                    pcapOutputLog->toPlainText(),
                    QStringLiteral("Save Complete PCAP Raw Report"),
                    suggestedPcapExportPath(
                        QStringLiteral("raw_report")
                    )
                );
            }
        }
    );

    const auto updateReportToolActions =
        [this, copyViewAction, saveViewAction, saveRawAction](
            int index
        ) {
            const QWidget *selectedTab = tabs->widget(index);

            const bool reportTabSelected =
                selectedTab == pcapTab ||
                selectedTab == extractTab ||
                selectedTab == lyzerTab ||
                selectedTab == hashTab ||
                selectedTab == stringTab ||
                selectedTab == magicTab ||
                selectedTab == entropyTab;

            copyViewAction->setEnabled(reportTabSelected);
            saveViewAction->setEnabled(reportTabSelected);
            saveRawAction->setEnabled(reportTabSelected);

            copyViewAction->setToolTip(
                reportTabSelected
                    ? QStringLiteral(
                        "Copy the currently selected results view"
                    )
                    : QStringLiteral(
                        "Available in EXTRACT, LYZER, HASH, STRING, MAGIC, ENTROPY, and PCAP"
                    )
            );

            saveViewAction->setToolTip(
                reportTabSelected
                    ? QStringLiteral(
                        "Save the currently selected results view"
                    )
                    : QStringLiteral(
                        "Available in EXTRACT, LYZER, HASH, STRING, MAGIC, ENTROPY, and PCAP"
                    )
            );

            saveRawAction->setToolTip(
                reportTabSelected
                    ? QStringLiteral(
                        "Save the complete raw analysis report"
                    )
                    : QStringLiteral(
                        "Available in EXTRACT, LYZER, HASH, STRING, MAGIC, ENTROPY, and PCAP"
                    )
            );
        };

    connect(
        tabs,
        &QTabWidget::currentChanged,
        this,
        updateReportToolActions
    );

    connect(runButton, &QPushButton::clicked, this, &MainWindow::runPcapCommand);
    connect(clearButton, &QPushButton::clicked, this, [this]() {
        pcapDetailsTabs->setCurrentIndex(0);

        pcapFindingsLog->clear();
        pcapNetworkLog->clear();
        pcapTransportLog->clear();
        pcapPayloadLog->clear();
        pcapOutputLog->clear();

        pcapFindingsLog->append(
            QStringLiteral(
                "[GUI] Findings will appear here after analysis."
            )
        );

        pcapNetworkLog->append(
            QStringLiteral(
                "[GUI] IP, MAC, VLAN, ARP, and IPv6 details "
                "will appear here."
            )
        );

        pcapTransportLog->append(
            QStringLiteral(
                "[GUI] TCP, UDP, and ICMP details will appear here."
            )
        );

        pcapPayloadLog->append(
            QStringLiteral(
                "[GUI] TCP payload and reconstruction details "
                "will appear here."
            )
        );

        pcapOutputLog->append(
            QStringLiteral(
                "[GUI] Packet capture analyzer ready."
            )
        );

        pcapOutputLog->append(
            QStringLiteral(
                "[GUI] Select a PCAP or PCAPNG file and choose "
                "Summary or Full packet view."
            )
        );
    });
}

void MainWindow::buildLyzerTab()
{
    lyzerTab = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(lyzerTab);

    QLabel *title = new QLabel("K1Wi Framework - LYZER", lyzerTab);
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

    lyzerDetailsTabs = new QTabWidget(lyzerTab);

    lyzerFindingsLog = new QTextEdit(lyzerDetailsTabs);
    lyzerFindingsLog->setReadOnly(true);
    lyzerFindingsLog->append(
        QStringLiteral("[GUI] LYZER findings will appear here.")
    );

    lyzerOutputLog = new QTextEdit(lyzerDetailsTabs);
    lyzerOutputLog->setReadOnly(true);
    lyzerOutputLog->append(
        QStringLiteral("[GUI] LYZER panel ready.")
    );

    lyzerDetailsTabs->addTab(
        lyzerFindingsLog,
        QStringLiteral("Findings")
    );
    lyzerDetailsTabs->addTab(
        lyzerOutputLog,
        QStringLiteral("Raw Output")
    );

    mainLayout->addWidget(lyzerDetailsTabs);

    connect(targetBrowse, &QPushButton::clicked, this, [this]() {
        QString path = QFileDialog::getOpenFileName(this, "Select LYZER Target");
        if (!path.isEmpty()) {
            lyzerTargetPath->setText(path);
        }
    });

    connect(
        runButton,
        &QPushButton::clicked,
        this,
        &MainWindow::runLyzerCommand
    );

    connect(clearButton, &QPushButton::clicked, this, [this]() {
        lyzerFindingsLog->clear();
        lyzerOutputLog->clear();
    });

}

void MainWindow::buildExtractTab()
{
    extractTab = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(extractTab);

    QLabel *title = new QLabel("K1Wi Framework - EXTRACT", extractTab);
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

    extractDetailsTabs = new QTabWidget(extractTab);

    extractFindingsLog = new QTextEdit(extractDetailsTabs);
    extractFindingsLog->setReadOnly(true);
    extractFindingsLog->append(
        QStringLiteral("[GUI] EXTRACT findings will appear here.")
    );

    extractOutputLog = new QTextEdit(extractDetailsTabs);
    extractOutputLog->setReadOnly(true);
    extractOutputLog->append(
        QStringLiteral("[GUI] EXTRACT panel ready.")
    );

    extractDetailsTabs->addTab(
        extractFindingsLog,
        QStringLiteral("Findings")
    );

    extractDetailsTabs->addTab(
        extractOutputLog,
        QStringLiteral("Raw Output")
    );

    mainLayout->addWidget(extractDetailsTabs);

    connect(targetBrowse, &QPushButton::clicked, this, [this]() {
        QString path = QFileDialog::getOpenFileName(this, "Select EXTRACT Target");
        if (!path.isEmpty()) {
            extractTargetPath->setText(path);
        }
    });

    connect(runButton, &QPushButton::clicked, this, &MainWindow::runExtractCommand);

    connect(clearButton, &QPushButton::clicked, this, [this]() {
        extractDetailsTabs->setCurrentIndex(0);
        extractFindingsLog->clear();
        extractOutputLog->clear();

        extractFindingsLog->append(
            QStringLiteral("[GUI] EXTRACT findings will appear here.")
        );

        extractOutputLog->append(
            QStringLiteral("[GUI] EXTRACT panel ready.")
        );
    });
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

    QLabel *title = new QLabel(
        QStringLiteral("K1Wi Framework - HASH"),
        hashTab
    );
    mainLayout->addWidget(title);

    QLabel *description = new QLabel(
        QStringLiteral(
            "Compute, verify, or compare MD5 and SHA-256 file hashes. "
            "Structured results appear under Findings while complete CLI "
            "output remains available under Raw Output."
        ),
        hashTab
    );
    description->setWordWrap(true);
    mainLayout->addWidget(description);

    QHBoxLayout *algorithmLayout = new QHBoxLayout();

    hashAlgorithmCombo = new QComboBox(hashTab);
    hashAlgorithmCombo->addItem(
        QStringLiteral("MD5"),
        QStringLiteral("MD5")
    );
    hashAlgorithmCombo->addItem(
        QStringLiteral("SHA-256"),
        QStringLiteral("SHA256")
    );

    algorithmLayout->addWidget(
        new QLabel(QStringLiteral("Algorithm:"), hashTab)
    );
    algorithmLayout->addWidget(hashAlgorithmCombo);

    mainLayout->addLayout(algorithmLayout);

    QHBoxLayout *modeLayout = new QHBoxLayout();

    hashModeCombo = new QComboBox(hashTab);
    hashModeCombo->addItem(
        QStringLiteral("Compute hash"),
        QStringLiteral("compute")
    );
    hashModeCombo->addItem(
        QStringLiteral("Verify hash"),
        QStringLiteral("verify")
    );
    hashModeCombo->addItem(
        QStringLiteral("Compare files"),
        QStringLiteral("compare")
    );

    modeLayout->addWidget(
        new QLabel(QStringLiteral("Mode:"), hashTab)
    );
    modeLayout->addWidget(hashModeCombo);

    mainLayout->addLayout(modeLayout);

    QHBoxLayout *fileLayout = new QHBoxLayout();

    hashFilePath = new QLineEdit(hashTab);

    QPushButton *fileBrowse = new QPushButton(
        QStringLiteral("Browse File"),
        hashTab
    );

    fileLayout->addWidget(
        new QLabel(QStringLiteral("File:"), hashTab)
    );
    fileLayout->addWidget(hashFilePath);
    fileLayout->addWidget(fileBrowse);

    mainLayout->addLayout(fileLayout);

    QHBoxLayout *expectedLayout = new QHBoxLayout();

    hashExpectedValue = new QLineEdit(hashTab);
    hashExpectedValue->setPlaceholderText(
        QStringLiteral("Expected hash for verify mode")
    );

    expectedLayout->addWidget(
        new QLabel(QStringLiteral("Expected hash:"), hashTab)
    );
    expectedLayout->addWidget(hashExpectedValue);

    mainLayout->addLayout(expectedLayout);

    QHBoxLayout *compareLayout = new QHBoxLayout();

    hashCompareFilePath = new QLineEdit(hashTab);

    QPushButton *compareBrowse = new QPushButton(
        QStringLiteral("Browse Compare File"),
        hashTab
    );

    compareLayout->addWidget(
        new QLabel(QStringLiteral("Compare file:"), hashTab)
    );
    compareLayout->addWidget(hashCompareFilePath);
    compareLayout->addWidget(compareBrowse);

    mainLayout->addLayout(compareLayout);

    QPushButton *runButton = new QPushButton(
        QStringLiteral("Run HASH"),
        hashTab
    );

    QPushButton *clearButton = new QPushButton(
        QStringLiteral("Clear Results"),
        hashTab
    );

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(runButton);
    buttonLayout->addWidget(clearButton);

    mainLayout->addLayout(buttonLayout);

    hashDetailsTabs = new QTabWidget(hashTab);

    hashFindingsLog = new QTextEdit(hashDetailsTabs);
    hashFindingsLog->setReadOnly(true);
    hashFindingsLog->append(
        QStringLiteral("[GUI] HASH findings will appear here.")
    );

    hashOutputLog = new QTextEdit(hashDetailsTabs);
    hashOutputLog->setReadOnly(true);
    hashOutputLog->append(
        QStringLiteral("[GUI] HASH panel ready.")
    );
    hashOutputLog->append(
        QStringLiteral(
            "[GUI] Select MD5 or SHA-256, then choose "
            "Compute, Verify, or Compare."
        )
    );

    hashDetailsTabs->addTab(
        hashFindingsLog,
        QStringLiteral("Findings")
    );
    hashDetailsTabs->addTab(
        hashOutputLog,
        QStringLiteral("Raw Output")
    );

    mainLayout->addWidget(hashDetailsTabs);

    auto updateHashModeFields = [this, compareBrowse]() {
        const QString mode =
            hashModeCombo->currentData().toString();

        const bool verifyMode =
            mode == QStringLiteral("verify");

        const bool compareMode =
            mode == QStringLiteral("compare");

        hashExpectedValue->setEnabled(verifyMode);
        hashCompareFilePath->setEnabled(compareMode);
        compareBrowse->setEnabled(compareMode);

        if (!verifyMode) {
            hashExpectedValue->clear();
        }

        if (!compareMode) {
            hashCompareFilePath->clear();
        }
    };

    connect(
        hashModeCombo,
        &QComboBox::currentIndexChanged,
        this,
        updateHashModeFields
    );

    connect(
        fileBrowse,
        &QPushButton::clicked,
        this,
        [this]() {
            const QString path = QFileDialog::getOpenFileName(
                this,
                QStringLiteral("Select HASH File")
            );

            if (!path.isEmpty()) {
                hashFilePath->setText(path);
            }
        }
    );

    connect(
        compareBrowse,
        &QPushButton::clicked,
        this,
        [this]() {
            const QString path = QFileDialog::getOpenFileName(
                this,
                QStringLiteral("Select Compare File")
            );

            if (!path.isEmpty()) {
                hashCompareFilePath->setText(path);
            }
        }
    );

    connect(
        runButton,
        &QPushButton::clicked,
        this,
        &MainWindow::runHashCommand
    );

    connect(
        clearButton,
        &QPushButton::clicked,
        this,
        [this]() {
            hashFindingsLog->clear();
            hashOutputLog->clear();
            hashDetailsTabs->setCurrentIndex(0);
        }
    );

    updateHashModeFields();
}

void MainWindow::runHashCommand()
{
    hashDetailsTabs->setCurrentIndex(1);
    hashFindingsLog->clear();
    hashOutputLog->clear();

    hashFindingsLog->append(
        QStringLiteral("[GUI] HASH analysis in progress...")
    );

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
        [
            this,
            process,
            combinedOutput,
            algorithmLabel,
            mode,
            modeLabel,
            filePath,
            expectedHash,
            compareFilePath
        ](int exitCode, QProcess::ExitStatus exitStatus) {
            hashOutputLog->append("");

            if (exitStatus == QProcess::NormalExit) {
                const QString normalizedOutput =
                    stripAnsiCodes(*combinedOutput).replace(
                        QStringLiteral("\r\n"),
                        QStringLiteral("\n")
                    );

                hashFindingsLog->clear();

                appendStyledLine(
                    hashFindingsLog,
                    QStringLiteral("HASH Analysis Findings"),
                    QStringLiteral("#0057b8"),
                    true
                );

                hashFindingsLog->append(
                    QStringLiteral("Algorithm: %1").arg(algorithmLabel)
                );
                hashFindingsLog->append(
                    QStringLiteral("Mode: %1").arg(modeLabel)
                );
                hashFindingsLog->append(
                    QStringLiteral("Primary file: %1").arg(filePath)
                );

                const QFileInfo primaryInfo(filePath);

                if (primaryInfo.exists()) {
                    hashFindingsLog->append(
                        QStringLiteral("Primary file size: %1 bytes")
                            .arg(primaryInfo.size())
                    );
                }

                QString resultText;
                QString resultColor = QStringLiteral("#0057b8");

                if (mode == QStringLiteral("compute")) {
                    const QRegularExpression digestPattern(
                        QStringLiteral(
                            R"((?:MD5|SHA256)\(.*\)\s*=\s*([0-9A-Fa-f]+))"
                        )
                    );

                    const QRegularExpressionMatch digestMatch =
                        digestPattern.match(normalizedOutput);

                    hashFindingsLog->append(QString());

                    appendStyledLine(
                        hashFindingsLog,
                        QStringLiteral("Computed digest"),
                        QStringLiteral("#0057b8"),
                        true
                    );

                    if (digestMatch.hasMatch()) {
                        hashFindingsLog->append(digestMatch.captured(1));
                        resultText =
                            QStringLiteral("Hash computed successfully.");
                        resultColor = QStringLiteral("#0b7a0b");
                    } else {
                        hashFindingsLog->append(
                            QStringLiteral("No digest detected.")
                        );
                        resultText =
                            QStringLiteral("Hash computation failed.");
                        resultColor = QStringLiteral("#b00020");
                    }
                } else if (mode == QStringLiteral("verify")) {
                    hashFindingsLog->append(QString());
                    hashFindingsLog->append(
                        QStringLiteral("Expected digest: %1")
                            .arg(expectedHash)
                    );

                    if (
                        normalizedOutput.contains(
                            QStringLiteral("MD5 OK")
                        ) ||
                        normalizedOutput.contains(
                            QStringLiteral("SHA256 OK")
                        )
                    ) {
                        resultText =
                            QStringLiteral("MATCH — verification passed.");
                        resultColor = QStringLiteral("#0b7a0b");
                    } else {
                        resultText =
                            QStringLiteral("MISMATCH — verification failed.");
                        resultColor = QStringLiteral("#b00020");
                    }
                } else if (mode == QStringLiteral("compare")) {
                    hashFindingsLog->append(QString());
                    hashFindingsLog->append(
                        QStringLiteral("Second file: %1")
                            .arg(compareFilePath)
                    );

                    const QFileInfo compareInfo(compareFilePath);

                    if (compareInfo.exists()) {
                        hashFindingsLog->append(
                            QStringLiteral("Second file size: %1 bytes")
                                .arg(compareInfo.size())
                        );
                    }

                    if (
                        normalizedOutput.contains(
                            QStringLiteral("MD5 MATCH")
                        ) ||
                        normalizedOutput.contains(
                            QStringLiteral("SHA256 MATCH")
                        )
                    ) {
                        resultText =
                            QStringLiteral(
                                "MATCH — files have identical hashes."
                            );
                        resultColor = QStringLiteral("#0b7a0b");
                    } else {
                        resultText =
                            QStringLiteral(
                                "DIFFER — files have different hashes."
                            );
                        resultColor = QStringLiteral("#b00020");
                    }
                }

                hashFindingsLog->append(QString());

                appendStyledLine(
                    hashFindingsLog,
                    QStringLiteral("Result"),
                    QStringLiteral("#0057b8"),
                    true
                );

                appendStyledLine(
                    hashFindingsLog,
                    resultText,
                    resultColor,
                    true
                );

                hashFindingsLog->append(
                    QStringLiteral("Exit code: %1").arg(exitCode)
                );

                hashDetailsTabs->setCurrentIndex(0);

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
    stringDetailsTabs->setCurrentIndex(0);
    stringFindingsLog->clear();
    stringOutputLog->clear();

    stringFindingsLog->append(
        QStringLiteral("[GUI] STRING analysis in progress...")
    );

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
                stringFindingsLog->clear();

                const QString normalizedOutput =
                    stripAnsiCodes(*combinedOutput).replace(
                        QStringLiteral("\r\n"),
                        QStringLiteral("\n")
                    );

                const QStringList lines =
                    normalizedOutput.split(
                        QChar('\n'),
                        Qt::KeepEmptyParts
                    );

                struct StringFinding {
                    QString offset;
                    QString raw;
                    QString type;
                    QString decoded;
                };

                QList<StringFinding> findings;
                QMap<QString, int> typeCounts;

                StringFinding current;
                bool collectingDecodedOutput = false;

                auto finishCurrentFinding = [&]() {
                    if (
                        current.raw.isEmpty() &&
                        current.type.isEmpty() &&
                        current.decoded.isEmpty()
                    ) {
                        return;
                    }

                    findings.append(current);

                    if (!current.type.isEmpty()) {
                        typeCounts[current.type] += 1;
                    }

                    current = StringFinding();
                    collectingDecodedOutput = false;
                };

                const QRegularExpression offsetPattern(
                    QStringLiteral(
                        R"(^\[STRING\]\s+offset\s+(0x[0-9A-Fa-f]+))"
                    )
                );

                for (const QString &line : lines) {
                    const QString trimmed = line.trimmed();

                    const QRegularExpressionMatch offsetMatch =
                        offsetPattern.match(trimmed);

                    if (offsetMatch.hasMatch()) {
                        finishCurrentFinding();
                        current.offset = offsetMatch.captured(1);
                        continue;
                    }

                    if (trimmed.startsWith(QStringLiteral("Input:"))) {
                        finishCurrentFinding();

                        current.raw =
                            trimmed.mid(QStringLiteral("Input:").size()).trimmed();

                        if (
                            current.raw.size() >= 2 &&
                            current.raw.startsWith(QChar('"')) &&
                            current.raw.endsWith(QChar('"'))
                        ) {
                            current.raw =
                                current.raw.mid(1, current.raw.size() - 2);
                        }

                        continue;
                    }

                    if (trimmed.startsWith(QStringLiteral("Raw:"))) {
                        current.raw =
                            trimmed.mid(QStringLiteral("Raw:").size()).trimmed();
                        continue;
                    }

                    if (
                        trimmed.startsWith(
                            QStringLiteral("Detected Type:")
                        )
                    ) {
                        current.type =
                            trimmed.mid(
                                QStringLiteral("Detected Type:").size()
                            ).trimmed();
                        continue;
                    }

                    if (trimmed == QStringLiteral("Decoded Output:")) {
                        collectingDecodedOutput = true;
                        continue;
                    }

                    if (collectingDecodedOutput) {
                        if (trimmed.isEmpty()) {
                            if (!current.decoded.isEmpty()) {
                                collectingDecodedOutput = false;
                            }
                            continue;
                        }

                        if (!current.decoded.isEmpty()) {
                            current.decoded += QChar('\n');
                        }

                        current.decoded += line;
                    }
                }

                finishCurrentFinding();

                const auto stringFindingRisk =
                    [](const QString &findingType) {
                        if (
                            findingType.contains(
                                QStringLiteral("private key"),
                                Qt::CaseInsensitive
                            ) ||
                            findingType.contains(
                                QStringLiteral("AWS access key"),
                                Qt::CaseInsensitive
                            ) ||
                            findingType.contains(
                                QStringLiteral("GitHub token"),
                                Qt::CaseInsensitive
                            ) ||
                            findingType.contains(
                                QStringLiteral("OpenAI API key"),
                                Qt::CaseInsensitive
                            ) ||
                            findingType.contains(
                                QStringLiteral("Bearer token"),
                                Qt::CaseInsensitive
                            ) ||
                            findingType.contains(
                                QStringLiteral("JWT token"),
                                Qt::CaseInsensitive
                            )
                        ) {
                            return 2;
                        }

                        if (
                            findingType.contains(
                                QStringLiteral("credential"),
                                Qt::CaseInsensitive
                            ) ||
                            findingType.contains(
                                QStringLiteral("secret"),
                                Qt::CaseInsensitive
                            ) ||
                            findingType.contains(
                                QStringLiteral("SSH public key"),
                                Qt::CaseInsensitive
                            ) ||
                            findingType.contains(
                                QStringLiteral("PEM certificate"),
                                Qt::CaseInsensitive
                            )
                        ) {
                            return 1;
                        }

                        return 0;
                    };

                const auto stringRiskColor =
                    [&stringFindingRisk](const QString &findingType) {
                        const int risk = stringFindingRisk(findingType);

                        if (risk == 2) {
                            return QStringLiteral("#b00020");
                        }

                        if (risk == 1) {
                            return QStringLiteral("#b26a00");
                        }

                        return QStringLiteral("#0057b8");
                    };

                int highRiskCount = 0;
                int warningCount = 0;
                int informationalCount = 0;

                for (const StringFinding &finding : findings) {
                    const int risk = stringFindingRisk(finding.type);

                    if (risk == 2) {
                        highRiskCount++;
                    } else if (risk == 1) {
                        warningCount++;
                    } else {
                        informationalCount++;
                    }
                }

                appendStyledLine(
                    stringFindingsLog,
                    QStringLiteral("[STRING] Analysis findings"),
                    QStringLiteral("#0057b8"),
                    true
                );

                stringFindingsLog->append(
                    QStringLiteral("Detected strings: %1")
                        .arg(findings.size())
                );

                stringFindingsLog->append(QString());

                appendStyledLine(
                    stringFindingsLog,
                    QStringLiteral("Risk summary"),
                    QStringLiteral("#0057b8"),
                    true
                );

                appendStyledLine(
                    stringFindingsLog,
                    QStringLiteral("  High-risk findings: %1")
                        .arg(highRiskCount),
                    highRiskCount > 0
                        ? QStringLiteral("#b00020")
                        : QStringLiteral("#2e7d32"),
                    highRiskCount > 0
                );

                appendStyledLine(
                    stringFindingsLog,
                    QStringLiteral("  Warning findings: %1")
                        .arg(warningCount),
                    warningCount > 0
                        ? QStringLiteral("#b26a00")
                        : QStringLiteral("#2e7d32"),
                    warningCount > 0
                );

                appendStyledLine(
                    stringFindingsLog,
                    QStringLiteral("  Informational findings: %1")
                        .arg(informationalCount),
                    QStringLiteral("#0057b8"),
                    false
                );

                if (!typeCounts.isEmpty()) {
                    stringFindingsLog->append(QString());
                    appendStyledLine(
                        stringFindingsLog,
                        QStringLiteral("Detection summary"),
                        QStringLiteral("#0057b8"),
                        true
                    );

                    for (
                        auto iterator = typeCounts.cbegin();
                        iterator != typeCounts.cend();
                        ++iterator
                    ) {
                        appendStyledLine(
                            stringFindingsLog,
                            QStringLiteral("  %1: %2")
                                .arg(iterator.key())
                                .arg(iterator.value()),
                            stringRiskColor(iterator.key()),
                            stringFindingRisk(iterator.key()) > 0
                        );
                    }
                }

                if (!findings.isEmpty()) {
                    stringFindingsLog->append(QString());

                    for (int index = 0; index < findings.size(); ++index) {
                        const StringFinding &finding = findings.at(index);

                        const QString findingType =
                            finding.type.isEmpty()
                                ? QStringLiteral("Unknown")
                                : finding.type;

                        QString findingColor =
                            QStringLiteral("#0057b8");

                        if (
                            findingType.contains(
                                QStringLiteral("private key"),
                                Qt::CaseInsensitive
                            ) ||
                            findingType.contains(
                                QStringLiteral("AWS access key"),
                                Qt::CaseInsensitive
                            ) ||
                            findingType.contains(
                                QStringLiteral("GitHub token"),
                                Qt::CaseInsensitive
                            ) ||
                            findingType.contains(
                                QStringLiteral("OpenAI API key"),
                                Qt::CaseInsensitive
                            ) ||
                            findingType.contains(
                                QStringLiteral("Bearer token"),
                                Qt::CaseInsensitive
                            ) ||
                            findingType.contains(
                                QStringLiteral("JWT token"),
                                Qt::CaseInsensitive
                            )
                        ) {
                            findingColor = QStringLiteral("#b00020");
                        } else if (
                            findingType.contains(
                                QStringLiteral("credential"),
                                Qt::CaseInsensitive
                            ) ||
                            findingType.contains(
                                QStringLiteral("secret"),
                                Qt::CaseInsensitive
                            ) ||
                            findingType.contains(
                                QStringLiteral("SSH public key"),
                                Qt::CaseInsensitive
                            ) ||
                            findingType.contains(
                                QStringLiteral("PEM certificate"),
                                Qt::CaseInsensitive
                            )
                        ) {
                            findingColor = QStringLiteral("#b26a00");
                        }

                        appendStyledLine(
                            stringFindingsLog,
                            QStringLiteral("[FINDING %1] %2")
                                .arg(index + 1)
                                .arg(findingType),
                            findingColor,
                            true
                        );

                        if (!finding.offset.isEmpty()) {
                            stringFindingsLog->append(
                                QStringLiteral("  Offset: %1")
                                    .arg(finding.offset)
                            );
                        }

                        if (!finding.raw.isEmpty()) {
                            stringFindingsLog->append(
                                QStringLiteral("  Raw: %1")
                                    .arg(finding.raw)
                            );
                        }

                        if (!finding.decoded.isEmpty()) {
                            appendStyledLine(
                                stringFindingsLog,
                                QStringLiteral("  Decoded output:"),
                                QStringLiteral("#2e7d32"),
                                true
                            );

                            QString decodedDisplay = finding.decoded;
                            decodedDisplay.replace(
                                QChar('\n'),
                                QStringLiteral("\n  ")
                            );

                            stringFindingsLog->append(
                                QStringLiteral("  %1").arg(decodedDisplay)
                            );
                        }

                        if (index + 1 < findings.size()) {
                            stringFindingsLog->append(QString());
                        }
                    }
                } else {
                    stringFindingsLog->append(QString());
                    stringFindingsLog->append(
                        QStringLiteral(
                            "[STRING] No structured detections were found."
                        )
                    );
                }

                stringDetailsTabs->setCurrentIndex(0);

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
    magicDetailsTabs->setCurrentIndex(1);
    magicFindingsLog->clear();
    magicOutputLog->clear();

    magicFindingsLog->append(
        QStringLiteral("[GUI] MAGIC analysis in progress...")
    );

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

    const bool recoveryEnabled =
        magicModeCombo->currentIndex() == 1;
    const QString recoveryPath =
        magicRecoveryPath->text().trimmed();

    if (recoveryEnabled && recoveryPath.isEmpty()) {
        QMessageBox::warning(
            this,
            QStringLiteral("K1Wi MAGIC"),
            QStringLiteral(
                "Select a recovery output path before running recovery mode."
            )
        );

        magicOutputLog->append(
            QStringLiteral(
                "[GUI] MAGIC cancelled: no recovery output path selected."
            )
        );
        return;
    }

    if (recoveryEnabled) {
        const QFileInfo recoveryInfo(recoveryPath);

        if (!recoveryInfo.absoluteDir().exists()) {
            QMessageBox::warning(
                this,
                QStringLiteral("K1Wi MAGIC"),
                QStringLiteral(
                    "The recovery output directory does not exist.\n\n"
                    "Please select a valid output location."
                )
            );

            magicOutputLog->append(
                QStringLiteral(
                    "[GUI] MAGIC cancelled: recovery output directory "
                    "does not exist."
                )
            );
            return;
        }

        if (QFileInfo::exists(recoveryPath)) {
            const QMessageBox::StandardButton response =
                QMessageBox::question(
                    this,
                    QStringLiteral("K1Wi MAGIC"),
                    QStringLiteral(
                        "The selected recovery output already exists.\n\n"
                        "Overwrite it?"
                    ),
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::No
                );

            if (response != QMessageBox::Yes) {
                magicOutputLog->append(
                    QStringLiteral(
                        "[GUI] MAGIC cancelled: recovery overwrite declined."
                    )
                );
                return;
            }
        }
    }

    QStringList args;
    args << QStringLiteral("MAGIC");
    args << target;

    if (recoveryEnabled) {
        args << QStringLiteral("--recover");
        args << recoveryPath;
    }

    magicOutputLog->append(
        QStringLiteral("[GUI] MAGIC run summary")
    );
    magicOutputLog->append(
        QStringLiteral("[GUI] Mode: ") +
        (recoveryEnabled
             ? QStringLiteral("Inspect and recover ASCII bitstream")
             : QStringLiteral("Inspect only"))
    );
    magicOutputLog->append(
        QStringLiteral("[GUI] Target: ") + target
    );

    if (recoveryEnabled) {
        magicOutputLog->append(
            QStringLiteral("[GUI] Recovery output: ") + recoveryPath
        );
    }

    magicOutputLog->append(QString());
    magicOutputLog->append(
        QStringLiteral("Running: ") +
        cliInfo.absoluteFilePath() +
        QStringLiteral(" ") +
        args.join(QStringLiteral(" "))
    );
    magicOutputLog->append(QString());

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
        [
            this,
            process,
            combinedOutput,
            target,
            recoveryEnabled,
            recoveryPath
        ](int exitCode, QProcess::ExitStatus exitStatus) {
            magicOutputLog->append("");

            if (exitStatus == QProcess::NormalExit) {
                const QString findings = magicFindingsReport(
                    *combinedOutput,
                    target,
                    recoveryEnabled,
                    recoveryPath,
                    exitCode
                );

                magicFindingsLog->clear();

                const QString findingsColor =
                    exitCode != 0
                        ? QStringLiteral("#b00020")
                        : (
                            findings.contains(
                                QStringLiteral("Unknown file signature"),
                                Qt::CaseInsensitive
                            ) ||
                            findings.contains(
                                QStringLiteral("Non-byte-aligned"),
                                Qt::CaseInsensitive
                            )
                                ? QStringLiteral("#b26a00")
                                : QStringLiteral("#0b7a0b")
                        );

                appendStyledBlock(
                    magicFindingsLog,
                    findings,
                    findingsColor,
                    false
                );

                magicDetailsTabs->setCurrentIndex(0);

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
                magicFindingsLog->clear();

                appendStyledLine(
                    magicFindingsLog,
                    "MAGIC Analysis Findings",
                    "#b00020",
                    true
                );

                appendStyledLine(
                    magicFindingsLog,
                    "=======================",
                    "#b00020",
                    true
                );

                appendStyledLine(
                    magicFindingsLog,
                    QStringLiteral("Target: ") + target,
                    "#b00020"
                );

                appendStyledLine(
                    magicFindingsLog,
                    QStringLiteral(
                        "Classification: Process or recovery error"
                    ),
                    "#b00020",
                    true
                );

                appendStyledLine(
                    magicFindingsLog,
                    QStringLiteral(
                        "Status: MAGIC crashed or was terminated."
                    ),
                    "#b00020"
                );

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
    entropyDetailsTabs->setCurrentIndex(1);

    entropyFindingsLog->clear();
    entropyOutputLog->clear();

    entropyFindingsLog->append(
        QStringLiteral("[GUI] ENTROPY analysis in progress...")
    );

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
                const QString findings =
                    entropyFindingsReport(
                        *combinedOutput,
                        exitCode,
                        target,
                        modeLabel
                    );

                entropyFindingsLog->clear();

                appendStyledBlock(
                    entropyFindingsLog,
                    findings,
                    exitCode == 0
                        ? QStringLiteral("#0b7a0b")
                        : QStringLiteral("#b00020"),
                    false
                );

                entropyOutputLog->append(
                    QStringLiteral(
                        "Process finished with exit code %1"
                    ).arg(exitCode)
                );

                entropyDetailsTabs->setCurrentIndex(0);
            } else {
                entropyFindingsLog->clear();

                appendStyledLine(
                    entropyFindingsLog,
                    QStringLiteral(
                        "[RESULT] ENTROPY process crashed or was terminated."
                    ),
                    QStringLiteral("#b00020"),
                    true
                );

                appendStyledLine(
                    entropyOutputLog,
                    QStringLiteral(
                        "[RESULT] ENTROPY process crashed or was terminated."
                    ),
                    QStringLiteral("#b00020"),
                    true
                );

                entropyDetailsTabs->setCurrentIndex(0);
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
    /*
     * Begin every analysis on Overview. After successful parsing,
     * automatic result selection opens the most relevant detail tab.
     */
    pcapDetailsTabs->setCurrentIndex(0);

    pcapFindingsLog->clear();
    pcapNetworkLog->clear();
    pcapTransportLog->clear();
    pcapPayloadLog->clear();
    pcapOutputLog->clear();

    pcapFindingsLog->append("[GUI] Analysis in progress...");
    pcapNetworkLog->append("[GUI] Waiting for network details...");
    pcapTransportLog->append("[GUI] Waiting for transport details...");
    pcapPayloadLog->append("[GUI] Waiting for payload details...");

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

                    if (linkType.contains(
                            QStringLiteral("Ethernet"),
                            Qt::CaseInsensitive
                        )) {
                        appendStyledLine(
                            pcapFindingsLog,
                            QStringLiteral(
                                "[RESULT] Ethernet frame summary"
                            ),
                            QStringLiteral("#0057b8"),
                            true
                        );

                        appendPcapFinding(
                            pcapFindingsLog,
                            QStringLiteral("IPv4 frames"),
                            pcapReportCount(
                                *combinedOutput,
                                QStringLiteral("IPv4 frames:")
                            )
                        );

                        appendPcapFinding(
                            pcapFindingsLog,
                            QStringLiteral("ARP frames"),
                            pcapReportCount(
                                *combinedOutput,
                                QStringLiteral("ARP frames:")
                            )
                        );

                        appendPcapFinding(
                            pcapFindingsLog,
                            QStringLiteral("IPv6 frames"),
                            pcapReportCount(
                                *combinedOutput,
                                QStringLiteral("IPv6 frames:")
                            )
                        );

                        appendPcapFinding(
                            pcapFindingsLog,
                            QStringLiteral("Other EtherTypes"),
                            pcapReportCount(
                                *combinedOutput,
                                QStringLiteral("Other EtherTypes:")
                            )
                        );
                    }

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

                    pcapNetworkLog->clear();

                    bool networkDetailsFound = false;

                    networkDetailsFound =
                        appendPcapReportTable(
                            pcapNetworkLog,
                            *combinedOutput,
                            QStringLiteral("Top Source IPs"),
                            QStringLiteral("Top source IP addresses"),
                            QStringLiteral("NETWORK")
                        ) || networkDetailsFound;

                    networkDetailsFound =
                        appendPcapReportTable(
                            pcapNetworkLog,
                            *combinedOutput,
                            QStringLiteral("Top Destination IPs"),
                            QStringLiteral("Top destination IP addresses"),
                            QStringLiteral("NETWORK")
                        ) || networkDetailsFound;

                    networkDetailsFound =
                        appendPcapReportTable(
                            pcapNetworkLog,
                            *combinedOutput,
                            QStringLiteral(
                                "Top Ethernet Source MACs"
                            ),
                            QStringLiteral(
                                "Top source MAC addresses"
                            ),
                            QStringLiteral("NETWORK")
                        ) || networkDetailsFound;

                    networkDetailsFound =
                        appendPcapReportTable(
                            pcapNetworkLog,
                            *combinedOutput,
                            QStringLiteral(
                                "Top Ethernet Destination MACs"
                            ),
                            QStringLiteral(
                                "Top destination MAC addresses"
                            ),
                            QStringLiteral("NETWORK")
                        ) || networkDetailsFound;

                    networkDetailsFound =
                        appendPcapReportTable(
                            pcapNetworkLog,
                            *combinedOutput,
                            QStringLiteral("Top VLAN IDs"),
                            QStringLiteral("Observed VLAN IDs"),
                            QStringLiteral("NETWORK")
                        ) || networkDetailsFound;

                    const QStringList arpDetails =
                        pcapReportMatchingLines(
                            *combinedOutput,
                            QRegularExpression(
                                QStringLiteral(
                                    R"(^(ARP request:|ARP reply:|ARP operation=))"
                                )
                            )
                        );

                    if (!arpDetails.isEmpty()) {
                        appendStyledLine(
                            pcapNetworkLog,
                            QStringLiteral(
                                "[NETWORK] Full-mode ARP activity"
                            ),
                            QStringLiteral("#b35c00"),
                            true
                        );

                        for (const QString &arpDetail : arpDetails) {
                            appendStyledLine(
                                pcapNetworkLog,
                                QStringLiteral("  ") + arpDetail,
                                QStringLiteral("#b35c00"),
                                false
                            );
                        }

                        networkDetailsFound = true;
                    }

                    const QStringList ipv6Details =
                        pcapReportMatchingLines(
                            *combinedOutput,
                            QRegularExpression(
                                QStringLiteral(
                                    R"(^IPv6 .+ -> .+ next-header=[0-9]+ \([^)]+\) payload=[0-9]+$)"
                                )
                            )
                        );

                    if (!ipv6Details.isEmpty()) {
                        appendStyledLine(
                            pcapNetworkLog,
                            QStringLiteral(
                                "[NETWORK] Full-mode IPv6 activity"
                            ),
                            QStringLiteral("#6a3db5"),
                            true
                        );

                        for (const QString &ipv6Detail : ipv6Details) {
                            appendStyledLine(
                                pcapNetworkLog,
                                QStringLiteral("  ") + ipv6Detail,
                                QStringLiteral("#6a3db5"),
                                false
                            );
                        }

                        networkDetailsFound = true;
                    }

                    const QStringList networkWarnings =
                        pcapReportMatchingLines(
                            *combinedOutput,
                            QRegularExpression(
                                QStringLiteral(
                                    R"(^Warning: (truncated .+ VLAN tag|truncated ARP payload|truncated ARP header|truncated IPv6 payload.*|invalid IPv6 version [0-9]+|truncated IPv6 header)$)"
                                )
                            )
                        );

                    if (!networkWarnings.isEmpty()) {
                        appendStyledLine(
                            pcapNetworkLog,
                            QStringLiteral(
                                "[WARNING] Network parsing warnings"
                            ),
                            QStringLiteral("#b00020"),
                            true
                        );

                        for (const QString &warning : networkWarnings) {
                            appendStyledLine(
                                pcapNetworkLog,
                                QStringLiteral("  ") + warning,
                                QStringLiteral("#b00020"),
                                false
                            );
                        }

                        networkDetailsFound = true;
                    }

                    if (!networkDetailsFound) {
                        appendStyledLine(
                            pcapNetworkLog,
                            "[NETWORK] No IP, MAC, VLAN, ARP, or IPv6 details were found.",
                            "#0057b8",
                            false
                        );
                    }

                    pcapTransportLog->clear();

                    bool transportDetailsFound = false;

                    transportDetailsFound =
                        appendPcapReportTable(
                            pcapTransportLog,
                            *combinedOutput,
                            QStringLiteral("Top TCP Source Ports"),
                            QStringLiteral("Top TCP source ports"),
                            QStringLiteral("TRANSPORT")
                        ) || transportDetailsFound;

                    transportDetailsFound =
                        appendPcapReportTable(
                            pcapTransportLog,
                            *combinedOutput,
                            QStringLiteral(
                                "Top TCP Destination Ports"
                            ),
                            QStringLiteral(
                                "Top TCP destination ports"
                            ),
                            QStringLiteral("TRANSPORT")
                        ) || transportDetailsFound;

                    transportDetailsFound =
                        appendPcapReportTable(
                            pcapTransportLog,
                            *combinedOutput,
                            QStringLiteral("Top UDP Source Ports"),
                            QStringLiteral("Top UDP source ports"),
                            QStringLiteral("TRANSPORT")
                        ) || transportDetailsFound;

                    transportDetailsFound =
                        appendPcapReportTable(
                            pcapTransportLog,
                            *combinedOutput,
                            QStringLiteral(
                                "Top UDP Destination Ports"
                            ),
                            QStringLiteral(
                                "Top UDP destination ports"
                            ),
                            QStringLiteral("TRANSPORT")
                        ) || transportDetailsFound;

                    const QStringList udpDetails =
                        pcapReportMatchingLines(
                            *combinedOutput,
                            QRegularExpression(
                                QStringLiteral(
                                    R"(^UDP .+:[0-9]+ -> .+:[0-9]+ length=[0-9]+ payload=[0-9]+$)"
                                )
                            )
                        );

                    if (!udpDetails.isEmpty()) {
                        appendStyledLine(
                            pcapTransportLog,
                            QStringLiteral(
                                "[TRANSPORT] Full-mode UDP activity"
                            ),
                            QStringLiteral("#0b7a6f"),
                            true
                        );

                        for (const QString &udpDetail : udpDetails) {
                            appendStyledLine(
                                pcapTransportLog,
                                QStringLiteral("  ") + udpDetail,
                                QStringLiteral("#0b7a6f"),
                                false
                            );
                        }

                        transportDetailsFound = true;
                    }

                    const QStringList tcpDetails =
                        pcapReportMatchingLines(
                            *combinedOutput,
                            QRegularExpression(
                                QStringLiteral(
                                    R"(^TCP .+:[0-9]+ -> .+:[0-9]+ seq=[0-9]+ flags=[^ ]+ payload=[0-9]+$)"
                                )
                            )
                        );

                    if (!tcpDetails.isEmpty()) {
                        appendStyledLine(
                            pcapTransportLog,
                            QStringLiteral(
                                "[TRANSPORT] Full-mode TCP activity"
                            ),
                            QStringLiteral("#6a3db5"),
                            true
                        );

                        for (const QString &tcpDetail : tcpDetails) {
                            appendStyledLine(
                                pcapTransportLog,
                                QStringLiteral("  ") + tcpDetail,
                                QStringLiteral("#6a3db5"),
                                false
                            );
                        }

                        transportDetailsFound = true;
                    }

                    const int synPackets = pcapReportCount(
                        *combinedOutput,
                        QStringLiteral("SYN packets:")
                    );

                    const int ackPackets = pcapReportCount(
                        *combinedOutput,
                        QStringLiteral("ACK packets:")
                    );

                    const int finPackets = pcapReportCount(
                        *combinedOutput,
                        QStringLiteral("FIN packets:")
                    );

                    const int rstPackets = pcapReportCount(
                        *combinedOutput,
                        QStringLiteral("RST packets:")
                    );

                    const int pshPackets = pcapReportCount(
                        *combinedOutput,
                        QStringLiteral("PSH packets:")
                    );

                    const int urgPackets = pcapReportCount(
                        *combinedOutput,
                        QStringLiteral("URG packets:")
                    );

                    const bool hasTcpFlags =
                        synPackets > 0 ||
                        ackPackets > 0 ||
                        finPackets > 0 ||
                        rstPackets > 0 ||
                        pshPackets > 0 ||
                        urgPackets > 0;

                    if (hasTcpFlags) {
                        appendStyledLine(
                            pcapTransportLog,
                            "[TRANSPORT] TCP flag activity",
                            "#0057b8",
                            true
                        );

                        transportDetailsFound =
                            appendPcapTransportCount(
                                pcapTransportLog,
                                QStringLiteral("SYN packets"),
                                synPackets
                            ) || transportDetailsFound;

                        transportDetailsFound =
                            appendPcapTransportCount(
                                pcapTransportLog,
                                QStringLiteral("ACK packets"),
                                ackPackets
                            ) || transportDetailsFound;

                        transportDetailsFound =
                            appendPcapTransportCount(
                                pcapTransportLog,
                                QStringLiteral("FIN packets"),
                                finPackets
                            ) || transportDetailsFound;

                        transportDetailsFound =
                            appendPcapTransportCount(
                                pcapTransportLog,
                                QStringLiteral("RST packets"),
                                rstPackets
                            ) || transportDetailsFound;

                        transportDetailsFound =
                            appendPcapTransportCount(
                                pcapTransportLog,
                                QStringLiteral("PSH packets"),
                                pshPackets
                            ) || transportDetailsFound;

                        transportDetailsFound =
                            appendPcapTransportCount(
                                pcapTransportLog,
                                QStringLiteral("URG packets"),
                                urgPackets
                            ) || transportDetailsFound;
                    }

                    const int icmpPackets = pcapReportCount(
                        *combinedOutput,
                        QStringLiteral("ICMP packets:")
                    );

                    const QStringList icmpDetails =
                        pcapReportMatchingLines(
                            *combinedOutput,
                            QRegularExpression(
                                QStringLiteral(
                                    R"(^ICMP .+ -> .+ type=[0-9]+ code=[0-9]+ \([^)]+\)$)"
                                )
                            )
                        );

                    if (icmpPackets > 0) {
                        appendStyledLine(
                            pcapTransportLog,
                            QStringLiteral(
                                "[TRANSPORT] ICMP packets: %1"
                            ).arg(icmpPackets),
                            QStringLiteral("#b35c00"),
                            true
                        );

                        if (icmpDetails.isEmpty()) {
                            appendStyledLine(
                                pcapTransportLog,
                                QStringLiteral(
                                    "[NOTE] Run Full packet view for ICMP type and code details."
                                ),
                                QStringLiteral("#b35c00"),
                                false
                            );
                        }

                        transportDetailsFound = true;
                    }

                    if (!icmpDetails.isEmpty()) {
                        appendStyledLine(
                            pcapTransportLog,
                            QStringLiteral(
                                "[TRANSPORT] Full-mode ICMP activity"
                            ),
                            QStringLiteral("#b35c00"),
                            true
                        );

                        for (const QString &icmpDetail : icmpDetails) {
                            appendStyledLine(
                                pcapTransportLog,
                                QStringLiteral("  ") + icmpDetail,
                                QStringLiteral("#b35c00"),
                                false
                            );
                        }

                        transportDetailsFound = true;
                    }

                    const QStringList transportWarnings =
                        pcapReportMatchingLines(
                            *combinedOutput,
                            QRegularExpression(
                                QStringLiteral(
                                    R"(^Warning: (truncated ICMP header|invalid or truncated UDP length|truncated UDP header)$)"
                                )
                            )
                        );

                    if (!transportWarnings.isEmpty()) {
                        appendStyledLine(
                            pcapTransportLog,
                            QStringLiteral(
                                "[WARNING] Transport parsing warnings"
                            ),
                            QStringLiteral("#b00020"),
                            true
                        );

                        for (const QString &warning :
                             transportWarnings) {
                            appendStyledLine(
                                pcapTransportLog,
                                QStringLiteral("  ") + warning,
                                QStringLiteral("#b00020"),
                                false
                            );
                        }

                        transportDetailsFound = true;
                    }

                    if (!transportDetailsFound) {
                        appendStyledLine(
                            pcapTransportLog,
                            "[TRANSPORT] No TCP, UDP, or ICMP activity was found.",
                            "#0057b8",
                            false
                        );
                    }

                    pcapPayloadLog->clear();

                    const int tcpPayloadPackets =
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("TCP payload packets:")
                        );

                    const int tcpPayloadBytes =
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral("TCP payload bytes:")
                        );

                    const int printablePayloadPackets =
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral(
                                "Printable TCP payload packets:"
                            )
                        );

                    const int base64PayloadPackets =
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral(
                                "Base64-like TCP payload packets:"
                            )
                        );

                    const int decodedPrintablePackets =
                        pcapReportCount(
                            *combinedOutput,
                            QStringLiteral(
                                "Base64 decoded printable packets:"
                            )
                        );

                    if (tcpPayloadPackets > 0) {
                        appendStyledLine(
                            pcapPayloadLog,
                            QStringLiteral(
                                "[PAYLOAD] TCP payload packets: %1"
                            ).arg(tcpPayloadPackets),
                            "#0057b8",
                            true
                        );

                        appendStyledLine(
                            pcapPayloadLog,
                            QStringLiteral(
                                "[PAYLOAD] TCP payload bytes: %1"
                            ).arg(tcpPayloadBytes),
                            "#0057b8",
                            false
                        );

                        if (printablePayloadPackets > 0) {
                            appendStyledLine(
                                pcapPayloadLog,
                                QStringLiteral(
                                    "[PAYLOAD] Printable payload packets: %1"
                                ).arg(printablePayloadPackets),
                                "#0057b8",
                                false
                            );
                        }

                        if (base64PayloadPackets > 0) {
                            appendStyledLine(
                                pcapPayloadLog,
                                QStringLiteral(
                                    "[PAYLOAD] Base64-like payload packets: %1"
                                ).arg(base64PayloadPackets),
                                "#b35c00",
                                true
                            );
                        }

                        if (decodedPrintablePackets > 0) {
                            appendStyledLine(
                                pcapPayloadLog,
                                QStringLiteral(
                                    "[PAYLOAD] Decoded printable packets: %1"
                                ).arg(decodedPrintablePackets),
                                "#b35c00",
                                false
                            );
                        }

                        const QStringList directionalFlows =
                            pcapDirectionalFlowSections(
                                *combinedOutput
                            );

                        if (!directionalFlows.isEmpty()) {
                            appendStyledLine(
                                pcapPayloadLog,
                                QStringLiteral(
                                    "[RECONSTRUCTION] Directional TCP flows: %1"
                                ).arg(directionalFlows.size()),
                                "#b35c00",
                                true
                            );
                        }

                        for (qsizetype flowIndex = 0;
                             flowIndex < directionalFlows.size();
                             ++flowIndex) {
                            const QString &flowOutput =
                                directionalFlows.at(flowIndex);

                            const QString flowHeading =
                                flowOutput.section(
                                    '\n',
                                    0,
                                    0
                                ).trimmed();

                            const QString streamDirection =
                                pcapReportValue(
                                    flowOutput,
                                    QStringLiteral("Stream:")
                                );

                            const QString payloadFragments =
                                pcapReportValue(
                                    flowOutput,
                                    QStringLiteral(
                                        "TCP payload fragments:"
                                    )
                                );

                            const QString reconstructedBytes =
                                pcapReportValue(
                                    flowOutput,
                                    QStringLiteral(
                                        "Reconstructed payload bytes:"
                                    )
                                );

                            const QString rawReconstruction =
                                pcapReportFollowingLine(
                                    flowOutput,
                                    QStringLiteral(
                                        "Reconstructed payload by TCP sequence:"
                                    )
                                );

                            const QStringList base64Section =
                                pcapReportSectionLines(
                                    flowOutput,
                                    QStringLiteral(
                                        "Base64 Reconstruction"
                                    )
                                );

                            const QStringList sequenceSection =
                                pcapReportSectionLines(
                                    flowOutput,
                                    QStringLiteral(
                                        "Decoded TCP Payload Reconstruction by Sequence"
                                    )
                                );

                            const QStringList timeSection =
                                pcapReportSectionLines(
                                    flowOutput,
                                    QStringLiteral(
                                        "Decoded TCP Payload Reconstruction by Time"
                                    )
                                );

                            const int sequenceDecodedFragments =
                                pcapReportCount(
                                    sequenceSection.join(
                                        QStringLiteral("\n")
                                    ),
                                    QStringLiteral(
                                        "Decoded printable fragments:"
                                    )
                                );

                            const int timeDecodedFragments =
                                pcapReportCount(
                                    timeSection.join(
                                        QStringLiteral("\n")
                                    ),
                                    QStringLiteral(
                                        "Decoded printable fragments:"
                                    )
                                );

                            appendStyledLine(
                                pcapPayloadLog,
                                QStringLiteral(
                                    "[FLOW] %1"
                                ).arg(
                                    flowHeading.isEmpty()
                                        ? QStringLiteral(
                                              "Directional flow %1"
                                          ).arg(flowIndex + 1)
                                        : flowHeading
                                ),
                                "#b35c00",
                                true
                            );

                            if (!streamDirection.isEmpty()) {
                                appendStyledLine(
                                    pcapPayloadLog,
                                    QStringLiteral("[STREAM] ") +
                                        streamDirection,
                                    "#b35c00",
                                    false
                                );
                            }

                            if (!payloadFragments.isEmpty()) {
                                appendStyledLine(
                                    pcapPayloadLog,
                                    QStringLiteral(
                                        "[RECONSTRUCTION] Payload fragments: "
                                    ) + payloadFragments,
                                    "#b35c00",
                                    false
                                );
                            }

                            if (!reconstructedBytes.isEmpty()) {
                                appendStyledLine(
                                    pcapPayloadLog,
                                    QStringLiteral(
                                        "[RECONSTRUCTION] Payload bytes: "
                                    ) + reconstructedBytes,
                                    "#b35c00",
                                    false
                                );
                            }

                            if (!rawReconstruction.isEmpty() &&
                                rawReconstruction !=
                                    QStringLiteral("n/a")) {
                                appendStyledLine(
                                    pcapPayloadLog,
                                    "[RECONSTRUCTION] Raw payload by TCP sequence:",
                                    "#b35c00",
                                    true
                                );

                                appendStyledLine(
                                    pcapPayloadLog,
                                    rawReconstruction,
                                    "#b35c00",
                                    false
                                );
                            }

                            if (!base64Section.isEmpty()) {
                                const QString base64Result =
                                    base64Section.join(
                                        QStringLiteral("\n")
                                    );

                                QString base64Status;
                                QString base64Color =
                                    QStringLiteral("#b35c00");

                                if (base64Result.contains(
                                        QStringLiteral(
                                            "Decoded bytes:"
                                        )
                                    ) &&
                                    base64Result.contains(
                                        QStringLiteral(
                                            "Decoded preview:"
                                        )
                                    )) {
                                    base64Status =
                                        QStringLiteral(
                                            "[BASE64] Clean stream decoded successfully"
                                        );

                                    base64Color =
                                        QStringLiteral("#0b7a0b");
                                } else if (base64Result.contains(
                                               QStringLiteral(
                                                   "decode failed"
                                               ),
                                               Qt::CaseInsensitive
                                           )) {
                                    base64Status =
                                        QStringLiteral(
                                            "[BASE64] Base64-like stream detected, but decoding failed"
                                        );
                                } else if (base64Result.contains(
                                               QStringLiteral(
                                                   "not clean Base64"
                                               ),
                                               Qt::CaseInsensitive
                                           )) {
                                    base64Status =
                                        QStringLiteral(
                                            "[BASE64] Reconstructed stream is not clean Base64"
                                        );
                                } else {
                                    base64Status =
                                        QStringLiteral(
                                            "[BASE64] Combined-stream result"
                                        );
                                }

                                appendStyledLine(
                                    pcapPayloadLog,
                                    base64Status,
                                    base64Color,
                                    true
                                );

                                for (const QString &line :
                                     base64Section) {
                                    appendStyledLine(
                                        pcapPayloadLog,
                                        line,
                                        base64Color,
                                        false
                                    );
                                }
                            }

                            if (!sequenceSection.isEmpty() &&
                                sequenceDecodedFragments > 0) {
                                appendStyledLine(
                                    pcapPayloadLog,
                                    "[RECONSTRUCTION] Decoded sequence-order result",
                                    "#b35c00",
                                    true
                                );

                                for (const QString &line :
                                     sequenceSection) {
                                    appendStyledLine(
                                        pcapPayloadLog,
                                        line,
                                        "#b35c00",
                                        false
                                    );
                                }
                            }

                            if (!timeSection.isEmpty() &&
                                timeDecodedFragments > 0) {
                                appendStyledLine(
                                    pcapPayloadLog,
                                    "[RECONSTRUCTION] Decoded time-order result",
                                    "#b35c00",
                                    true
                                );

                                for (const QString &line :
                                     timeSection) {
                                    appendStyledLine(
                                        pcapPayloadLog,
                                        line,
                                        "#b35c00",
                                        false
                                    );
                                }
                            }

                            if (flowIndex + 1 <
                                directionalFlows.size()) {
                                pcapPayloadLog->append("");
                            }
                        }

                        if (directionalFlows.isEmpty()) {
                            appendStyledLine(
                                pcapPayloadLog,
                                "[RECONSTRUCTION] No directional-flow reconstruction blocks were available.",
                                "#0057b8",
                                false
                            );
                        }

                    } else {
                        appendStyledLine(
                            pcapPayloadLog,
                            "[PAYLOAD] No TCP payload or reconstruction data was found.",
                            "#0057b8",
                            false
                        );
                    }

                    /*
                     * Select the most useful result tab automatically.
                     * Priority:
                     *   1. Payload data
                     *   2. Transport activity
                     *   3. Network activity
                     *   4. Overview fallback
                     */
                    if (tcpPayloadPackets > 0) {
                        pcapDetailsTabs->setCurrentIndex(3);
                    } else if (transportDetailsFound) {
                        pcapDetailsTabs->setCurrentIndex(2);
                    } else if (networkDetailsFound) {
                        pcapDetailsTabs->setCurrentIndex(1);
                    } else {
                        pcapDetailsTabs->setCurrentIndex(0);
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
    lyzerFindingsLog->clear();
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
                lyzerFindingsLog->setPlainText(
                    lyzerStructuredFindings(
                        *combinedOutput,
                        exitCode,
                        target,
                        modeLabel
                    )
                );

                lyzerDetailsTabs->setCurrentWidget(
                    lyzerFindingsLog
                );

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
    extractDetailsTabs->setCurrentIndex(1);
    extractFindingsLog->clear();
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
                extractFindingsLog->setPlainText(
                    extractStructuredFindings(
                        *combinedOutput,
                        exitCode,
                        target,
                        recursiveMode
                    )
                );

                extractDetailsTabs->setCurrentWidget(
                    extractFindingsLog
                );

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
