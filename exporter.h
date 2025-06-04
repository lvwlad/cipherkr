#ifndef EXPORTER_H
#define EXPORTER_H

#include <QString>
#include <QDateTime>
#include <QFile>
#include <QTextStream>
#include <QJsonObject>
#include <QJsonDocument>

class Exporter {
public:
    bool exportData(const QString& filename, const QString& format, const QString& input, const QString& output, const QString& cipherName);

private:
    bool exportToText(const QString& filename, const QString& input, const QString& output, const QString& cipherName);
    bool exportToHtml(const QString& filename, const QString& input, const QString& output, const QString& cipherName);
    bool exportToJson(const QString& filename, const QString& input, const QString& output, const QString& cipherName);
    QString getCipherDescription(const QString& cipherName);
};

#endif // EXPORTER_H
