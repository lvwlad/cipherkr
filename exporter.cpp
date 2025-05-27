// Exporter.cpp
#include "exporter.h"
#include <QFile>
#include <QTextStream>

bool Exporter::exportToFile(const QString& filename,
                            const QString& original,
                            const QString& encrypted) {
    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
        return false;

    QTextStream out(&file);
    out << "Original Text:" << Qt::endl
        << original << Qt::endl << Qt::endl;
    out << "Encrypted Text:" << Qt::endl
        << encrypted << Qt::endl;
    return true;
}
