#include "exporter.h"
#include <QFile>
#include <QTextStream>

bool Exporter::exportToFile(const QString& filename,
                            const QString& original,
                            const QString& encrypted,
                            const QString& publicKey,
                            const QString& privateKey) {
    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
        return false;

    QTextStream out(&file);
    out << "Original Text:" << Qt::endl
        << original << Qt::endl << Qt::endl;
    out << "Encrypted Text:" << Qt::endl
        << encrypted << Qt::endl;
    if (!publicKey.isEmpty()) {
        out << Qt::endl << "RSA Public Key:" << Qt::endl
            << publicKey << Qt::endl;
    }
    if (!privateKey.isEmpty()) {
        out << Qt::endl << "RSA Private Key:" << Qt::endl
            << privateKey << Qt::endl;
    }
    return true;
}
