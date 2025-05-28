#include <QString>
#include <QByteArray>
#include <QtCrypto/QtCrypto>  // Именно так

// Инициализация QCA (лучше делать один раз, но для примера тут)
static QCA::Initializer init;

int indexOfIgnoreCase(const QString& alphabet, QChar c) {
    for (int i = 0; i < alphabet.size(); ++i) {
        if (alphabet[i].toCaseFolded() == c.toCaseFolded())
            return i;
    }
    return -1;
}

QChar adjustCase(QChar resultChar, QChar original) {
    return original.isLower() ? resultChar.toLower() : resultChar.toUpper();
}

// Caesar
QString caesarEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    bool ok;
    int shift = key.toInt(&ok);
    if (!ok) shift = 0;
    QString result;
    int n = alphabet.size();
    for (QChar c : text) {
        int idx = indexOfIgnoreCase(alphabet, c);
        if (idx >= 0) {
            int newIdx = (idx + shift + n) % n;
            result.append(adjustCase(alphabet[newIdx], c));
        } else
            result.append(c);
    }
    return result;
}

// Atbash
QString atbashEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(key);
    QString result;
    int n = alphabet.size();
    for (QChar c : text) {
        int idx = indexOfIgnoreCase(alphabet, c);
        if (idx >= 0)
            result.append(adjustCase(alphabet[n - 1 - idx], c));
        else
            result.append(c);
    }
    return result;
}

// Beaufort
QString beaufortEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    QString result;
    int n = alphabet.size();
    int m = key.size();
    for (int i = 0; i < text.size(); ++i) {
        QChar c = text[i];
        int idx = indexOfIgnoreCase(alphabet, c);
        if (idx >= 0) {
            int kidx = indexOfIgnoreCase(alphabet, key[i % m]);
            int newIdx = (kidx - idx + n) % n;
            result.append(adjustCase(alphabet[newIdx], c));
        } else
            result.append(c);
    }
    return result;
}

// Kuznechik (простой XOR)
QString kuznechikEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(alphabet);
    QByteArray data = text.toUtf8();
    QByteArray k = key.toUtf8();
    for (int i = 0; i < data.size(); ++i) {
        data[i] = data[i] ^ k[i % k.size()];
    }
    return QString::fromUtf8(data.toBase64());
}

// RSA
QString rsaEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(alphabet);

    QCA::PublicKey pub = QCA::PublicKey::fromPEM(key.toUtf8());

    if (pub.isNull()) {
        qWarning("Invalid public key");
        return QString();
    }

    QCA::SecureArray encrypted = pub.encrypt(text.toUtf8(), QCA::EME_PKCS1_OAEP);

    if (encrypted.isEmpty()) {
        qWarning("Encryption failed");
        return QString();
    }

    QByteArray encryptedBytes = encrypted.data();
    QString encryptedBase64 = encryptedBytes.toBase64();

    return encryptedBase64;
}

