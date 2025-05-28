#include <QString>
#include <QByteArray>
#include <QtCrypto/QtCrypto>

// Инициализация QCA
static QCA::Initializer init;

// Helper: case-insensitive index
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

// Caesar cipher
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
        } else result.append(c);
    }
    return result;
}

// Atbash cipher
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

// Beaufort cipher
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
        } else result.append(c);
    }
    return result;
}

// Kuznechik (stub)
QString kuznechikEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(alphabet);
    QByteArray data = text.toUtf8();
    QByteArray k = key.toUtf8();
    for (int i = 0; i < data.size(); ++i) {
        data[i] = data[i] ^ k[i % k.size()];
    }
    return QString::fromUtf8(data.toBase64());
}

// RSA Encrypt
QString rsaEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(alphabet); // alphabet не используется для RSA
    QCA::PublicKey publicKey = QCA::PublicKey::fromPEM(key.toUtf8());
    if (publicKey.isNull()) {
        qWarning("Недействительный публичный ключ.");
        return QString();
    }

    QCA::SecureArray encrypted = publicKey.encrypt(text.toUtf8(), QCA::EME_PKCS1_OAEP);
    if (encrypted.isEmpty()) {
        qWarning("Ошибка шифрования.");
        return QString();
    }
    return QString(encrypted.toByteArray().toBase64());
}

// RSA Decrypt
QString rsaDecrypt(const QString& base64Text, const QString& privateKeyPem) {
    QCA::PrivateKey privateKey = QCA::PrivateKey::fromPEM(privateKeyPem.toUtf8());
    if (privateKey.isNull()) {
        qWarning("Недействительный приватный ключ.");
        return QString();
    }

    QByteArray encryptedBytes = QByteArray::fromBase64(base64Text.toUtf8());
    if (encryptedBytes.isEmpty()) {
        qWarning("Некорректный зашифрованный текст в формате Base64.");
        return QString();
    }

    QCA::SecureArray decrypted;
    bool success = privateKey.decrypt(encryptedBytes, &decrypted, QCA::EME_PKCS1_OAEP);
    if (!success || decrypted.isEmpty()) {
        qWarning("Ошибка расшифровки.");
        return QString();
    }

    return QString::fromUtf8(decrypted.data(), decrypted.size());
}
