#include <QString>
#include <QByteArray>
#include <QtCrypto/QtCrypto>
#include <QDebug>

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
    Q_UNUSED(alphabet);
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

// AES-256 Encrypt
QString aes256Encrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(alphabet);
    QByteArray keyData = key.toUtf8();
    if (keyData.size() < 32) {
        keyData.resize(32, 0);
    } else if (keyData.size() > 32) {
        keyData = keyData.left(32);
    }

    QCA::SymmetricKey symKey(keyData);
    QCA::InitializationVector iv(QByteArray(16, 0));
    QCA::Cipher cipher("aes256", QCA::Cipher::CBC, QCA::Cipher::DefaultPadding, QCA::Encode, symKey, iv);

    QCA::SecureArray encrypted = cipher.process(text.toUtf8());
    if (!cipher.ok() || encrypted.isEmpty()) {
        qWarning("Ошибка шифрования AES-256.");
        return QString("Ошибка шифрования AES-256.");
    }

    return QString(encrypted.toByteArray().toBase64());
}

// AES-256 Decrypt
QString aes256Decrypt(const QString& base64Text, const QString& key) {
    QByteArray keyData = key.toUtf8();
    if (keyData.size() < 32) {
        keyData.resize(32, 0);
    } else if (keyData.size() > 32) {
        keyData = keyData.left(32);
    }

    QCA::SymmetricKey symKey(keyData);
    QCA::InitializationVector iv(QByteArray(16, 0));
    QCA::Cipher cipher("aes256", QCA::Cipher::CBC, QCA::Cipher::DefaultPadding, QCA::Decode, symKey, iv);

    QByteArray encryptedBytes = QByteArray::fromBase64(base64Text.toUtf8());
    if (encryptedBytes.isEmpty()) {
        qWarning("Некорректный зашифрованный текст в формате Base64.");
        return QString();
    }

    QCA::SecureArray decrypted = cipher.process(encryptedBytes);
    if (!cipher.ok() || decrypted.isEmpty()) {
        qWarning("Ошибка расшифровки AES-256.");
        return QString("Ошибка расшифровки AES-256.");
    }

    return QString::fromUtf8(decrypted.data(), decrypted.size());
}

// Blowfish Encrypt
QString blowfishEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(alphabet);
    QByteArray keyData = key.toUtf8();
    if (keyData.size() < 4) {
        keyData.resize(4, 0);
    } else if (keyData.size() > 56) {
        keyData = keyData.left(56);
    }

    QCA::SymmetricKey symKey(keyData);
    QCA::InitializationVector iv(QByteArray(8, 0));
    QCA::Cipher cipher("blowfish", QCA::Cipher::CBC, QCA::Cipher::DefaultPadding, QCA::Encode, symKey, iv);

    QCA::SecureArray encrypted = cipher.process(text.toUtf8());
    if (!cipher.ok() || encrypted.isEmpty()) {
        qWarning("Ошибка шифрования Blowfish.");
        return QString("Ошибка шифрования Blowfish.");
    }

    return QString(encrypted.toByteArray().toBase64());
}

// Blowfish Decrypt
QString blowfishDecrypt(const QString& base64Text, const QString& key) {
    QByteArray keyData = key.toUtf8();
    if (keyData.size() < 4) {
        keyData.resize(4, 0);
    } else if (keyData.size() > 56) {
        keyData = keyData.left(56);
    }

    QCA::SymmetricKey symKey(keyData);
    QCA::InitializationVector iv(QByteArray(8, 0));
    QCA::Cipher cipher("blowfish", QCA::Cipher::CBC, QCA::Cipher::DefaultPadding, QCA::Decode, symKey, iv);

    QByteArray encryptedBytes = QByteArray::fromBase64(base64Text.toUtf8());
    if (encryptedBytes.isEmpty()) {
        qWarning("Некорректный зашифрованный текст в формате Base64.");
        return QString();
    }

    QCA::SecureArray decrypted = cipher.process(encryptedBytes);
    if (!cipher.ok() || decrypted.isEmpty()) {
        qWarning("Ошибка расшифровки Blowfish.");
        return QString("Ошибка расшифровки Blowfish.");
    }

    return QString::fromUtf8(decrypted.data(), decrypted.size());
}

// 3DES Encrypt
QString tripleDesEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(alphabet);
    qDebug() << "Начало шифрования 3DES...";

    if (!QCA::isSupported("tripledes-ecb")) {
        qWarning() << "3DES в режиме ECB не поддерживается в вашей системе!";
        return QString("Ошибка: 3DES в режиме ECB не поддерживается.");
    }

    if (text.isEmpty()) {
        qWarning() << "Пустой текст для шифрования.";
        return QString("Ошибка: пустой текст для шифрования.");
    }

    QByteArray keyData = key.toUtf8();
    qDebug() << "Длина ключа:" << keyData.size();
    if (keyData.isEmpty()) {
        qWarning() << "Пустой ключ для 3DES.";
        return QString("Ошибка: пустой ключ.");
    }
    if (keyData.size() < 24) {
        keyData.resize(24, 0);
        qDebug() << "Ключ дополнен до 24 байт.";
    } else if (keyData.size() > 24) {
        keyData = keyData.left(24);
        qDebug() << "Ключ обрезан до 24 байт.";
    }

    QByteArray textData = text.toUtf8();
    qDebug() << "Размер текста (в байтах):" << textData.size();
    // Явное дополнение текста до кратности 8 байт с использованием PKCS5/PKCS7
    int paddingLength = 8 - (textData.size() % 8);
    if (paddingLength < 8) {
        textData.append(QByteArray(paddingLength, paddingLength));
        qDebug() << "Текст дополнен на" << paddingLength << "байт. Новый размер:" << textData.size();
    }

    QCA::SymmetricKey symKey(keyData);
    qDebug() << "Ключ успешно создан.";

    QCA::Cipher cipher("tripledes", QCA::Cipher::ECB, QCA::Cipher::DefaultPadding, QCA::Encode, symKey);
    qDebug() << "Шифр 3DES (ECB) создан.";

    qDebug() << "Шифрование текста...";
    QCA::SecureArray encrypted = cipher.process(textData);
    if (!cipher.ok() || encrypted.isEmpty()) {
        qWarning() << "Ошибка шифрования 3DES.";
        return QString("Ошибка шифрования 3DES.");
    }

    qDebug() << "Шифрование успешно. Размер зашифрованных данных:" << encrypted.size();
    return QString(encrypted.toByteArray().toBase64());
}

// 3DES Decrypt
QString tripleDesDecrypt(const QString& base64Text, const QString& key) {
    if (!QCA::isSupported("tripledes-ecb")) {
        qWarning() << "3DES в режиме ECB не поддерживается в вашей системе!";
        return QString("Ошибка: 3DES в режиме ECB не поддерживается.");
    }

    QByteArray keyData = key.toUtf8();
    if (keyData.size() < 24) {
        keyData.resize(24, 0);
    } else if (keyData.size() > 24) {
        keyData = keyData.left(24);
    }

    QCA::SymmetricKey symKey(keyData);
    QCA::Cipher cipher("tripledes", QCA::Cipher::ECB, QCA::Cipher::DefaultPadding, QCA::Decode, symKey);

    QByteArray encryptedBytes = QByteArray::fromBase64(base64Text.toUtf8());
    if (encryptedBytes.isEmpty()) {
        qWarning("Некорректный зашифрованный текст в формате Base64.");
        return QString();
    }

    QCA::SecureArray decrypted = cipher.process(encryptedBytes);
    if (!cipher.ok() || decrypted.isEmpty()) {
        qWarning("Ошибка расшифровки 3DES.");
        return QString("Ошибка расшифровки 3DES.");
    }

    // Удаление padding (PKCS5/PKCS7)
    int paddingLength = decrypted[decrypted.size() - 1];
    if (paddingLength > 0 && paddingLength <= 8) {
        decrypted.resize(decrypted.size() - paddingLength);
    }

    return QString::fromUtf8(decrypted.data(), decrypted.size());
}

// CAST5 Encrypt
QString cast5Encrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(alphabet);
    QByteArray keyData = key.toUtf8();
    if (keyData.size() < 5) {
        keyData.resize(5, 0);
    } else if (keyData.size() > 16) {
        keyData = keyData.left(16);
    }

    QCA::SymmetricKey symKey(keyData);
    QCA::InitializationVector iv(QByteArray(8, 0));
    QCA::Cipher cipher("cast5", QCA::Cipher::CBC, QCA::Cipher::DefaultPadding, QCA::Encode, symKey, iv);

    QCA::SecureArray encrypted = cipher.process(text.toUtf8());
    if (!cipher.ok() || encrypted.isEmpty()) {
        qWarning("Ошибка шифрования CAST5.");
        return QString();
    }

    return QString(encrypted.toByteArray().toBase64());
}

// CAST5 Decrypt
QString cast5Decrypt(const QString& base64Text, const QString& key) {
    QByteArray keyData = key.toUtf8();
    if (keyData.size() < 5) {
        keyData.resize(5, 0);
    } else if (keyData.size() > 16) {
        keyData = keyData.left(16);
    }

    QCA::SymmetricKey symKey(keyData);
    QCA::InitializationVector iv(QByteArray(8, 0));
    QCA::Cipher cipher("cast5", QCA::Cipher::CBC, QCA::Cipher::DefaultPadding, QCA::Decode, symKey, iv);

    QByteArray encryptedBytes = QByteArray::fromBase64(base64Text.toUtf8());
    if (encryptedBytes.isEmpty()) {
        qWarning("Некорректный зашифрованный текст в формате Base64.");
        return QString();
    }

    QCA::SecureArray decrypted = cipher.process(encryptedBytes);
    if (!cipher.ok() || decrypted.isEmpty()) {
        qWarning("Ошибка расшифровки CAST5.");
        return QString();
    }

    return QString::fromUtf8(decrypted.data(), decrypted.size());
}
