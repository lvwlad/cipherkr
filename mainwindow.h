#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "exporter.h"
#include "exportformatdialog.h"
#include <QtCrypto/QtCrypto>
#include "kuz_calc.h"
#include <functional>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow();
    QString crypt(QString data);

private slots:
    void onCipherChanged(int index);
    void onAlphabetChanged(int index);
    void updateAlphabetDisplay();
    void generateRsaKeys();
    void encryptText();
    void decryptText();
    void exportResult();

private:
    Ui::MainWindow* ui;
    QString currentAlphabet;
    QString rsaPublicKey;
    QString rsaPrivateKey;
    QVector<QString> cipherNames;
    QVector<std::function<QString(MainWindow*, const QString&, const QString&, const QString&)>> cipherFuncs;

    // Функции шифрования
    QString caesarEncrypt(const QString& text, const QString& key, const QString& alphabet);
    QString atbashEncrypt(const QString& text, const QString& key, const QString& alphabet);
    QString beaufortEncrypt(const QString& text, const QString& key, const QString& alphabet);
    QString kuznechikEncrypt(const QString& text, const QString& key, const QString& alphabet);
    QString rsaEncrypt(const QString& text, const QString& key, const QString& alphabet);
    QString aes256Encrypt(const QString& text, const QString& key, const QString& alphabet);
    QString blowfishEncrypt(const QString& text, const QString& key, const QString& alphabet);
    QString tripleDesEncrypt(const QString& text, const QString& key, const QString& alphabet);
    QString cast5Encrypt(const QString& text, const QString& key, const QString& alphabet);

    // Функции расшифровки
    QString rsaDecrypt(const QString& text, const QString& key);
    QString aes256Decrypt(const QString& text, const QString& key);
    QString blowfishDecrypt(const QString& text, const QString& key);
    QString tripleDesDecrypt(const QString& text, const QString& key);
    QString cast5Decrypt(const QString& text, const QString& key);
};

#endif // MAINWINDOW_H
