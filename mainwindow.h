#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QWidget>
#include <QStyle>
#include <QApplication>
#include "exporter.h"
#include "exportformatdialog.h"
#include <QtCrypto>
#include "kuz_calc.h"
#include <functional>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

private slots:
    void onCipherChanged(int index);
    void onAlphabetChanged(int index);
    void encryptText();
    void decryptText();
    void exportResult();

    
    // Слоты для генерации ключей
    void generateCaesarKey();
    void generateBeaufortKey();
    void generateKuznechikKey();
    void generateKuznechikVector();
    void generateAes256Key();
    void generateBlowfishKey();
    void generateTripleDesKey();
    void generateCast5Key();

private:
    Ui::MainWindow* ui;
    QString currentAlphabet;
    QString rsaPublicKey;
    QString rsaPrivateKey;
    QVector<QString> cipherNames;
    //QVector<std::function<QString(MainWindow*, const QString&, const QString&, const QString&)>> cipherFuncs;
    using CipherFunc = QString (MainWindow::*)(const QString&, const QString&, const QString&);
    QList<CipherFunc> cipherFuncs;

    void updateAlphabetDisplay();
    QString caesarEncrypt(const QString& text, const QString& key, const QString& alphabet);
    QString atbashEncrypt(const QString& text, const QString& key, const QString& alphabet);
    QString beaufortEncrypt(const QString& text, const QString& key, const QString& alphabet);
    QString kuznechikEncrypt(const QString& text, const QString& key, const QString& alphabet);
    QString rsaEncrypt(const QString& text, const QString& key, const QString& alphabet);
    QString rsaDecrypt(const QString& text, const QString& key);
    QString aes256Encrypt(const QString& text, const QString& key, const QString& alphabet);
    QString aes256Decrypt(const QString& text, const QString& key);
    QString blowfishEncrypt(const QString& text, const QString& key, const QString& alphabet);
    QString blowfishDecrypt(const QString& text, const QString& key);
    QString tripleDesEncrypt(const QString& text, const QString& key, const QString& alphabet);
    QString tripleDesDecrypt(const QString& text, const QString& key);
    QString cast5Encrypt(const QString& text, const QString& key, const QString& alphabet);
    QString cast5Decrypt(const QString& text, const QString& key);
    QString crypt(QString data);

    QCA::SecureArray padData(const QCA::SecureArray& data, int blockSize);
    QCA::SecureArray unpadData(const QCA::SecureArray& data);
};

#endif // MAINWINDOW_H
