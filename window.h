#ifndef WINDOW_H
#define WINDOW_H

#include <QDialog>
#include <QTextEdit>
#include <QLineEdit>
#include <QGroupBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QUdpSocket>
#include <QHostAddress>

#include "reply.h"

struct Reply;

class Window : public QDialog
{
    Q_OBJECT

public:
    Window(QWidget *parent = 0);
    ~Window();

private:
        QUdpSocket *socket;
        QTextEdit *edit;
        QLineEdit *user, *passwd;

        Reply *reply;
        QString username, password;
        quint16 src_port;

private:
        void Layout();

private slots:

            void SendDatagram(int type, quint16 port);
            void ProcessData();
            void ButtonClick();
};

#endif // WINDOW_H
