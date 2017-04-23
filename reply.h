#ifndef REPLY_H
#define REPLY_H

#include <QObject>
#include <QHostAddress>

struct Reply
{
    quint8 version;
    quint8 count_methodes;
    quint8 methodes[2];
    quint16 port;
    QHostAddress ip;
    QString message;
};

#endif // REPLY_H
