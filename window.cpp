#include "window.h"
Window::Window(QWidget *parent): QDialog(parent)
{
    socket = new QUdpSocket(this); // creating new socket
    socket->bind(2424); // listen 2424 port
    connect(socket, SIGNAL(readyRead()), this, SLOT(ProcessData()));

    Layout();

    reply = new Reply;
}

Window::~Window()
{

}

void Window::Layout() // creating UI
{
    this->setFixedSize(300, 400);
    this->setStyleSheet("background: rgb(95, 96, 97);");

    edit = new QTextEdit;
    edit->setReadOnly(true);
    edit->setStyleSheet("border: 1px solid white;"
                        "color: white; font-weight: bold;");

    QHBoxLayout *security = new QHBoxLayout;
    user = new QLineEdit("user");
    user->setStyleSheet("border: 1px solid white; font-weight: bold; "
                        "color: white;");

    passwd = new QLineEdit("password");
    passwd->setStyleSheet("border: 1px solid white; font-weight: bold; "
                        "color: white;");
    passwd->setEchoMode(QLineEdit::Password);

    QPushButton *btn = new QPushButton("OK");
    btn->setMaximumWidth(30);
    btn->setCursor(Qt::PointingHandCursor);
    btn->setStyleSheet("QPushButton:hover { background: rgb(70, 150, 30); }");
    connect(btn, SIGNAL(clicked(bool)), this, SLOT(ButtonClick()));

    security->addWidget(user);
    security->addWidget(passwd);
    security->addWidget(btn);

    QGroupBox *box = new QGroupBox("Security");
    box->setStyleSheet("font-weight: bold;");
    box->setLayout(security);

    QVBoxLayout *layout = new QVBoxLayout;
    layout->addWidget(edit);
    layout->addWidget(box);
    this->setLayout(layout);
    this->setWindowTitle("Socks proxy server");
}

void Window::SendDatagram(int type, quint16 port) // method for sending data
{
    QByteArray datagram;
    QDataStream out(&datagram, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_7);

    if(type == 1) // answer for the first query
    {
        if(user->text() == "user" && passwd->text() == "password") // if password and username are default - connection without log in
            out << QString("PROXY: ") << reply->version << reply->methodes[0]; // Code: 0 (0x00)
        else
            out << QString("PROXY: ") << reply->version << reply->methodes[1]; // else Code: 2 (0x02). Need pass and username
    }
    else if(type == 2) // if pass and username are valid
        out << QString("PROXY: Connected...");
    else if(type == 3) // if pass and username are invalid
        out << QString("PROXY: Connection error");
    else if(type == 4)
        out << QString("Answer: ") << reply->message;

    socket->writeDatagram(datagram, QHostAddress::LocalHost, port);
}

void Window::ProcessData() // method for processing data from clients
{
    QByteArray datagram;
    QHostAddress adr;

    do
        {
            datagram.resize(socket->pendingDatagramSize());
            socket->readDatagram(datagram.data(), datagram.size(), &adr, &src_port);

        } while(socket->hasPendingDatagrams()); // getting data from client

    QString id;
    QDataStream in(&datagram, QIODevice::ReadOnly);
    in.setVersion(QDataStream::Qt_5_7);

    if(datagram.size() < 30) // first query from client (SOCKSv, count of methodes, methodes)
    {
        in >> id;
        in >> reply->version >> reply->count_methodes >> reply->methodes[0];
        in >> reply->methodes[1];

        edit->append("Package from " + id);
        edit->append("");
        edit->append("SOCKSv: " + QString::number(reply->version) +
                     "; Methodes: " + QString::number(reply->count_methodes));
        edit->append(" - " + QString::number(reply->methodes[0]));
        edit->append(" - " + QString::number(reply->methodes[1]));
        edit->append("---------------------------------------------------");

        SendDatagram(1, src_port);
    }
    else
    {
        in >> id;

        if( id == "Client: " || id == "Server: ") // standart package from client: SOCKSv, count of methodes, methodes,
        {                                          // dst. port, dst. ip, message
            in >> reply->version >> reply->count_methodes >> reply->methodes[0];
            in >> reply->methodes[1] >> reply->port >> reply->ip >> reply->message;


            edit->append("Package from " + id);
            edit->append("");
            edit->append("SOCKSv: " + QString::number(reply->version) +
                         "; Methodes: " + QString::number(reply->count_methodes));
            edit->append(" - " + QString::number(reply->methodes[0]));
            edit->append(" - " + QString::number(reply->methodes[1]));
            edit->append("Port: " + QString::number(reply->port) + "; IP: " +
                         reply->ip.toString());
            edit->append("Message: " + reply->message);
            edit->append("---------------------------------------------------");

            SendDatagram(4, reply->port);
        }
        else // package with username and password for authorization
            {
                username = id;
                in >> password;

                if(username == user->text() && password == passwd->text())
                    SendDatagram(2, src_port);
                else
                    SendDatagram(3, src_port);
            }
    }
}

void Window::ButtonClick()
{
    SendDatagram(1, src_port);
    SendDatagram(1, reply->port);
}
