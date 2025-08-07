#ifndef CHAT_SERVER_H
#define CHAT_SERVER_H

#include <QObject>        // 继承 QObject 以使用 Qt 的信号/槽机制
#include <QTcpServer>     // 用于监听传入连接
#include <QTcpSocket>     // 用于处理每个客户端连接
#include <QDataStream>    // 用于数据包解析
#include <QSqlDatabase>   // 包含 QSqlDatabase 头文件
#include <QSqlQuery>      // 包含 QSqlQuery 头文件
#include <QSqlError>      // 包含 QSqlError 头文件，用于错误处理
#include <QHash>          // 用于存储每个客户端的m_blockSize（同时其键代表所有客户端套接字）
#include <QJsonDocument>  // 用于 JSON 文档处理
#include <QJsonObject>    // 用于 JSON 对象处理
#include <QDebug>         // 用于调试输出
#include <QDateTime>      //

class ChatServer : public QObject {
    Q_OBJECT // 启用 Qt 的元对象系统，让类可以使用信号和槽

public:
    explicit ChatServer(QObject *parent = nullptr);
    ~ChatServer();

    // 启动服务器监听指定端口
    bool startServer(quint16 port);
    // 停止服务器监听
    void stopServer();

private slots:
    // 槽函数：当有新的客户端连接请求到来时，QTcpServer 会发出 newConnection() 信号，此槽函数响应
    void onNewConnection();

    // 槽函数：当当前客户端套接字有新数据可读时，QTcpSocket 会发出 readyRead() 信号，此槽函数响应
    void onReadyRead();

    // 槽函数：当当前客户端套接字断开连接时，QTcpSocket 会发出 disconnected() 信号，此槽函数响应
    void onDisconnected();

    // 槽函数：处理套接字发生的错误
    void onErrorOccurred(QAbstractSocket::SocketError socketError);

private:
    QTcpServer *m_tcpServer;           // 用于监听客户端连接的服务器对象
    QHash<QTcpSocket*, quint32> m_clientBlockSizes; // 存储每个客户端的数据包大小

    QSqlDatabase m_db; // 数据库连接对象

    // **新增辅助函数声明**
    // 用于获取客户端的 IP:Port 信息
    QString getPeerInfo(QTcpSocket* socket) const;

    // 用于发送通用的 JSON 响应
    void sendResponse(QTcpSocket *socket, const QJsonObject &response);

    // 用于发送错误响应
    void sendErrorResponse(QTcpSocket *socket, const QString &message, const QString &requestType);

    // 处理注册请求的逻辑
    void handleRegisterRequest(QTcpSocket* socket, const QString& username, const QString& account, const QString& password);

    // 处理登录请求的逻辑
    void handleLoginRequest(QTcpSocket* socket, const QString& account, const QString& password);

    // 处理聊天消息请求的逻辑
    void handleChatMessage(QTcpSocket* socket, const QString& account, const QString& content);
};

#endif // CHAT_SERVER_H