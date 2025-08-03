// chat_server.cpp

#include "chat_server.h" // 包含自己的头文件
#include <QHostAddress>    // 用于绑定IP地址
#include <QDebug>          // 用于在命令行输出调试和信息
#include <QJsonDocument>   // 用于解析JSON
#include <QJsonObject>     // 用于解析JSON
#include <QSqlError>       // 确保包含
#include <QDir>            // 用于处理文件路径和目录创建
#include <QCoreApplication> // 用于获取应用程序路径

// 构造函数：初始化成员变量，连接信号和槽
ChatServer::ChatServer(QObject *parent)
    : QObject(parent),
      m_tcpServer(new QTcpServer(this)) // 初始化 m_tcpServer
{
    // **数据库连接设置**
    m_db = QSqlDatabase::addDatabase("QSQLITE"); // 添加 SQLite 驱动

    // 获取应用程序可执行文件所在的目录
    QString appDirPath = QCoreApplication::applicationDirPath();

    // 构建数据库文件路径：假设数据库在项目根目录下的 Database 文件夹中
    // 从可执行文件目录向上导航一级 (..)，再进入 Database 文件夹
    QString databaseFolderPath = QDir::cleanPath(appDirPath + QDir::separator() + ".." + QDir::separator() + "Database");

    QDir dir(databaseFolderPath);
    if (!dir.exists()) {
        if (!dir.mkpath(".")) { // 尝试创建目录
            qCritical() << "服务器无法创建指定的数据库目录：" << databaseFolderPath;
        } else {
            qInfo() << "已创建指定的服务器数据库目录：" << databaseFolderPath;
        }
    }

    QString dbPath = databaseFolderPath + QDir::separator() + "user_data.db";
    m_db.setDatabaseName(dbPath);

    if (!m_db.open()) {
        qCritical() << "服务器数据库连接失败：" << m_db.lastError().text();
    } else {
        qInfo() << "服务器数据库连接成功，文件：" << dbPath;

        QSqlQuery query(m_db);
        QString createTableSql = "CREATE TABLE IF NOT EXISTS Users ("
                                 "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                                 "username TEXT UNIQUE NOT NULL,"
                                 "account TEXT UNIQUE NOT NULL,"
                                 "password TEXT NOT NULL"
                                 ");";
        if (!query.exec(createTableSql)) {
            qCritical() << "服务器无法创建 Users 表：" << query.lastError().text();
        } else {
            qInfo() << "服务器 Users 表已准备好。";
        }
    }
    //数据库设置结束

    // 将 m_tcpServer 发出的 newConnection() 信号连接到 ChatServer 的 onNewConnection() 槽函数
    connect(m_tcpServer, &QTcpServer::newConnection, this, &ChatServer::onNewConnection);
    qInfo() << "ChatServer initialized.";
}

// 析构函数：清理资源
ChatServer::~ChatServer() {
    stopServer(); // 确保在 ChatServer 对象销毁前，服务器已经停止监听
    if (m_db.isOpen()) {
        m_db.close();
        qInfo() << "服务器数据库已关闭。";
    }
    qInfo() << "ChatServer destroyed.";
}

// 启动服务器监听
bool ChatServer::startServer(quint16 port) {
    if (!m_tcpServer->listen(QHostAddress::Any, port)) {
        qCritical() << "无法启动服务器：" << m_tcpServer->errorString();
        return false;
    }
    qInfo() << "服务器正在监听端口" << port;
    qInfo() << "聊天服务器已在端口" << port << "上启动。等待客户端连接...";
    return true;
}

// 停止服务器监听
void ChatServer::stopServer() {
    if (m_tcpServer->isListening()) {
        m_tcpServer->close(); // 关闭监听套接字
        qInfo() << "服务器停止监听。";
    }

    // 遍历所有已连接的客户端套接字，并进行清理
    QList<QTcpSocket*> clientSocketsToClose = m_clientBlockSizes.keys();
    qInfo() << "正在关闭所有 " << clientSocketsToClose.size() << " 个活跃客户端连接...";

    for (QTcpSocket* clientSocket : clientSocketsToClose) {
        if (clientSocket->state() == QAbstractSocket::ConnectedState) {
            clientSocket->disconnectFromHost(); // 向客户端发送断开连接请求
            // 这里不立即 deleteLater()，依赖 onDisconnected() 槽来安全清理
        }
    }
    // 理论上所有客户端都会触发 onDisconnected，导致 m_clientBlockSizes 被清空
    // 但为保险起见，可以在这里显式清空一次，或者只依赖 onDisconnected
    m_clientBlockSizes.clear(); // 清空 QHash
    qInfo() << "所有客户端连接清理完毕。";
}

// 槽函数：处理新的客户端连接
void ChatServer::onNewConnection() {
    QTcpSocket* newClientSocket = m_tcpServer->nextPendingConnection();
    if (!newClientSocket) {
        qCritical() << "服务器获取新的客户端连接失败！";
        return;
    }

    m_clientBlockSizes.insert(newClientSocket, 0); // 初始化为0，表示等待读取新数据包的长度

    connect(newClientSocket, &QTcpSocket::readyRead, this, &ChatServer::onReadyRead);
    connect(newClientSocket, &QTcpSocket::disconnected, this, &ChatServer::onDisconnected);
    connect(newClientSocket, &QTcpSocket::errorOccurred, this, &ChatServer::onErrorOccurred);

    qInfo() << "新连接来自：" << getPeerInfo(newClientSocket) << "。当前在线客户端数量：" << m_clientBlockSizes.size();
}

// 槽函数：当当前客户端套接字有数据可读时被调用 (修正版)
void ChatServer::onReadyRead() {
    QTcpSocket* senderSocket = qobject_cast<QTcpSocket*>(sender());
    if (!senderSocket) {
        qWarning() << "onReadyRead: 无法获取发送信号的套接字！";
        return;
    }

    QDataStream in(senderSocket);
    in.setVersion(QDataStream::Qt_6_0);

    quint32 currentBlockSize = m_clientBlockSizes.value(senderSocket);

    for (;;) {
        if (currentBlockSize == 0) {
            if (senderSocket->bytesAvailable() < (qint64)sizeof(quint32)) {
                return; // 数据不足以读取完整的数据包长度，等待更多数据
            }
            in >> currentBlockSize;
            qDebug() << "DEBUG (" << getPeerInfo(senderSocket) << "): 读取到数据包的预期总长度 (currentBlockSize):" << currentBlockSize;
            m_clientBlockSizes[senderSocket] = currentBlockSize;
        }

        if (senderSocket->bytesAvailable() < currentBlockSize) {
            return; // 数据不足以读取完整的数据包，等待更多数据
        }

        QByteArray jsonData;
        in >> jsonData;

        qDebug() << "DEBUG (" << getPeerInfo(senderSocket) << "): QDataStream 成功读取到 JSON 数据块。大小:" << jsonData.size();
        qDebug() << "DEBUG (" << getPeerInfo(senderSocket) << "): 原始 JSON 数据 (Hex):" << jsonData.toHex();
        qDebug() << "DEBUG (" << getPeerInfo(senderSocket) << "): 原始 JSON 数据 (UTF8):" << QString::fromUtf8(jsonData);

        QJsonDocument doc = QJsonDocument::fromJson(jsonData);
        if (doc.isNull() || !doc.isObject()) {
            qWarning() << "无法解析传入的 JSON 数据来自 " << getPeerInfo(senderSocket) << "。原始数据 (Hex):" << jsonData.toHex();
            sendErrorResponse(senderSocket, "无效的请求格式。", "unknown"); // 使用辅助函数发送错误响应
            m_clientBlockSizes[senderSocket] = 0;
            break;
        }

        QJsonObject request = doc.object();
        QString requestType = request["type"].toString();
        QString username = request["username"].toString();
        QString account = request["account"].toString();
        QString password = request["password"].toString();

        qInfo() << "成功解析请求来自 " << getPeerInfo(senderSocket) << "：类型=" << requestType << ", 账号=" << account << ", 密码=" << password;

        // **核心修正：使用明确的 else if 结构来处理不同类型的请求**
        if (requestType == "register") {
            handleRegisterRequest(senderSocket, username, account, password);
        } else if (requestType == "login") {
            handleLoginRequest(senderSocket, account, password);
        } else if (requestType == "chatMessage") {
            // TODO: 在这里实现 handleChatMessage 逻辑
            QString content = request["content"].toString();
            qInfo() << "收到聊天消息请求：来自 " << account << " 的消息： " << content;
            // 示例：回复一个接收成功的消息
            QJsonObject response;
            response["type"] = "chatMessage";
            response["status"] = "success";
            response["message"] = "服务器已接收消息。";
            sendResponse(senderSocket, response);
            qInfo() << "已发送聊天消息接收响应给 [" << getPeerInfo(senderSocket) << "]";
        }
        else {
            // 未知的请求类型
            QString errorMessage = "服务器无法处理该请求类型：" + requestType;
            qWarning() << "服务器收到未知请求类型来自 " << getPeerInfo(senderSocket) << "：" << requestType;
            sendErrorResponse(senderSocket, errorMessage, requestType); // 使用辅助函数发送错误响应
        }

        m_clientBlockSizes[senderSocket] = 0; // 处理完一个完整的数据包后，重置该客户端的 m_blockSize

        // 如果 socket 还有数据，继续循环处理下一个包
    }
}


// 槽函数：当当前客户端套接字断开连接时被调用
void ChatServer::onDisconnected() {
    QTcpSocket* senderSocket = qobject_cast<QTcpSocket*>(sender());
    if (!senderSocket) {
        qWarning() << "onDisconnected: 无法获取发送信号的套接字！";
        return;
    }

    qInfo() << "客户端 [" << getPeerInfo(senderSocket) << "] 已断开连接。";

    if (m_clientBlockSizes.contains(senderSocket)) {
        m_clientBlockSizes.remove(senderSocket);
        qInfo() << "已从客户端列表中移除 [" << getPeerInfo(senderSocket) << "]。当前在线客户端数量：" << m_clientBlockSizes.size();
    } else {
        qWarning() << "onDisconnected: 尝试移除一个不在列表中的套接字！[" << getPeerInfo(senderSocket) << "]";
    }

    senderSocket->deleteLater(); // 安全地删除 QTcpSocket 对象。
}

// 槽函数：处理套接字发生的错误
void ChatServer::onErrorOccurred(QAbstractSocket::SocketError socketError) {
    QTcpSocket* senderSocket = qobject_cast<QTcpSocket*>(sender());
    if (!senderSocket) {
        qWarning() << "onErrorOccurred: 无法获取发送信号的套接字！";
        return;
    }

    qCritical() << "客户端 [" << getPeerInfo(senderSocket) << "] 发生套接字错误："
                << senderSocket->errorString() << " (错误码：" << socketError << ")";
}


// **辅助函数：获取客户端的 IP:Port 信息**
QString ChatServer::getPeerInfo(QTcpSocket* socket) const {
    if (socket) {
        return socket->peerAddress().toString() + ":" + QString::number(socket->peerPort());
    }
    return "未知客户端";
}

// **辅助函数：发送通用的 JSON 响应**
void ChatServer::sendResponse(QTcpSocket *socket, const QJsonObject &response) {
    if (!socket || socket->state() != QAbstractSocket::ConnectedState) {
        qWarning() << "sendResponse: 套接字未连接或无效，无法发送响应。";
        return;
    }

    QByteArray jsonData = QJsonDocument(response).toJson(QJsonDocument::Compact);
    QByteArray dataBlock;
    QDataStream out(&dataBlock, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_6_0);
    out << (quint32)0; // 预留总长度位置
    out << jsonData;   // 写入实际 JSON 数据

    out.device()->seek(0);
    out << (quint32)(dataBlock.size() - sizeof(quint32)); // 写入真正的总长度

    qDebug() << "DEBUG (Server to " << getPeerInfo(socket) << "): 发送响应数据包总大小:" << dataBlock.size();
    qDebug() << "DEBUG (Server to " << getPeerInfo(socket) << "): outer quint32 value being written:" << (quint32)(dataBlock.size() - sizeof(quint32));
    qDebug() << "DEBUG (Server to " << getPeerInfo(socket) << "): 发送响应数据包内容 (Hex):" << dataBlock.toHex();

    socket->write(dataBlock);
    socket->flush();
}

// **辅助函数：发送错误响应**
void ChatServer::sendErrorResponse(QTcpSocket *socket, const QString &message, const QString &requestType) {
    QJsonObject response;
    response["type"] = requestType; // 错误响应也带上原请求类型，方便客户端识别
    response["status"] = "error";
    response["message"] = message;
    sendResponse(socket, response);
    qInfo() << "已发送错误响应给 [" << getPeerInfo(socket) << "] (类型: " << requestType << "): " << message;
}

// **辅助函数：处理注册请求的逻辑**
void ChatServer::handleRegisterRequest(QTcpSocket* socket, const QString& username, const QString& account, const QString& password) {
    QJsonObject response;
    response["type"] = "register";

    // 验证输入数据
    if (account.isEmpty() || password.isEmpty() || username.isEmpty()) {
        response["status"] = "error";
        response["message"] = "注册失败：账号、密码和昵称不能为空。";
        sendResponse(socket, response);
        qWarning() << "注册失败：输入数据不完整";
        return;
    }

    QSqlQuery checkQuery(m_db);
    checkQuery.prepare("SELECT account FROM Users WHERE account = :account");
    checkQuery.bindValue(":account", account);

    if (checkQuery.exec() && checkQuery.next()) {
        response["status"] = "error";
        response["message"] = "注册失败：用户名 '" + account + "' 已存在。";
        qWarning() << "注册失败：用户名重复：" << account;
    } else {
        QSqlQuery insertQuery(m_db);
        insertQuery.prepare("INSERT INTO Users (username, account, password) VALUES (:username, :account, :password)");
        insertQuery.bindValue(":username", username);
        insertQuery.bindValue(":account", account);
        insertQuery.bindValue(":password", password);

        if (insertQuery.exec()) {
            response["status"] = "success";
            response["message"] = "注册成功！欢迎 " + username + "！";
            response["username"] = username;
            qInfo() << "新用户注册成功：账号=" << account << ", 昵称=" << username;
        } else {
            response["status"] = "error";
            response["message"] = "注册失败：数据库错误 - " + insertQuery.lastError().text();
            qCritical() << "注册失败：数据库错误：" << insertQuery.lastError().text();
        }
    }
    sendResponse(socket, response);
    qInfo() << "已发送注册响应给 [" << getPeerInfo(socket) << "]";
}

// **辅助函数：处理登录请求的逻辑**
void ChatServer::handleLoginRequest(QTcpSocket* socket, const QString& account, const QString& password) {
    QJsonObject response;
    response["type"] = "login";

    QSqlQuery query(m_db);
    query.prepare("SELECT username FROM Users WHERE account = :account AND password = :password");
    query.bindValue(":account", account);
    query.bindValue(":password", password);

    if (query.exec() && query.next()) {
        QString username = query.value("username").toString();
        response["status"] = "success";
        response["message"] = "登录成功！欢迎 " + username + "！";
        response["username"] = username;
        qInfo() << "用户登录成功：账号=" << account << ", 昵称=" << username << " from " << getPeerInfo(socket);
    } else {
        response["status"] = "error";
        response["message"] = "登录失败：账号或密码不正确。";
        qWarning() << "用户登录失败：账号=" << account << ", 密码=" << password << " from " << getPeerInfo(socket);
    }
    sendResponse(socket, response);
    qInfo() << "已发送登录响应给 [" << getPeerInfo(socket) << "]";
}