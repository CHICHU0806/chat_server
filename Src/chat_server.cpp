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
        // 创建消息表
        QString createMessageTableSql = "CREATE TABLE IF NOT EXISTS Messages ("
                                       "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                                       "sender_account TEXT NOT NULL,"
                                       "receiver_account TEXT,"  // NULL表示公共消息
                                       "content TEXT NOT NULL,"
                                       "message_type TEXT NOT NULL,"  // 'public' 或 'private'
                                       "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
                                       "is_read BOOLEAN DEFAULT FALSE,"
                                       "FOREIGN KEY (sender_account) REFERENCES Users(account),"
                                       "FOREIGN KEY (receiver_account) REFERENCES Users(account)"
                                       ");";

        if (!query.exec(createMessageTableSql)) {
            qCritical() << "服务器无法创建 Messages 表：" << query.lastError().text();
        } else {
            qInfo() << "服务器 Messages 表已准备好。";
        }

        // 创建用户状态表
        QString createUserStatusTableSql = "CREATE TABLE IF NOT EXISTS UserStatus ("
                                          "account TEXT PRIMARY KEY,"
                                          "last_online DATETIME DEFAULT CURRENT_TIMESTAMP,"
                                          "last_message_sync DATETIME DEFAULT CURRENT_TIMESTAMP,"
                                          "is_online BOOLEAN DEFAULT FALSE,"
                                          "FOREIGN KEY (account) REFERENCES Users(account)"
                                          ");";

        if (!query.exec(createUserStatusTableSql)) {
            qCritical() << "服务器无法创建 UserStatus 表：" << query.lastError().text();
        } else {
            qInfo() << "服务器 UserStatus 表已准备好。";
        }

        // 创建消息已读状态表（用于公共消息的已读跟踪）
        QString createMessageReadStatusTableSql = "CREATE TABLE IF NOT EXISTS MessageReadStatus ("
                                                 "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                                                 "message_id INTEGER NOT NULL,"
                                                 "user_account TEXT NOT NULL,"
                                                 "read_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
                                                 "FOREIGN KEY (message_id) REFERENCES Messages(id),"
                                                 "FOREIGN KEY (user_account) REFERENCES Users(account),"
                                                 "UNIQUE(message_id, user_account)"
                                                 ");";

        if (!query.exec(createMessageReadStatusTableSql)) {
            qCritical() << "服务器无法创建 MessageReadStatus 表：" << query.lastError().text();
        } else {
            qInfo() << "服务器 MessageReadStatus 表已准备好。";
        }

        // 创建索引以提高查询性能
        QStringList indexQueries = {
            "CREATE INDEX IF NOT EXISTS idx_messages_receiver_timestamp ON Messages(receiver_account, timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_messages_sender_timestamp ON Messages(sender_account, timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_messages_type_timestamp ON Messages(message_type, timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_user_status_last_sync ON UserStatus(last_message_sync);",
            "CREATE INDEX IF NOT EXISTS idx_message_read_status ON MessageReadStatus(message_id, user_account);"
        };

        for (const QString& indexSql : indexQueries) {
            if (!query.exec(indexSql)) {
                qWarning() << "创建索引失败：" << query.lastError().text() << "SQL:" << indexSql;
            }
        }

        qInfo() << "数据库索引创建完成。";
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
            //这里不立即 deleteLater()，依赖 onDisconnected() 槽来安全清理
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
        QString account = request["account"].toString();
        QString password = request["password"].toString();

        qInfo() << "成功解析请求来自 " << getPeerInfo(senderSocket) << "：类型=" << requestType << ", 账号=" << account << ", 密码=" << password;

        // **核心修正：使用明确的 else if 结构来处理不同类型的请求**
        if (requestType == "register") {
            QString username = request["username"].toString();
            handleRegisterRequest(senderSocket, username, account, password);
        } else if (requestType == "login") {
            handleLoginRequest(senderSocket, account, password);
        } else if (requestType == "chatMessage") {
            QString chatType = request["chatType"].toString(); // 改为 chatType
            QString targetAccount = request["targetAccount"].toString(); // 获取目标账号（私聊时使用）
            if (chatType == "private") {
                handlePrivateChatMessage(senderSocket, account, request["content"].toString(), targetAccount);
            } else if (chatType == "public"){
                handleChatMessage(senderSocket, account, request["content"].toString());
            }
        }
        else if (requestType == "updateUserInfo") {
            QString nickname = request["nickname"].toString();
            QString oldPassword = request["oldPassword"].toString();
            QString newPassword = request["newPassword"].toString();
            handleUpdateUserInfo(senderSocket, account, nickname, oldPassword, newPassword);
        }
        else if (requestType == "searchFriend") {
            QString targetAccount = request["targetAccount"].toString();
            handleSearchFriend(senderSocket, account, targetAccount);
        }
        else {
            // 未知的请求类型
            QString errorMessage = "服务器无法处理该请求类型：" + requestType;
            qWarning() << "服务器收到未知请求类型来自 " << getPeerInfo(senderSocket) << "：" << requestType;
            sendErrorResponse(senderSocket, errorMessage, requestType); // 使用辅助函数发送错误响应
        }

        m_clientBlockSizes[senderSocket] = 0; // 处理完一个完整的数据包后，重置该客户端的 m_blockSize
    }
}


// 槽函数：当当前客户端套接字断开连接时被调用
void ChatServer::onDisconnected() {
    QTcpSocket* senderSocket = qobject_cast<QTcpSocket*>(sender());
    if (!senderSocket) {
        qWarning() << "onDisconnected: 无法获取发送信号的套接字！";
        return;
    }

    // 清理账号映射
    if (m_socketToAccount.contains(senderSocket)) {
        QString account = m_socketToAccount.value(senderSocket);

        // 更新用户离线状态
        updateUserOnlineStatus(account, false);

        m_socketToAccount.remove(senderSocket);
        qInfo() << "用户 " << account << " 已下线";
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

    //检查昵称是否重复
    QSqlQuery checkUsernameQuery(m_db);
    checkUsernameQuery.prepare("SELECT username FROM Users WHERE username = :username");
    checkUsernameQuery.bindValue(":username", username);

    if (checkUsernameQuery.exec() && checkUsernameQuery.next()) {
        response["status"] = "error";
        response["message"] = "注册失败：昵称 '" + username + "' 已存在。";
        sendResponse(socket, response);
        qWarning() << "注册失败：昵称重复：" << username;
        return;
    }

    //检查账号是否重复
    QSqlQuery checkQuery(m_db);
    checkQuery.prepare("SELECT account FROM Users WHERE account = :account");
    checkQuery.bindValue(":account", account);

    if (checkQuery.exec() && checkQuery.next()) {
        response["status"] = "error";
        response["message"] = "注册失败：账号 '" + account + "' 已存在。";
        qWarning() << "注册失败：账号重复：" << account;
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

        // 登录成功，初始化用户状态
        initializeUserStatus(account);

        response["status"] = "success";
        response["message"] = "登录成功";
        response["username"] = username;
        response["account"] = account;

        // 将套接字与账号关联
        m_socketToAccount.insert(socket, account);

        // 推送离线消息
        pushOfflineMessages(socket, account);

        qInfo() << "登录成功：" << username << "(" << account << ") 来自 [" << getPeerInfo(socket) << "]";
    }else {
        response["status"] = "error";
        response["message"] = "登录失败：账号或密码不正确。";
        qWarning() << "用户登录失败：账号=" << account << ", 密码=" << password << " from " << getPeerInfo(socket);
    }
    sendResponse(socket, response);
    qInfo() << "已发送登录响应给 [" << getPeerInfo(socket) << "]";
}

// **辅助函数：处理聊天消息请求的逻辑**
void ChatServer::handleChatMessage(QTcpSocket* socket, const QString& account, const QString& content) {
    // 验证输入数据
    if (account.isEmpty() || content.isEmpty()) {
        QJsonObject response;
        response["type"] = "chatMessage";
        response["status"] = "error";
        response["message"] = "聊天消息发送失败：账号和消息内容不能为空。";
        response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
        sendResponse(socket, response);
        qWarning() << "聊天消息发送失败：输入数据不完整";
        return;
    }

    // 验证用户是否存在
    QSqlQuery checkQuery(m_db);
    checkQuery.prepare("SELECT username FROM Users WHERE account = :account COLLATE NOCASE");
    checkQuery.bindValue(":account", account);

    if (!checkQuery.exec() || !checkQuery.next()) {
        QJsonObject response;
        response["type"] = "chatMessage";
        response["status"] = "error";
        response["message"] = "聊天消息发送失败：用户不存在。";
        response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
        sendResponse(socket, response);
        qWarning() << "聊天消息发送失败：用户不存在：" << account;
        return;
    }

    QString username = checkQuery.value("username").toString();
    qInfo() << "收到聊天消息：来自用户" << username << "(" << account << ")的消息：" << content;

    // 保存公共消息到数据库
    saveMessageToDatabase(account, "", content, "public");

    // 构建广播消息
    QJsonObject broadcastMessage;
    broadcastMessage["type"] = "chatMessage";
    broadcastMessage["status"] = "broadcast";
    broadcastMessage["sender"] = account;
    broadcastMessage["username"] = username;
    broadcastMessage["content"] = content;
    broadcastMessage["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);

    // 向所有在线客户端广播消息（包括发送者）
    int broadcastCount = 0;
    for (auto it = m_clientBlockSizes.begin(); it != m_clientBlockSizes.end(); ++it) {
        QTcpSocket* clientSocket = it.key();
        if (clientSocket && clientSocket->state() == QAbstractSocket::ConnectedState) {
            sendResponse(clientSocket, broadcastMessage);
            broadcastCount++;
        }
    }

    // 向发送者发送确认响应
    QJsonObject confirmResponse;
    confirmResponse["type"] = "chatMessage";
    confirmResponse["status"] = "success";
    confirmResponse["message"] = "消息发送成功，已广播给 " + QString::number(broadcastCount) + " 个在线用户";
    confirmResponse["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    sendResponse(socket, confirmResponse);

    qInfo() << "聊天消息已广播给" << broadcastCount << "个在线客户端，来自用户：" << username << "(" << account << ")";
}

// **辅助函数：处理私聊消息请求的逻辑**
void ChatServer::handlePrivateChatMessage(QTcpSocket* socket, const QString& senderAccount, const QString& content, const QString& targetAccount) {
    QJsonObject response;
    response["type"] = "chatMessage";

    // 验证输入数据
    if (senderAccount.isEmpty() || content.isEmpty() || targetAccount.isEmpty()) {
        response["status"] = "error";
        response["message"] = "私聊消息发送失败：发送者账号、接收者账号和消息内容不能为空。";
        response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
        sendResponse(socket, response);
        qWarning() << "私聊消息发送失败：输入数据不完整";
        return;
    }

    // 验证发送者是否存在
    QSqlQuery senderQuery(m_db);
    senderQuery.prepare("SELECT username FROM Users WHERE account = :account COLLATE NOCASE");
    senderQuery.bindValue(":account", senderAccount);

    if (!senderQuery.exec() || !senderQuery.next()) {
        response["status"] = "error";
        response["message"] = "私聊消息发送失败：发送者不存在。";
        response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
        sendResponse(socket, response);
        qWarning() << "私聊消息发送失败：发送者不存在：" << senderAccount;
        return;
    }

    QString senderUsername = senderQuery.value("username").toString();

    // 验证接收者是否存在
    QSqlQuery targetQuery(m_db);
    targetQuery.prepare("SELECT username FROM Users WHERE account = :account COLLATE NOCASE");
    targetQuery.bindValue(":account", targetAccount);

    if (!targetQuery.exec() || !targetQuery.next()) {
        response["status"] = "error";
        response["message"] = "私聊消息发送失败：接收者不存在。";
        response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
        sendResponse(socket, response);
        qWarning() << "私聊消息发送失败：接收者不存在：" << targetAccount;
        return;
    }

    QString targetUsername = targetQuery.value("username").toString();

    // 保存私聊消息到数据库
    saveMessageToDatabase(senderAccount, targetAccount, content, "private");

    // 构建私聊消息
    QJsonObject privateMessage;
    privateMessage["type"] = "chatMessage";
    privateMessage["status"] = "private";
    privateMessage["sender"] = senderAccount;
    privateMessage["username"] = senderUsername;
    privateMessage["target"] = targetAccount;
    privateMessage["targetUsername"] = targetUsername;
    privateMessage["content"] = content;
    privateMessage["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);

    // 找到目标用户的套接字并发送消息
    bool targetFound = false;
    for (auto it = m_clientBlockSizes.begin(); it != m_clientBlockSizes.end(); ++it) {
        QTcpSocket* clientSocket = it.key();
        if (clientSocket && clientSocket->state() == QAbstractSocket::ConnectedState) {
            // 这里需要一个方法来识别套接字对应的账号，暂时发送给所有在线用户
            // 实际应用中需要维护套接字到账号的映射
            sendResponse(clientSocket, privateMessage);
            targetFound = true;
        }
    }

    // 向发送者确认消息状态
    response["status"] = targetFound ? "success" : "error";
    response["message"] = targetFound ?
        "私聊消息已发送给 " + targetUsername + "。" :
        "私聊消息发送失败：目标用户不在线。";
    response["timestamp"] = privateMessage["timestamp"];
    sendResponse(socket, response);

    qInfo() << "私聊消息处理完成，从" << senderUsername << "(" << senderAccount << ")到" << targetUsername << "(" << targetAccount << ")";
}

// **辅助函数：处理用户信息更新请求的逻辑**
void ChatServer::handleUpdateUserInfo(QTcpSocket* socket, const QString& account, const QString& nickname, const QString& oldPassword, const QString& newPassword) {
    QJsonObject response;
    response["type"] = "updateUserInfo";
    response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);

    // 验证输入数据
    if (account.isEmpty() || nickname.isEmpty() || oldPassword.isEmpty()) {
        response["status"] = "error";
        response["message"] = "用户信息更新失败：账号、昵称和原密码不能为空。";
        sendResponse(socket, response);
        qWarning() << "用户信息更新失败：输入数据不完整";
        return;
    }

    // 验证用户身份（检查账号和原密码）
    QSqlQuery authQuery(m_db);
    authQuery.prepare("SELECT username FROM Users WHERE account = :account AND password = :password COLLATE NOCASE");
    authQuery.bindValue(":account", account);
    authQuery.bindValue(":password", oldPassword);

    if (!authQuery.exec() || !authQuery.next()) {
        response["status"] = "error";
        response["message"] = "用户信息更新失败：原密码不正确。";
        sendResponse(socket, response);
        qWarning() << "用户信息更新失败：身份验证失败：" << account;
        return;
    }

    QString currentUsername = authQuery.value("username").toString();

    // 开始更新用户信息
    QSqlQuery updateQuery(m_db);
    QString updateSql;

    if (newPassword.isEmpty()) {
        // 只更新昵称
        updateSql = "UPDATE Users SET username = :nickname WHERE account = :account";
        updateQuery.prepare(updateSql);
        updateQuery.bindValue(":nickname", nickname);
        updateQuery.bindValue(":account", account);
    } else {
        // 同时更新昵称和密码
        updateSql = "UPDATE Users SET username = :nickname, password = :newPassword WHERE account = :account";
        updateQuery.prepare(updateSql);
        updateQuery.bindValue(":nickname", nickname);
        updateQuery.bindValue(":newPassword", newPassword);
        updateQuery.bindValue(":account", account);
    }

    if (updateQuery.exec()) {
        response["status"] = "success";
        if (newPassword.isEmpty()) {
            response["message"] = "昵称更新成功！新昵称：" + nickname;
            qInfo() << "用户昵称更新成功：账号=" << account << ", 原昵称=" << currentUsername << ", 新昵称=" << nickname;
        } else {
            response["message"] = "用户信息更新成功！新昵称：" + nickname + "，密码已更新。";
            qInfo() << "用户信息更新成功：账号=" << account << ", 原昵称=" << currentUsername << ", 新昵称=" << nickname << ", 密码已更新";
        }
        response["username"] = nickname;
        response["account"] = account;
    } else {
        response["status"] = "error";
        response["message"] = "用户信息更新失败：数据库错误 - " + updateQuery.lastError().text();
        qCritical() << "用户信息更新失败：数据库错误：" << updateQuery.lastError().text();
    }

    sendResponse(socket, response);
    qInfo() << "已发送用户信息更新响应给 [" << getPeerInfo(socket) << "]";
}

// **辅助函数：处理搜索好友请求的逻辑**
void ChatServer::handleSearchFriend(QTcpSocket* socket, const QString& account, const QString& targetAccount) {
    QJsonObject response;
    response["type"] = "searchFriend";
    response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);

    // 检查是否搜索自己
    if (account == targetAccount) {
        response["status"] = "error";
        response["message"] = "不能添加自己为好友";
        sendResponse(socket, response);
        qWarning() << "搜索好友失败：用户尝试搜索自己：" << account;
        return;
    }

    // 验证当前用户是否存在
    QSqlQuery currentUserQuery(m_db);
    currentUserQuery.prepare("SELECT username FROM Users WHERE account = :account COLLATE NOCASE");
    currentUserQuery.bindValue(":account", account);

    if (!currentUserQuery.exec() || !currentUserQuery.next()) {
        response["status"] = "error";
        response["message"] = "搜索失败：当前用户不存在。";
        sendResponse(socket, response);
        qWarning() << "搜索好友失败：当前用户不存在：" << account;
        return;
    }

    // 搜索目标用户
    QSqlQuery targetUserQuery(m_db);
    targetUserQuery.prepare("SELECT username FROM Users WHERE account = :targetAccount COLLATE NOCASE");
    targetUserQuery.bindValue(":targetAccount", targetAccount);

    if (!targetUserQuery.exec() || !targetUserQuery.next()) {
        response["status"] = "error";
        response["message"] = "用户不存在";
        sendResponse(socket, response);
        qInfo() << "搜索好友：用户不存在 - 搜索者:" << account << ", 目标:" << targetAccount;
        return;
    }

    QString targetUsername = targetUserQuery.value("username").toString();

    // 检查目标用户是否在线
    bool isOnline = m_socketToAccount.values().contains(targetAccount);
    for (auto it = m_socketToAccount.begin(); it != m_socketToAccount.end(); ++it) {
        QTcpSocket* clientSocket = it.key();
        QString clientAccount = it.value();

        if (clientSocket &&
            clientSocket->state() == QAbstractSocket::ConnectedState &&
            clientAccount == targetAccount) {
            isOnline = true;
            break;
        }
    }

    // 构建成功响应
    response["status"] = "success";
    response["message"] = "用户找到";

    QJsonObject userInfo;
    userInfo["account"] = targetAccount;
    userInfo["username"] = targetUsername;
    userInfo["isOnline"] = isOnline;
    //TODO:头像相关内容
    response["userInfo"] = userInfo;

    sendResponse(socket, response);
    qInfo() << "搜索好友成功：搜索者=" << account << ", 找到用户=" << targetUsername << "(" << targetAccount << ")";
}

// 保存消息到数据库
void ChatServer::saveMessageToDatabase(const QString& senderAccount, const QString& receiverAccount,
                                     const QString& content, const QString& messageType) {
    QSqlQuery insertQuery(m_db);
    insertQuery.prepare("INSERT INTO Messages (sender_account, receiver_account, content, message_type, timestamp) "
                       "VALUES (:sender, :receiver, :content, :type, :timestamp)");

    insertQuery.bindValue(":sender", senderAccount);
    insertQuery.bindValue(":receiver", receiverAccount.isEmpty() ? QVariant() : receiverAccount);
    insertQuery.bindValue(":content", content);
    insertQuery.bindValue(":type", messageType);
    insertQuery.bindValue(":timestamp", QDateTime::currentDateTime().toString(Qt::ISODate));

    if (!insertQuery.exec()) {
        qCritical() << "保存消息到数据库失败：" << insertQuery.lastError().text();
    } else {
        qDebug() << "消息已保存到数据库：" << messageType << "类型，发送者：" << senderAccount;
    }
}

// 更新用户在线状态
void ChatServer::updateUserOnlineStatus(const QString& account, bool isOnline) {
    QSqlQuery updateQuery(m_db);

    if (isOnline) {
        // 用户上线
        updateQuery.prepare("INSERT OR REPLACE INTO UserStatus (account, last_online, is_online) "
                           "VALUES (:account, :timestamp, :online)");
    } else {
        // 用户下线
        updateQuery.prepare("UPDATE UserStatus SET last_online = :timestamp, is_online = :online "
                           "WHERE account = :account");
    }

    updateQuery.bindValue(":account", account);
    updateQuery.bindValue(":timestamp", QDateTime::currentDateTime().toString(Qt::ISODate));
    updateQuery.bindValue(":online", isOnline);

    if (!updateQuery.exec()) {
        qWarning() << "更新用户状态失败：" << updateQuery.lastError().text();
    }
}

// 更新用户最后同步时间
void ChatServer::updateUserLastSync(const QString& account) {
    QSqlQuery updateQuery(m_db);
    updateQuery.prepare("UPDATE UserStatus SET last_message_sync = :timestamp WHERE account = :account");
    updateQuery.bindValue(":account", account);
    updateQuery.bindValue(":timestamp", QDateTime::currentDateTime().toString(Qt::ISODate));

    if (!updateQuery.exec()) {
        qWarning() << "更新用户同步时间失败：" << updateQuery.lastError().text();
    }
}

// 推送离线消息
void ChatServer::pushOfflineMessages(QTcpSocket* socket, const QString& account) {
    // 获取用户最后同步时间
    QSqlQuery syncQuery(m_db);
    syncQuery.prepare("SELECT last_message_sync FROM UserStatus WHERE account = :account");
    syncQuery.bindValue(":account", account);

    QString lastSyncTime;
    if (syncQuery.exec() && syncQuery.next()) {
        lastSyncTime = syncQuery.value("last_message_sync").toString();
    } else {
        // 如果没有同步记录，使用很早的时间来获取所有消息
        lastSyncTime = "2000-01-01T00:00:00";
    }

    // 查询离线期间的公共消息
    QSqlQuery publicMsgQuery(m_db);
    publicMsgQuery.prepare("SELECT sender_account, content, timestamp "
                          "FROM Messages "
                          "WHERE message_type = 'public' AND timestamp > :lastSync "
                          "ORDER BY timestamp ASC");
    publicMsgQuery.bindValue(":lastSync", lastSyncTime);

    int publicMsgCount = 0;
    if (publicMsgQuery.exec()) {
        while (publicMsgQuery.next()) {
            QString senderAccount = publicMsgQuery.value("sender_account").toString();
            QString content = publicMsgQuery.value("content").toString();
            QString timestamp = publicMsgQuery.value("timestamp").toString();

            // 获取发送者用户名
            QSqlQuery senderQuery(m_db);
            senderQuery.prepare("SELECT username FROM Users WHERE account = :account");
            senderQuery.bindValue(":account", senderAccount);

            QString senderUsername = senderAccount; // 默认值
            if (senderQuery.exec() && senderQuery.next()) {
                senderUsername = senderQuery.value("username").toString();
            }

            // 构建离线消息
            QJsonObject offlineMessage;
            offlineMessage["type"] = "chatMessage";
            offlineMessage["status"] = "offline_broadcast";
            offlineMessage["sender"] = senderAccount;
            offlineMessage["username"] = senderUsername;
            offlineMessage["content"] = content;
            offlineMessage["timestamp"] = timestamp;

            sendResponse(socket, offlineMessage);
            publicMsgCount++;
        }
    }

    // 查询离线期间的私聊消息（接收的）
    QSqlQuery privateMsgQuery(m_db);
    privateMsgQuery.prepare("SELECT sender_account, content, timestamp "
                           "FROM Messages "
                           "WHERE message_type = 'private' AND receiver_account = :account "
                           "AND timestamp > :lastSync AND is_read = FALSE "
                           "ORDER BY timestamp ASC");
    privateMsgQuery.bindValue(":account", account);
    privateMsgQuery.bindValue(":lastSync", lastSyncTime);

    int privateMsgCount = 0;
    if (privateMsgQuery.exec()) {
        while (privateMsgQuery.next()) {
            QString senderAccount = privateMsgQuery.value("sender_account").toString();
            QString content = privateMsgQuery.value("content").toString();
            QString timestamp = privateMsgQuery.value("timestamp").toString();

            // 获取发送者用户名
            QSqlQuery senderQuery(m_db);
            senderQuery.prepare("SELECT username FROM Users WHERE account = :account");
            senderQuery.bindValue(":account", senderAccount);

            QString senderUsername = senderAccount;
            if (senderQuery.exec() && senderQuery.next()) {
                senderUsername = senderQuery.value("username").toString();
            }

            // 构建离线私聊消息
            QJsonObject offlineMessage;
            offlineMessage["type"] = "chatMessage";
            offlineMessage["status"] = "offline_private";
            offlineMessage["sender"] = senderAccount;
            offlineMessage["username"] = senderUsername;
            offlineMessage["target"] = account;
            offlineMessage["content"] = content;
            offlineMessage["timestamp"] = timestamp;

            sendResponse(socket, offlineMessage);
            privateMsgCount++;
        }
    }

    // 更新用户最后同步时间
    updateUserLastSync(account);

    if (publicMsgCount > 0 || privateMsgCount > 0) {
        qInfo() << "已推送离线消息给用户" << account << "：公共消息" << publicMsgCount << "条，私聊消息" << privateMsgCount << "条";
    }
}

// 初始化用户状态
void ChatServer::initializeUserStatus(const QString& account) {
    QSqlQuery checkQuery(m_db);
    checkQuery.prepare("SELECT account FROM UserStatus WHERE account = :account");
    checkQuery.bindValue(":account", account);

    if (checkQuery.exec() && !checkQuery.next()) {
        // 用户状态记录不存在，创建新记录
        QSqlQuery insertQuery(m_db);
        insertQuery.prepare("INSERT INTO UserStatus (account, last_online, last_message_sync, is_online) "
                           "VALUES (:account, :timestamp, :timestamp, :online)");
        insertQuery.bindValue(":account", account);
        insertQuery.bindValue(":timestamp", QDateTime::currentDateTime().toString(Qt::ISODate));
        insertQuery.bindValue(":online", true);

        if (!insertQuery.exec()) {
            qWarning() << "初始化用户状态失败：" << insertQuery.lastError().text();
        }
    } else {
        // 更新现有记录
        updateUserOnlineStatus(account, true);
    }
}