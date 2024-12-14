#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <queue>
#include <cstdint>
#include <ifaddrs.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <chrono>
#include <thread>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <math.h>
#include <algorithm>
#include <netinet/tcp.h>

#define KEYFILE_SIZE 512   // 密钥文件长度,单位字节
#define PACKETHEAD_SIZE 12 // 包头长度,单位字节

// #define INIT_RSVP_REQUEST_LIST                                                                                             \
//     {                                                                                                                      \
//         {"PC4", "PC6", 3000, 50000, 2500, 0.2, 0, false, true}, { "PC3", "PC7", 10000, 40000, 5000, 0.6, 0, false, true } \
//     } // 初始RSVP请求队列,格式为{{源节点名,目的节点名,发送数据包数目,发送时间ms,令牌桶深度包数目,发送速率占比,链路服务速率，激活标志，密钥充足标志}}//注意此时令牌桶深度数目>100

#define INIT_RSVP_REQUEST_LIST                                                                                             \
    {                                                                                                                      \
        {"PC4", "PC6", 6500, 45000, 2500, 0.45, 0, false, true}, { "PC3", "PC7", 6500, 45000, 2500, 0.68, 0, false, true } \
    } // 初始RSVP请求队列,格式为{{源节点名,目的节点名,发送数据包数目,发送时间ms,令牌桶深度包数目,发送速率占比,链路服务速率，激活标志，密钥充足标志}}//注意此时令牌桶深度数目>100

#define DATA_COLLECT_INTERVAL 500 // 数据收集间隔，单位ms
#define DATA_COLLECT_TIME 0       // 数据收集开始时间，单位ms

#define KEYRELAY_PORT 23000 // 数据包通信端口

#define KEYRELAY_PACKET 0   // 中继数据包类型
#define BEGIN_PACKET 1      // 仿真开始信令
#define END_PACKET 2        // 仿真结束信令
#define INF_PACKET 3        // 控制信令包类型
#define KEYSUPPLY_PACKET 4  // 密钥补充包类型
#define ECN_PACKET 5        // 显式拥塞通知包类型
#define PAUSE_PACKET 6      // 暂停信令包类型
#define RESUME_PACKET 7     // 恢复信令包类型
#define PROBE_PACKET 8      // 探测包类型
#define RSVP_PROBE_PACKET 9 // RSVP请求探测包
#define RSVP_LOCK_PACKET 10 // RSVP请求锁定包

#define SLOW_START 0
#define CONGESTION_AVOIDANCE 1
#define FAST_RECOVERY 2
#define SLOW_START_THRESHOLD 256 // 单位为kbps,超过此值进入拥塞避免状态
#define RTT_TIME_WINDOWS 100     // RTT时间窗口，单位ms
#define REQUEST_RATE 1           // 请求初始速率，单位kbps
#define MAX_KEY_SEND_RATE 1000   // 最大密钥发送速率，单位kbps

#define ECN_THRESHOLD 200 // 定义ECN阈值，单位为包数目，低于此值则启动ECN机制

#define MAX_EVENT_NUM 100 // epoll监听事件数量

#define W_TIME_SIZE 5            // 定义计算时间窗口大小，单位为s
#define MAX_QUEUE_SIZE 200       // 定义节点上最大队列长度
#define ONE_HOP_RTT 10           // 定义一跳RTT时间，单位为ms
#define PROBE_INTERVAL 8         // 定义探测包发送时间间隔，单位为ms
#define MAX_KEY_SERVER_RATE 1000 // 定义最大密钥服务速率，单位为kbps
#define MAX_WAIT_TIME 50         // 定义最大等待时间，单位为ms
#define DECISION_INTERVAL 8      // 定义决策周期，单位为ms
#define PACKET_DELAY 8           // 定义数据包传输延迟，单位为ms

#define DELAY_RSVP 1000     // 定义RSVP请求延迟，单位为ms
#define MAX_P_RSVP 4000     // 定义RSVP请求服务速率，单位为kbps
#define PROBE_RTT_RSVP 2000 // 定义RSVP探测包RTT时间，单位为ms

struct node_inf
{
    uint32_t ip_net;     // 32位ip地址
    std::string ip_char; // 字符串形式ip地址
    std::string ip_name; // PC名字标识
};

struct key_pool
{
    int encrypt_key_num;                                                          // 加密密钥数量，按照密钥文件数量计算
    int decrypt_key_num;                                                          // 解密密钥数量，按照文件数目计算
    int total_key_num;                                                            // 产生的总密钥数量
    float key_rate;                                                               // 密钥发送速率，单位bps
    double average_delay;                                                         // 平均密钥产生延迟
    int packet_num;                                                               // 已经发送数据包数目
    int flow_event_num;                                                           // 流事件数目
    double average_a_t;                                                           // 平均到达速率,单位kbps
    double average_Q_t;                                                           // 平均队列长度
    double average_S_t;                                                           // 平均发送数据量
    int last_S_t;                                                                 // 上一次记录的消耗量
    std::chrono::time_point<std::chrono::high_resolution_clock> last_supply_time; // 上次密钥补充时间
};

struct RSVP_request
{
    std::string src_name; // 源节点名
    std::string dst_name; // 目的节点名
    int packet_num;       // 发送的数据包数目
    int send_beign_time;  // 发送距离仿真开始时间，单位ms
    int bucket_depth_b;   // 令牌桶深度，单位为数据包数目
    float send_rate_r;    // 按照百分比计算的发送速率，基础速率为100kbps
    int service_rate_R;   // 链路服务速率,单位为bps
    int active_flag;      // 请求激活标志,0表示未激活，1表示激活
    int enough_flag;      // 密钥充足标志,0表示密钥不足，1表示密钥充足
    // std::vector<std::chrono::time_point<std::chrono::high_resolution_clock>> request_enter_time; // 记录每一个请求进入该节点的时间，用vector存储
};

void RSVP_service_rate_calculate(struct RSVP_request &request)
{
    request.service_rate_R = (MAX_P_RSVP * (request.bucket_depth_b - 1) / (MAX_P_RSVP - request.send_rate_r * 1000 / 2.0) * KEYFILE_SIZE * 8 + KEYFILE_SIZE * 8) / (DELAY_RSVP / 1000.0 + (request.bucket_depth_b - 1) * KEYFILE_SIZE * 8 / 1024 / (MAX_P_RSVP - request.send_rate_r * 1000.0 / 2.0)); // 计算速率为10倍！！！
    // 输出请求信息和服务速率
    // printf("%f,%f,%f\n", MAX_P_RSVP * (request.bucket_depth_b - 1) / (MAX_P_RSVP - request.send_rate_r * 1000) * KEYFILE_SIZE * 8 + KEYFILE_SIZE * 8, MAX_P_RSVP * (request.bucket_depth_b - 1) / (MAX_P_RSVP - request.send_rate_r * 1000), float(DELAY_RSVP / 1000) + (request.bucket_depth_b - 1) * KEYFILE_SIZE * 8 / 1024 / (MAX_P_RSVP - request.send_rate_r * 1000));
    printf("src_name: %s, dst_name: %s, packet_num: %d, send_beign_time: %d, bucket_depth_b: %d, send_rate_r: %f, service_rate_R: %d\n", request.src_name.c_str(), request.dst_name.c_str(), request.packet_num, request.send_beign_time, request.bucket_depth_b, request.send_rate_r, request.service_rate_R);
}

void RSVP_inf_get(struct RSVP_request &request, uint16_t packet_inf)
{
    // packet_inf中的个位和十位为发送速率，减去发送速率后得到令牌桶深度
    request.send_rate_r = (packet_inf % 100) / 100.0;
    request.bucket_depth_b = packet_inf - request.send_rate_r * 100;
    // 计算服务速率
    RSVP_service_rate_calculate(request);
}

void RSVP_inf_set(struct RSVP_request &request, uint16_t &packet_inf)
{
    // 将发送速率和令牌桶深度转换为packet_inf
    packet_inf = request.bucket_depth_b + request.send_rate_r * 100;
}

struct key_request
{
    std::string src_name;                                                                        // 源节点名
    std::string dst_name;                                                                        // 目的节点名
    int packet_num;                                                                              // 发送的数据包数目
    int send_beign_time;                                                                         // 发送距离仿真开始时间，单位ms
    std::vector<std::chrono::time_point<std::chrono::high_resolution_clock>> request_enter_time; // 记录每一个请求进入该节点的时间，用vector存储
};

struct request_queue
{
    std::chrono::time_point<std::chrono::high_resolution_clock> next_send_time; // 请求下一次发送时间
    int next_request_number;                                                    // vector序号标明下一个服务的请求
    std::string next_request_src_name;
    std::string next_request_dst_name;
    std::vector<key_request> request_active_list;                               // 可用请求队列
    std::vector<std::string> request_wait_list;                                 // 等待请求队列，存储格式为"src_name_dst_name"
    std::chrono::time_point<std::chrono::high_resolution_clock> next_wait_time; // 下一个请求等待结束时间
};
// 对窗口内数据进行计数
struct window_info_count
{
    int S_t_count;                                                  // 发送数据量当前计数
    int A_t_count;                                                  // 接收数据量当前计数
    int service_rate;                                               // 链路服务速率
    std::map<std::pair<std::string, std::string>, int> arrive_rate; // 各个请求到达速率
    std::map<std::pair<std::string, std::string>, int> live_label;  // 各个请求存活标记
};

// 密钥补充类
class supply_key
{
private:
    /* data */
public:
    int PC_num; // 有效PC数量
    std::string PC1_name;
    std::string PC2_name;
    std::chrono::time_point<std::chrono::high_resolution_clock> send_time;
    int packet_num;
    std::ifstream *in = nullptr;
    // 默认构造函数
    supply_key()
    {
        PC_num = 0;
    }
    // 打开指定文件名文件
    int openfile(std::string filename)
    {
        in = new std::ifstream();
        (*in).open(filename);
        if (!(*in).is_open())
        {
            std::cerr << "open file error" << std::endl;
            return -1;
        }
        // 文件名格式为两台PC的名字，拆出并赋值
        size_t pos = filename.find('_');
        if (pos != std::string::npos)
        {
            PC1_name = filename.substr(0, pos);
            PC2_name = filename.substr(pos + 1, filename.length() - pos - 5); // -5 to remove ".txt"
        }
        else
        {
            std::cerr << "Invalid filename format" << std::endl;
            return -1;
        }
        return 0;
    }
    // 从指定文件中读取send_time和packet_num
    void read_data()
    {
        float gap_time;
        if ((*in) >> gap_time >> packet_num)
        {
            send_time = std::chrono::high_resolution_clock::now() + std::chrono::microseconds((int)gap_time);
        }
        else
        {
            std::cerr << "read file error" << std::endl;
        }
    }
    // 采用生成send_time和packet_num，以满足速率要求,r bps
    void creat_rate(float r)
    {
        packet_num = 1;
        float gap_time = packet_num * KEYFILE_SIZE * 8 / r;
        send_time = std::chrono::high_resolution_clock::now() + std::chrono::milliseconds((int)gap_time);
    }

    // 关闭文件
    void closefile()
    {
        (*in).close();
        delete in;
    }
};

class packet
{
private:
    /* data */
public:
    struct data
    {
        uint32_t src_ip;                 // 源ip
        uint32_t dst_ip;                 // 目的ip
        uint16_t packet_flag;            // 包标识
        uint16_t packet_inf;             // 包携带信息
        unsigned char key[KEYFILE_SIZE]; // 数据,注意采用无符号字符型
    };
    struct data data;
    // 构造函数
    packet()
    {
        // 构造一个全0的data
        memset(&this->data, 0, sizeof(data));
    }
    packet(uint32_t src_ip, uint32_t dst_ip, uint16_t packet_flag, uint16_t packet_inf)
    {
        this->data.src_ip = src_ip;
        this->data.dst_ip = dst_ip;
        this->data.packet_flag = packet_flag;
        this->data.packet_inf = packet_inf;
        // 构造一个全0的key
        memset(this->data.key, 0, KEYFILE_SIZE);
    }
    // 将key设置为一个全为字符0的字符串
    void set_key_zero()
    {
        memset(this->data.key, '0', KEYFILE_SIZE);
    }
    // 网络字节序转换
    void hton()
    {
        this->data.src_ip = htonl(this->data.src_ip);
        this->data.dst_ip = htonl(this->data.dst_ip);
        this->data.packet_flag = htons(this->data.packet_flag);
        this->data.packet_inf = htons(this->data.packet_inf);
    }
    // 主机字节序转换
    void ntoh()
    {
        this->data.src_ip = ntohl(this->data.src_ip);
        this->data.dst_ip = ntohl(this->data.dst_ip);
        this->data.packet_flag = ntohs(this->data.packet_flag);
        this->data.packet_inf = ntohs(this->data.packet_inf);
    }
    // 打印包结构体内容
    void output()
    {
        printf("src_ip=%s\n", inet_ntoa(*(struct in_addr *)&data.src_ip));
        printf("dst_ip=%s\n", inet_ntoa(*(struct in_addr *)&data.dst_ip));
        printf("packet_flag=%d\n", data.packet_flag);
        printf("packet_inf=%d\n", data.packet_inf);
        printf("key=%s\n", data.key);
    }
    // 向指定套接字发送数据
    int send_data(int sockfd)
    {
        char buf[PACKETHEAD_SIZE + KEYFILE_SIZE];
        // 将数据包头转换为网络字节序
        this->hton();
        // 将数据包头拷贝到buf中
        memcpy(buf, &this->data, PACKETHEAD_SIZE);
        // 将数据包数据拷贝到buf中
        memcpy(buf + PACKETHEAD_SIZE, this->data.key, KEYFILE_SIZE);
        // 发送数据
        int data_size;
        if ((data_size = send(sockfd, buf, PACKETHEAD_SIZE + KEYFILE_SIZE, 0)) <= 0)
        {
            perror("send error");
            return -1;
        }
        // std::cout << "send data size: " << data_size << std::endl;
        return 0;
    }
    // 从指定套接字接收数据
    int recv_data(int sockfd)
    {
        char buf[PACKETHEAD_SIZE + KEYFILE_SIZE];
        // 接收数据
        int data_size;
        if ((data_size = recv(sockfd, buf, PACKETHEAD_SIZE + KEYFILE_SIZE, 0)) <= 0)
        {
            perror("recv error");
            return -1;
        }
        // std::cout << "recv data size: " << data_size << std::endl;
        //  将数据包头拷贝到buf中
        memcpy(&this->data, buf, PACKETHEAD_SIZE);
        // 将数据包数据拷贝到buf中
        memcpy(this->data.key, buf + PACKETHEAD_SIZE, KEYFILE_SIZE);
        // 将数据包头转换为主机字节序
        this->ntoh();
        return 0;
    }
};

// 异步TCP和指定IP地址主机的指定端口建立连接，返回值为套接字描述符，并设置为非阻塞模式
int pre_send(const char *ip, int port)
{
    int sockfd;
    struct sockaddr_in servaddr;
    // 创建套接字
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket error");
        return -1;
    }
    // 设置非阻塞模式
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    int bufsize = 16 * 1024 * 1024; // 4MB
    socklen_t len = sizeof(bufsize);

    // 设置发送缓冲区大小
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, len) < 0)
    {
        perror("setsockopt SO_SNDBUF");
        return -1;
    }

    // 设置套接字选项，禁用 Nagle 算法
    int flag = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int)) < 0)
    {
        perror("setsockopt failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 设置服务器地址
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &servaddr.sin_addr) <= 0)
    {
        perror("inet_pton error");
        return -1;
    }
    // 连接服务器
    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        if (errno != EINPROGRESS)
        {
            perror("connect error");
            return -1;
        }
    }
    // 使用select等待连接完成
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sockfd, &writefds);
    // 设置超时时间为0.1s
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;
    int ret = select(sockfd + 1, NULL, &writefds, NULL, &timeout);
    if (ret <= 0)
    {
        perror("select error");
        close(sockfd);
        return -1;
    }
    std::cout << "connect to " << ip << " success" << " sockfd: " << sockfd << std::endl;
    return sockfd;
}

// 非阻塞式监听指定端口，返回值为套接字描述符
int pre_recv(int port)
{
    int listenfd;
    struct sockaddr_in servaddr;
    // 创建套接字
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket error");
        return -1;
    }
    // 设置为非阻塞模式
    int flags = fcntl(listenfd, F_GETFL, 0);
    fcntl(listenfd, F_SETFL, flags | O_NONBLOCK);
    // 设置服务器地址
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    // 绑定套接字
    if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        perror("bind error");
        return -1;
    }
    // 监听套接字
    if (listen(listenfd, 5) < 0)
    {
        perror("listen error");
        return -1;
    }
    return listenfd;
}

// 接受连接，返回值为套接字描述符，非阻塞模式
int accept_connect(int listenfd)
{
    int connfd;
    struct sockaddr_in cliaddr;
    socklen_t clilen = sizeof(cliaddr);
    // 接受连接
    if ((connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen)) < 0)
    {
        if (errno != EWOULDBLOCK && errno != EAGAIN)
        {
            perror("accept error");
            return -1;
        }
    }
    // 设置为非阻塞模式
    int flags = fcntl(connfd, F_GETFL, 0);
    fcntl(connfd, F_SETFL, flags | O_NONBLOCK);

    int bufsize = 4 * 1024 * 1024; // 4MB
    socklen_t len = sizeof(bufsize);

    // 设置发送缓冲区大小
    if (setsockopt(connfd, SOL_SOCKET, SO_RCVBUF, &bufsize, len) < 0)
    {
        perror("setsockopt SO_SO_RCVBUF");
        return -1;
    }

    return connfd;
}

// 获取已连接套接字的对端IP地址和端口号
int get_socket_info(int sockfd, char *ip, int *port)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    // 获取对端地址
    if (getpeername(sockfd, (struct sockaddr *)&addr, &len) < 0)
    {
        perror("getpeername error");
        return -1;
    }
    // 获取对端IP地址
    strcpy(ip, inet_ntoa(addr.sin_addr));
    // 获取对端端口号
    *port = ntohs(addr.sin_port);
    return 0;
}

// 根据ip地址查询节点信息，如果为本地回环地址，则返回本地节点信息，失败返回-1
int get_node_inf(std::string ip_address, node_inf *node)
{
    // 每一台主机可能有多个ip地址，利用map存储ip地址和主机名
    std::map<std::string, std::vector<std::string>> ip_list;
    ip_list["PC1"] = {"192.168.190.128", "192.168.194.128", "192.168.195.128", "192.168.196.129"};
    ip_list["PC2"] = {"192.168.190.129", "192.168.191.128", "192.168.192.128", "192.168.194.133"};
    ip_list["PC3"] = {"192.168.191.129", "192.168.194.131"};
    ip_list["PC4"] = {"192.168.192.129", "192.168.194.134"};
    ip_list["PC5"] = {"192.168.194.129"};
    ip_list["PC6"] = {"192.168.196.128", "192.168.194.130"};
    ip_list["PC7"] = {"192.168.195.129", "192.168.194.132"};
    // 如果IP地址为本地地址，则读取本地信息
    if (ip_address == "127.0.0.1")
    {
        // 定义数组存储IP地址
        struct ifaddrs *ifaddr, *ifa;
        int family, s;
        char host[NI_MAXHOST];
        if (getifaddrs(&ifaddr) == -1)
        {
            perror("getifaddrs");
            return -1;
        }
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) // 遍历所有接口
        {
            family = ifa->ifa_addr->sa_family;
            if (family == AF_INET)
            {
                s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                                host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                if (s != 0)
                {
                    printf("getnameinfo() failed: %s\n", gai_strerror(s));
                    return -1;
                }
                if (strcmp(ifa->ifa_name, "lo") != 0)
                {
                    // printf("address: %s\n", host);
                    // 查找是否在数组中，并输出是第几个IP
                    for (auto it = ip_list.begin(); it != ip_list.end(); it++)
                    {
                        for (std::vector<std::string>::size_type i = 0; i < it->second.size(); i++)
                        {
                            if (host == it->second[i])
                            {
                                // printf("IP: %s is the %dth IP\n", host, i + 1);
                                node->ip_net = inet_addr(host);
                                node->ip_char = host;
                                node->ip_name = it->first;
                                printf("ip_name: %s \n", node->ip_name.c_str());
                                freeifaddrs(ifaddr);
                                return 0;
                            }
                        }
                    }
                }
            }
        }
        // 如果ip地址不在列表中，输出错误信息
        printf("IP: %s is not in the list\n", host);
        freeifaddrs(ifaddr);
        return 0;
    }
    else
    {
        for (auto it = ip_list.begin(); it != ip_list.end(); it++)
        {
            for (std::vector<std::string>::size_type i = 0; i < it->second.size(); i++)
            {
                if (ip_address == it->second[i])
                {
                    // printf("IP: %s is the %dth IP\n", host, i + 1);
                    node->ip_net = inet_addr(ip_address.c_str());
                    node->ip_char = ip_address;
                    node->ip_name = it->first;
                }
            }
        }
        return 0;
    }
}

// 根据目的节点信息和当前节点信息查询路由表获取下一跳节点信息
int get_next_node_inf(node_inf *now_node, node_inf *dst_node, node_inf *next_node)
{
    // 利用三维map存储路由表信息，第一维为当前节点，第二维为目的节点，第三维为下一跳节点
    std::map<std::string, std::map<std::string, std::string>> route_table;
    route_table["PC1"]["PC3"] = "192.168.190.129";
    route_table["PC1"]["PC4"] = "192.168.190.129";

    route_table["PC2"]["PC6"] = "192.168.190.128";
    route_table["PC2"]["PC7"] = "192.168.190.128";

    route_table["PC3"]["PC1"] = "192.168.191.128";
    route_table["PC3"]["PC4"] = "192.168.191.128";
    route_table["PC3"]["PC6"] = "192.168.191.128";
    route_table["PC3"]["PC7"] = "192.168.191.128";

    route_table["PC4"]["PC1"] = "192.168.192.128";
    route_table["PC4"]["PC3"] = "192.168.192.128";
    route_table["PC4"]["PC6"] = "192.168.192.128";
    route_table["PC4"]["PC7"] = "192.168.192.128";

    route_table["PC6"]["PC2"] = "192.168.196.129";
    route_table["PC6"]["PC3"] = "192.168.196.129";
    route_table["PC6"]["PC4"] = "192.168.196.129";
    route_table["PC6"]["PC7"] = "192.168.196.129";

    route_table["PC7"]["PC2"] = "192.168.195.128";
    route_table["PC7"]["PC3"] = "192.168.195.128";
    route_table["PC7"]["PC4"] = "192.168.195.128";
    route_table["PC7"]["PC6"] = "192.168.195.128";

    // 查询对应表项，查不到则说明下一跳节点为目的节点
    if (route_table.find(now_node->ip_name) == route_table.end())
    {
        *next_node = *dst_node;
    }
    else
    {
        if (route_table[now_node->ip_name].find(dst_node->ip_name) == route_table[now_node->ip_name].end())
        {
            *next_node = *dst_node;
        }
        else
        {
            get_node_inf(route_table[now_node->ip_name][dst_node->ip_name], next_node);
        }
    }
    return 0;
}

// 计算在指定RTT内发送包的数目，生成对应数据包的时间戳列表，其中RTT单位为ms，sendrate单位为kbps，数据包大小为packet_size字节
std::vector<int> generate_sendtime(int RTT, int sendrate)
{
    std::vector<int> sendtime;
    if (sendrate * RTT <= KEYFILE_SIZE * 8)
    {
        sendtime.push_back(KEYFILE_SIZE * 8 / sendrate);
        return sendtime;
    }
    int packet_num = sendrate * RTT / (KEYFILE_SIZE * 8);
    for (int i = 0; i < packet_num; i++)
    {
        // sendtime.push_back(KEYFILE_SIZE * 8 / sendrate * (i + 1));
        sendtime.push_back(KEYFILE_SIZE * 8 / sendrate);
    }
    return sendtime;
}

// 模拟TCP拥塞控制过程调整发送速率
int congestion_control(int last_sendrate, int &state)
{
    if (state == SLOW_START)
    {
        if (last_sendrate >= SLOW_START_THRESHOLD / 2)
        {
            state = CONGESTION_AVOIDANCE;
            return last_sendrate;
        }
        else
        {
            return last_sendrate * 2;
        }
    }
    else if (state == CONGESTION_AVOIDANCE)
    {
        return last_sendrate + 1;
    }
    else if (state == FAST_RECOVERY)
    {
        state = CONGESTION_AVOIDANCE;
        return last_sendrate / 2 > 0 ? last_sendrate / 2 : 1;
    }
    else
    {
        return -1;
    }
}

// 定义计算窗口历史信息类
class window_history
{
private:
    /* data */
public:
    struct window_info
    {
        // 窗口信息，均按照数据包数目计算
        int Q_t;                                                          // 节点上总队列大小
        int S_t;                                                          // 发送数据量
        int A_t;                                                          // 接收数据量
        int a_t;                                                          // 接收数据速率
        int Lambda_t;                                                     // 产生密钥量
        int L_t;                                                          // 密钥池中密钥量
        float DoE;                                                        // 弹性程度
        std::chrono::time_point<std::chrono::high_resolution_clock> time; // 信息存储的时间
    };
    std::vector<window_info> window;
    // 默认构造函数
    window_history()
    {
    }

    // 根据窗口内信息计算链路服务量，单位为包数目，均值计算版本,周期性调用版本,返回值即为链路服务速率，单位为kbps
    int calculate_link_serve_number(double average_Q_t, double average_a_t, double average_S_t, double average_create_key_time, double average_delay, double flow_event_num, int L_t, int packet_num, int a_t, int Q_t)
    {
        // printf("Q_t: %d, A_t: %d, Lambda_t: %d, L_t: %d, DoE: %f, window size: %d\n", Q_t, A_t, Lambda_t, L_t, DoE, window.size());
        int time_interval = DECISION_INTERVAL;
        double S_t_min = 0;
        double S_t_max = 0;
        double S_t_max_1 = 0;
        double S_t_max_2 = 0;
        double S_t_D = 0;
        double S_t = 0;
        double epsilon = 0;
        double A_t_predict = (double)a_t * time_interval / KEYFILE_SIZE / 8;
        average_create_key_time = PACKET_DELAY;
        printf("---------------packet_creat_delay: %f, average_delay: %f,A_t_predict: %f, average_create_key_time: %f,a_t: %d   ", average_create_key_time, average_delay, A_t_predict, average_create_key_time, a_t);
        window_info last_info;
        if (window.size() == 0)
        {
            return 0;
        }
        last_info = window.back();
        S_t_min = average_Q_t - (time_interval - average_create_key_time + epsilon) * average_a_t / KEYFILE_SIZE / 8;
        S_t_min = S_t_min > A_t_predict ? A_t_predict : S_t_min;
        S_t_max_1 = average_Q_t + (time_interval - average_create_key_time + epsilon) * average_a_t / KEYFILE_SIZE / 8 > L_t ? L_t : average_Q_t + (time_interval - average_create_key_time + epsilon) * average_a_t / KEYFILE_SIZE / 8;
        // printf("---------------S_t_min: %f, S_t_max_1: %f\n", S_t_min, S_t_max_1);
        int sum = 0;
        int V_W = 0;
        for (auto it = window.begin(); it != window.end(); it++)
        {
            sum += it->Lambda_t;
            V_W += it->S_t - it->Lambda_t;
        }
        float max_DoE = last_info.DoE;
        float time_trans = (float)W_TIME_SIZE / window.size() * 1000 / time_interval;

        S_t_max_2 = (max_DoE * sum / W_TIME_SIZE - V_W) / time_trans + (float)sum / time_trans;
        S_t_max_2 = S_t_max_2 > L_t ? L_t : S_t_max_2;
        S_t_max = S_t_max_1 > S_t_max_2 ? S_t_max_2 : S_t_max_1;

        // printf("####################S_t_min: %f, S_t_max: %f, S_t_max_1: %f, S_t_max_2: %f,flow_event_num: %f, average_S_t: %f\n", S_t_min, S_t_max, S_t_max_1, S_t_max_2, flow_event_num, average_S_t);
        S_t_min = S_t_min * (flow_event_num + 1) - flow_event_num * average_S_t;
        S_t_max = S_t_max * (flow_event_num + 1) - flow_event_num * average_S_t;
        // printf("####################S_t_min: %f, S_t_max: %f\n", S_t_min, S_t_max);

        S_t_D = (double)Q_t + A_t_predict - (average_create_key_time * (packet_num + A_t_predict) - average_delay * packet_num) * a_t / KEYFILE_SIZE / 8 / A_t_predict;
        // printf("***************************Q_t: %d, A_t_predict: %f, S_t_D: %f,packet_num: %d,a_t: %d\n", Q_t, A_t_predict, S_t_D, packet_num, a_t);
        S_t_D = S_t_D * (flow_event_num + 1) - flow_event_num * average_S_t;

        printf("------------------S_t_min: %f, S_t_max: %f, S_t_D: %f\n", S_t_min, S_t_max, S_t_D);

        if (S_t_D >= S_t_min && S_t_D <= S_t_max)
        {
            S_t = S_t_D;
        }
        else
        {
            // 取S_t_min和S_t_max中离S_t_D最近的值
            S_t = abs(S_t_D - S_t_min) < abs(S_t_D - S_t_max) ? S_t_min : S_t_max;
        }
        if (S_t <= 0 || S_t_min > S_t_max)
        {
            return 10;
        }
        float alpha = 1; // 速率调整因子
        return int(alpha * S_t * KEYFILE_SIZE * 8 / time_interval) > MAX_KEY_SERVER_RATE ? MAX_KEY_SERVER_RATE : int(alpha * S_t * KEYFILE_SIZE * 8 / time_interval);
    }
    // 添加窗口信息,返回值为链路服务速率，单位为kbps
    int add_window_info(int Q_t, int S_t, int A_t, int a_t, int Lambda_t, int L_t, int total_key_num, int time, double average_delay, int packet_num)
    {
        window_info info;
        info.Q_t = Q_t;
        info.A_t = A_t;
        info.a_t = a_t;
        info.Lambda_t = Lambda_t;
        info.L_t = L_t;
        info.S_t = S_t;
        info.time = std::chrono::high_resolution_clock::now();
        // 检查队列中元素的入队时间，如果超过时间窗口则出队
        while (!window.empty() && std::chrono::duration_cast<std::chrono::seconds>(info.time - window.front().time).count() > W_TIME_SIZE)
        {
            window.erase(window.begin());
        }
        // 计算时间窗口内当前平均密钥产生量
        int sum = 0;
        for (auto it = window.begin(); it != window.end(); it++)
        {
            sum += it->Lambda_t;
        }
        info.DoE = (float)L_t / (sum / W_TIME_SIZE) - 1;
        window.push_back(info);
        int S_t_temp = calculate_link_serve_number(Q_t, A_t, a_t, Lambda_t, L_t, info.DoE, total_key_num, time, average_delay, packet_num);
        // return int(S_t_temp * KEYFILE_SIZE * 8 / W_TIME_SIZE / 1000) > MAX_KEY_SERVER_RATE ? MAX_KEY_SERVER_RATE : int(S_t_temp * KEYFILE_SIZE * 8 / W_TIME_SIZE / 1000);
        return int(S_t_temp * KEYFILE_SIZE * 8 / W_TIME_SIZE * window.size() / 1000) > MAX_KEY_SERVER_RATE ? MAX_KEY_SERVER_RATE : int(S_t_temp * KEYFILE_SIZE * 8 / W_TIME_SIZE * window.size() / 1000);
        // return MAX_KEY_SERVER_RATE;
    }
};

// 计算requset_queue中队列长度和
int calculate_queue_length(request_queue rq)
{
    int sum = 0;
    for (auto it = rq.request_active_list.begin(); it != rq.request_active_list.end(); it++)
    {
        sum += it->packet_num;
    }
    return sum;
}

// 通过路由计算得到上一跳节点信息，利用源节点和目的节点信息，按照路由表查询
int get_last_node_inf(node_inf *src_node, node_inf *dst_node, node_inf *now_node, node_inf *last_node)
{
    node_inf node1;
    node_inf node2 = *src_node;
    get_next_node_inf(&node2, dst_node, &node1);
    while (node1.ip_name != now_node->ip_name)
    {
        node2 = node1;
        if (node2.ip_name == dst_node->ip_name)
        {
            printf("Can't find last node\n");
            return -1;
        }
        get_next_node_inf(&node2, dst_node, &node1);
    }
    last_node->ip_name = node2.ip_name;
    last_node->ip_char = node2.ip_char;
    last_node->ip_net = node2.ip_net;
    return 0;
}
int main()
{
    node_inf now_node;
    get_node_inf("127.0.0.1", &now_node);
    // 利用map存储发往每个主机的soket描述符，key为主机名，value为socket描述符，初始化为-1
    std::map<std::string, int> sockfd_map = {{"PC1", -1}, {"PC2", -1}, {"PC3", -1}, {"PC4", -1}, {"PC5", -1}, {"PC6", -1}, {"PC7", -1}};
    if (now_node.ip_name == "PC5")
    {
        // 需要发送给的主机列表，利用map存储，key为主机名，value为ip地址
        std::map<std::string, std::string> dst_map = {{"PC1", "192.168.194.128"}, {"PC2", "192.168.194.133"}, {"PC3", "192.168.194.131"}, {"PC4", "192.168.194.134"}, {"PC6", "192.168.194.130"}, {"PC7", "192.168.194.132"}};
        // 遍历目的主机列表,依次建立套接字连接，并存储在sockfd_map中
        for (auto it = dst_map.begin(); it != dst_map.end(); it++)
        {
            sockfd_map[it->first] = pre_send(it->second.c_str(), KEYRELAY_PORT);
            if (sockfd_map[it->first] == -1)
            {
                std::cerr << "connect to " << it->first << " failed" << std::endl;
            }
        }
        // 终端输入“begin”后向已经建立连接的主机发送开始数据包
        std::string begin;
        std::cin >> begin;
        while (begin != "begin")
        {
            std::cin >> begin;
        }

        for (auto it = dst_map.begin(); it != dst_map.end(); it++)
        {
            packet begin_packet(now_node.ip_net, inet_addr(it->second.c_str()), BEGIN_PACKET, 0);
            // 当发送数据包节点套接字描述符不为-1时，发送数据包
            if (sockfd_map[it->first] != -1)
            {
                begin_packet.send_data(sockfd_map[it->first]);
            }
        }
        // 创建vector存储每个主机下一次发送数据包的时间
        std::vector<class supply_key> time_list;
        // 待读取文件名字信息
        std::vector<std::string> file_list = {"PC1_PC2.txt", "PC1_PC6.txt", "PC1_PC7.txt", "PC2_PC3.txt", "PC2_PC4.txt"};
        // 读取文件信息，存储在time_list中
        for (auto it = file_list.begin(); it != file_list.end(); it++)
        {
            class supply_key key;
            key.openfile(*it);
            // 检查对应的两台PC是否可以通信
            if (sockfd_map[key.PC1_name] != -1 && sockfd_map[key.PC2_name] != -1)
            {
                key.read_data();
                time_list.push_back(key);
            }
            else
            {
                std::cerr << key.PC1_name << " and " << key.PC2_name << " can't communicate" << std::endl;
                key.closefile();
            }
        }
        while (true)
        {
            if (time_list.size() == 0)
            {
                printf("No link can be sent\n");
                break;
            }
            else
            {
                // 根据time_list中的最小时间，sleep到该时间，并根据该时间向对应主机发送数据包
                auto min_time = time_list[0].send_time;
                for (auto it = time_list.begin(); it != time_list.end(); it++)
                {
                    if (it->send_time < min_time)
                    {
                        min_time = it->send_time;
                    }
                }
                if (std::chrono::high_resolution_clock::now() < min_time)
                {
                    std::this_thread::sleep_until(min_time);
                }
                for (auto it = time_list.begin(); it != time_list.end(); it++)
                {
                    if (std::chrono::high_resolution_clock::now() >= it->send_time)
                    {
                        // 向PC1_name和PC2_name发送补充数据包packet_num作为inf字段
                        packet data_packet1(now_node.ip_net, inet_addr(dst_map[it->PC1_name].c_str()), KEYSUPPLY_PACKET, it->packet_num / 2);
                        // 将PC2_name作为key字段
                        strcat((char *)data_packet1.data.key, it->PC2_name.c_str());
                        data_packet1.send_data(sockfd_map[it->PC1_name]);
                        packet data_packet2(now_node.ip_net, inet_addr(dst_map[it->PC2_name].c_str()), KEYSUPPLY_PACKET, it->packet_num / 2);
                        // 将PC1_name作为key字段
                        strcat((char *)data_packet2.data.key, it->PC1_name.c_str());
                        data_packet2.send_data(sockfd_map[it->PC2_name]);
                        // 读取下一次发送时间
                        it->read_data();
                    }
                }
            }

            // 将标准输入设置为非阻塞模式，如果输入“end”则向所有主机发送结束数据包
            int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
            fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
            char end[5];
            if (read(STDIN_FILENO, end, 5) > 0)
            {
                if (std::string(end) == "end\n")
                {
                    break;
                }
            }
        }
        for (auto it = dst_map.begin(); it != dst_map.end(); it++)
        {
            packet end_packet(now_node.ip_net, inet_addr(it->second.c_str()), END_PACKET, 0);
            if (sockfd_map[it->first] != -1)
            {
                end_packet.send_data(sockfd_map[it->first]);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                // 关闭套接字
                close(sockfd_map[it->first]);
            }
        }
        // 关闭文件读写
        for (auto it = time_list.begin(); it != time_list.end(); it++)
        {
            it->closefile();
        }
    }
    else
    {
        // 需要发送给的主机列表，利用map存储，key为主机名，value为ip地址
        std::map<std::string, std::string> dst_map = {{"PC1", "192.168.190.128"}, {"PC2", "192.168.190.129"}, {"PC3", "192.168.191.129"}, {"PC4", "192.168.192.129"}, {"PC6", "192.168.196.128"}, {"PC7", "192.168.195.129"}};
        // 使用epoll对接收过程进行管理
        int listenfd = pre_recv(KEYRELAY_PORT);
        int epollfd = epoll_create(MAX_EVENT_NUM);
        struct epoll_event ev, events[MAX_EVENT_NUM];
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = listenfd;
        epoll_ctl(epollfd, EPOLL_CTL_ADD, listenfd, &ev);
        std::chrono::time_point<std::chrono::high_resolution_clock> begin_time;              // 定义开始时间变量类型
        std::map<std::string, key_pool> key_pool_map;                                        // 定义密钥池，采用map存储，key为主机名，value为密钥池
        std::map<std::string, int> finish_req_map;                                           // 定义请求完成map，key为源节点，value为完成的请求包数目 ################
        std::vector<RSVP_request> RSVP_request_list = INIT_RSVP_REQUEST_LIST;                // 初始RSVP请求队列
        std::map<std::string, std::vector<RSVP_request>> RSVP_request_map;                   // 定义RSVP请求map，key为源节点，value为RSVP请求队列
        std::map<std::string, int> drop_req_map;                                             // 定义请求丢包map，key为源节点+目的节点，value为丢包数目
        std::ofstream out(now_node.ip_name + ".csv", std::ios::trunc);                       // 收集数据
        int collect_interval = DATA_COLLECT_INTERVAL;                                        // 定义数据收集间隔，单位ms
        int collect_time = DATA_COLLECT_TIME;                                                // 定义数据收集时间，单位ms
        std::ofstream send_time_out(now_node.ip_name + "_send_time.csv", std::ios::trunc);   // 发送时间记录表
        std::ofstream recv_time_out(now_node.ip_name + "_recv_time.csv", std::ios::trunc);   // 接收时间记录表
        std::ofstream table_head_out(now_node.ip_name + "_table_head.csv", std::ios::trunc); // 表头记录表
        int RTT = RTT_TIME_WINDOWS;                                                          // 定义RTT，单位ms
        int state = SLOW_START;                                                              // 拥塞控制状态
        int request_rate = REQUEST_RATE;                                                     // 请求速率，单位kbps
        std::vector<int> sendtime_list;                                                      // 发送时间列表
        int next_probe_time = 2000;                                                          // 定义下一次探测包开始发送时间，单位ms
        int next_decision_time = 2000;                                                       // 定义下一次决策时间，单位ms
        // 进行事件监听，采用非阻塞模式
        int begin_flag = 0;
        while (1)
        {
            // 非阻塞监听事件
            int nfds = epoll_wait(epollfd, events, MAX_EVENT_NUM, 0);
            for (int i = 0; i < nfds; i++)
            {
                // std::cout << "events[i].data.fd: " << events[i].data.fd << std::endl;
                if (events[i].data.fd == listenfd) // 如果是监听套接字，接受连接
                {
                    int connfd = accept_connect(listenfd);
                    if (connfd != -1)
                    {
                        char ip[16];
                        int port;
                        get_socket_info(connfd, ip, &port);
                        node_inf dst_node;
                        get_node_inf(ip, &dst_node);
                        std::cout << "accept a connection from " << dst_node.ip_name << std::endl;
                        // sockfd_map[dst_node.ip_name] = connfd;
                        // std::cout << " connfd: " << connfd << std::endl;
                        ev.data.fd = connfd;
                        ev.events = EPOLLIN | EPOLLET;
                        epoll_ctl(epollfd, EPOLL_CTL_ADD, connfd, &ev);
                    }
                }
                else
                {
                    int connfd = events[i].data.fd;
                    int bytes_available;
                    ioctl(connfd, FIONREAD, &bytes_available);
                    while (bytes_available >= PACKETHEAD_SIZE + KEYFILE_SIZE)
                    {
                        packet data_packet;
                        data_packet.recv_data(connfd);
                        bytes_available -= PACKETHEAD_SIZE + KEYFILE_SIZE;
                        // std::cout << "recv data from socket: " << connfd << std::endl;
                        // data_packet.output();
                        // 如果是开始数据包，记录开始时间
                        if (data_packet.data.packet_flag == BEGIN_PACKET)
                        {
                            begin_time = std::chrono::high_resolution_clock::now();
                            std::cout << "BEGIN!, now time: " << std::chrono::duration_cast<std::chrono::milliseconds>(begin_time.time_since_epoch()).count() << "ms" << std::endl;
                            // send_time_out << std::chrono::duration_cast<std::chrono::milliseconds>(begin_time.time_since_epoch()).count() << std::endl;
                            //  开始时间记录
                            begin_flag = 1;
                        }
                        else if (data_packet.data.packet_flag == END_PACKET)
                        {
                            // 如果是结束数据包，计算时间间隔
                            auto end_time = std::chrono::high_resolution_clock::now();
                            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - begin_time);
                            std::cout << "END! Stay Time: " << duration.count() << "ms" << std::endl;
                            // 关闭所有套接字
                            for (auto it = dst_map.begin(); it != dst_map.end(); it++)
                            {
                                if (sockfd_map[it->first] != -1)
                                {
                                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                                    // 关闭套接字
                                    close(sockfd_map[it->first]);
                                }
                            }
                            // 关闭监听套接字
                            close(listenfd);
                            // 关闭epoll
                            close(epollfd);
                            // 关闭文件
                            out.close();
                            send_time_out.close();
                            recv_time_out.close();
                            // 结束后将表头写入文件
                            table_head_out << "Time,";
                            for (auto it = key_pool_map.begin(); it != key_pool_map.end(); it++)
                            {
                                table_head_out << it->first << "_encrypt_key_num," << it->first << "_decrypt_key_num," << it->first << "_key_rate,";
                            }
                            for (auto it = finish_req_map.begin(); it != finish_req_map.end(); it++)
                            {
                                table_head_out << it->first << ",";
                            }
                            for (auto it = drop_req_map.begin(); it != drop_req_map.end(); it++)
                            {
                                table_head_out << it->first << ",";
                            }
                            table_head_out << std::endl;
                            table_head_out.close();
                            return 0;
                        }
                        else if (data_packet.data.packet_flag == KEYSUPPLY_PACKET)
                        {
                            // 输出当前时间
                            auto now_time = std::chrono::high_resolution_clock::now();
                            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now_time - begin_time);
                            std::string PC_key((char *)data_packet.data.key);
                            // 根据key字段补充到对应的密钥池中
                            if (key_pool_map.find(PC_key) == key_pool_map.end())
                            {
                                key_pool_map[PC_key].encrypt_key_num = data_packet.data.packet_inf * 10;
                                key_pool_map[PC_key].decrypt_key_num = data_packet.data.packet_inf * 10;
                                key_pool_map[PC_key].total_key_num = data_packet.data.packet_inf * 10;
                                key_pool_map[PC_key].average_delay = 0;
                                key_pool_map[PC_key].packet_num = 0;
                                key_pool_map[PC_key].average_a_t = 0;
                                key_pool_map[PC_key].average_Q_t = 0;
                                key_pool_map[PC_key].average_S_t = 0;
                                key_pool_map[PC_key].flow_event_num = 0;
                                key_pool_map[PC_key].last_S_t = 0;
                                key_pool_map[PC_key].last_supply_time = std::chrono::high_resolution_clock::now();
                                // key_pool_map[PC_key].key_rate = MAX_KEY_SEND_RATE * 1000;
                            }
                            else
                            {
                                // 检查是否已经有活跃请求，如果有则需要扣除这部分密钥并添加到对应请求密钥池中
                                int lost_key = 0;
                                for (auto re_it = RSVP_request_map[PC_key].begin(); re_it != RSVP_request_map[PC_key].end(); re_it++)
                                {
                                    if (re_it->active_flag == true)
                                    {
                                        // 按照指定速率补充新密钥，需要用上次补充密钥的时间进行计算
                                        auto now_time = std::chrono::high_resolution_clock::now();
                                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now_time - key_pool_map[PC_key].last_supply_time);
                                        int supply_key_num = int(re_it->send_rate_r * 100 * 10 / 2 * duration.count() / KEYFILE_SIZE / 8);
                                        if (lost_key + supply_key_num > data_packet.data.packet_inf * 10)
                                        {
                                            supply_key_num = data_packet.data.packet_inf * 10 - lost_key;
                                        }
                                        re_it->bucket_depth_b += supply_key_num;
                                        lost_key += supply_key_num;
                                        if (lost_key >= data_packet.data.packet_inf * 10)
                                        {
                                            break;
                                        }
                                        printf("request: from %s to %s, bucket_depth_b: %d\n", re_it->src_name.c_str(), re_it->dst_name.c_str(), re_it->bucket_depth_b);
                                    }
                                }
                                // 注意：这里未考虑lost_key是否大于key_pool_map[PC_key].encrypt_key_num的情况！！！，如果考虑需要增加判断
                                key_pool_map[PC_key].encrypt_key_num += (data_packet.data.packet_inf * 10 - lost_key); // 注意：这里变为了原始密钥产生速率的十倍
                                key_pool_map[PC_key].decrypt_key_num += data_packet.data.packet_inf * 10;
                                key_pool_map[PC_key].total_key_num += data_packet.data.packet_inf * 10;
                                key_pool_map[PC_key].last_supply_time = std::chrono::high_resolution_clock::now();
                            }
                            std::cout << "KEYSUPPLY_PACKET: " << PC_key << std::endl;
                            // std::cout << "window_info_count_map[PC_key].service_rate: " << window_info_count_map[PC_key].service_rate << "Time: " << duration.count() << "ms" << std::endl;
                            std::cout << "Now encrypt_key_num: " << key_pool_map[PC_key].encrypt_key_num << " decrypt_key_num: " << key_pool_map[PC_key].decrypt_key_num << " time: " << duration.count() << "ms" << std::endl;
                            // std::cout << "average_delay: " << key_pool_map[PC_key].average_delay << " packet_num: " << key_pool_map[PC_key].packet_num << std::endl;
                        }
                        else if (data_packet.data.packet_flag == KEYRELAY_PACKET)
                        {
                            // 输出当前时间
                            auto now_time = std::chrono::high_resolution_clock::now();
                            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now_time - begin_time);
                            // std::cout << "KEYRELAY_PACKET: " << duration.count() << "ms" << std::endl;
                            //  获取目的节点信息
                            node_inf dst_node;
                            get_node_inf(inet_ntoa(*(struct in_addr *)&data_packet.data.dst_ip), &dst_node);
                            // 检查当前节点是否是目的节点
                            if (now_node.ip_name == dst_node.ip_name)
                            {
                                recv_time_out << duration.count() << std::endl;
                                // 获取源节点信息
                                node_inf src_node;
                                get_node_inf(inet_ntoa(*(struct in_addr *)&data_packet.data.src_ip), &src_node);
                                // 获取上一跳节点信息
                                char ip[16];
                                int port;
                                get_socket_info(connfd, ip, &port);
                                node_inf last_node;
                                get_node_inf(ip, &last_node);
                                key_pool_map[last_node.ip_name].decrypt_key_num--;
                                // 如果是目的节点，输出finish和源节点信息，并保存到finish_req_map中
                                // std::cout << "finish! src_name: " << src_node.ip_name << std::endl;
                                if (finish_req_map.find(src_node.ip_name) == finish_req_map.end())
                                {
                                    finish_req_map[src_node.ip_name] = 1;
                                }
                                else
                                {
                                    finish_req_map[src_node.ip_name]++;
                                }
                            }
                            else
                            {
                                // 如果不是目的节点，查询下一跳节点
                                node_inf next_node;
                                get_next_node_inf(&now_node, &dst_node, &next_node);
                                // 获取源节点信息
                                node_inf src_node;
                                get_node_inf(inet_ntoa(*(struct in_addr *)&data_packet.data.src_ip), &src_node);
                                // 获取上一跳节点信息
                                char ip[16];
                                int port;
                                get_socket_info(connfd, ip, &port);
                                node_inf last_node;
                                get_node_inf(ip, &last_node);
                                key_pool_map[last_node.ip_name].decrypt_key_num--;
                                // 将请求放入RSVP_request_map中
                                for (auto re_it = RSVP_request_map[next_node.ip_name].begin(); re_it != RSVP_request_map[next_node.ip_name].end(); re_it++)
                                {
                                    if (re_it->src_name == src_node.ip_name && re_it->dst_name == dst_node.ip_name)
                                    {
                                        re_it->packet_num++; // 记录下一跳节点的请求包数目
                                    }
                                }
                                // 输出收到中转数据包提示
                                // std::cout << "KEYRELAY_PACKET: " << src_node.ip_name << " to " << dst_node.ip_name << std::endl;
                            }
                        }
                        else if (data_packet.data.packet_flag == ECN_PACKET)
                        {
                            // 输出当前时间
                            auto now_time = std::chrono::high_resolution_clock::now();
                            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now_time - begin_time);
                            std::cout << "ECN_PACKET: " << duration.count() << "ms" << std::endl;
                            state = FAST_RECOVERY; // 进入快速恢复状态
                        }
                        else if (data_packet.data.packet_flag == RSVP_PROBE_PACKET) // RSVP探测包，检查当前密钥池内密钥量以及速率是否满足要求，如果满足则转发给下一跳节点，否则直接结束该过程
                        {
                            // 输出当前时间
                            auto now_time = std::chrono::high_resolution_clock::now();
                            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now_time - begin_time);
                            //  获取源节点信息
                            node_inf src_node;
                            get_node_inf(inet_ntoa(*(struct in_addr *)&data_packet.data.src_ip), &src_node);
                            // 获取目的节点信息
                            node_inf dst_node;
                            get_node_inf(inet_ntoa(*(struct in_addr *)&data_packet.data.dst_ip), &dst_node);
                            // 如果是目的节点，则沿着之前路径发送RSVP_LOCK包
                            if (now_node.ip_name == dst_node.ip_name)
                            {
                                data_packet.data.src_ip = dst_node.ip_net;
                                data_packet.data.dst_ip = src_node.ip_net;
                                data_packet.data.packet_flag = RSVP_LOCK_PACKET;
                                node_inf next_node;
                                get_next_node_inf(&now_node, &src_node, &next_node);
                                if (sockfd_map[next_node.ip_name] == -1)
                                {
                                    sockfd_map[next_node.ip_name] = pre_send(dst_map[next_node.ip_name].c_str(), KEYRELAY_PORT);
                                }
                                while (data_packet.send_data(sockfd_map[next_node.ip_name]) == -1)
                                {
                                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                                    printf("send RSVP_LOCK_PACKET failed\n");
                                }
                            }
                            else
                            {
                                // 如果是中间节点，则检查密钥池内密钥量以及速率是否满足要求，如果满足则转发给下一跳节点，否则直接结束该过程
                                node_inf next_node;
                                get_next_node_inf(&now_node, &dst_node, &next_node);
                                // 读取packet_inf字段，判断密钥池内密钥量是否满足要求
                                RSVP_request new_request;
                                new_request.src_name = src_node.ip_name;
                                new_request.dst_name = dst_node.ip_name;
                                new_request.packet_num = 0;
                                RSVP_inf_get(new_request, data_packet.data.packet_inf);
                                // 如果密钥池内密钥量满足要求，则转发给下一跳节点
                                if (key_pool_map[next_node.ip_name].encrypt_key_num >= new_request.bucket_depth_b)
                                {
                                    if (sockfd_map[next_node.ip_name] == -1)
                                    {
                                        sockfd_map[next_node.ip_name] = pre_send(dst_map[next_node.ip_name].c_str(), KEYRELAY_PORT);
                                    }
                                    while (data_packet.send_data(sockfd_map[next_node.ip_name]) == -1)
                                    {
                                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                                        printf("send RSVP_PROBE_PACKET failed\n");
                                    }
                                    printf("RSVP_PROBE_PACKET: %dms, from %s to %s\n", duration.count(), src_node.ip_name.c_str(), dst_node.ip_name.c_str());
                                }
                                else
                                {
                                    // 如果密钥池内密钥量不满足要求，则直接结束该过程
                                    std::cout << "RSVP_PROBE_PACKET: " << duration.count() << "ms, from " << src_node.ip_name << " to " << dst_node.ip_name << " failed" << std::endl;
                                }
                            }
                        }
                        else if (data_packet.data.packet_flag == RSVP_LOCK_PACKET) // RSVP锁定包，锁定路径，将路径上的所有节点的密钥池内密钥量减去RSVP请求中的bucket_depth_b，并生成相应的请求列表
                        {
                            // 输出当前时间
                            auto now_time = std::chrono::high_resolution_clock::now();
                            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now_time - begin_time);
                            //  获取源节点信息,注意反向传播过程中源节点和目的节点的变化
                            node_inf src_node;
                            node_inf dst_node;
                            get_node_inf(inet_ntoa(*(struct in_addr *)&data_packet.data.src_ip), &dst_node);
                            // 获取目的节点信息
                            get_node_inf(inet_ntoa(*(struct in_addr *)&data_packet.data.dst_ip), &src_node);
                            // 如果是目的节点，则激活对应的RSVP请求
                            if (now_node.ip_name == src_node.ip_name)
                            {
                                node_inf last_node;                                  // 获取上一跳节点
                                get_next_node_inf(&now_node, &dst_node, &last_node); // 获取上一跳节点
                                for (auto rq_it = RSVP_request_list.begin(); rq_it != RSVP_request_list.end(); rq_it++)
                                {
                                    if (rq_it->src_name == src_node.ip_name && rq_it->dst_name == dst_node.ip_name)
                                    {
                                        rq_it->active_flag = true;
                                        rq_it->send_beign_time = duration.count();
                                        key_pool_map[last_node.ip_name].encrypt_key_num -= rq_it->bucket_depth_b;
                                        break;
                                    }
                                }
                                printf("RSVP_REQUEST active: %dms, from %s to %s\n", duration.count(), src_node.ip_name.c_str(), dst_node.ip_name.c_str());
                            }
                            else
                            {
                                // 如果是中间节点，则将路径上的所有节点的密钥池内密钥量减去RSVP请求中的bucket_depth_b，并生成相应的请求列表
                                node_inf last_node;
                                get_next_node_inf(&now_node, &dst_node, &last_node);
                                // 读取packet_inf字段，判断密钥池内密钥量是否满足要求
                                RSVP_request new_request;
                                new_request.src_name = src_node.ip_name;
                                new_request.dst_name = dst_node.ip_name;
                                new_request.packet_num = 0;
                                new_request.active_flag = true;
                                new_request.enough_flag = true;
                                RSVP_inf_get(new_request, data_packet.data.packet_inf);
                                // 将路径上的所有节点的密钥池内密钥量减去RSVP请求中的bucket_depth_b
                                key_pool_map[last_node.ip_name].encrypt_key_num -= new_request.bucket_depth_b;
                                // 生成相应的请求列表
                                if (RSVP_request_map.find(last_node.ip_name) == RSVP_request_map.end())
                                {
                                    RSVP_request_map[last_node.ip_name].push_back(new_request);
                                }
                                else
                                {
                                    bool find_flag = false;
                                    for (auto rq_it = RSVP_request_map[last_node.ip_name].begin(); rq_it != RSVP_request_map[last_node.ip_name].end(); rq_it++)
                                    {
                                        if (rq_it->src_name == new_request.src_name && rq_it->dst_name == new_request.dst_name)
                                        {
                                            rq_it->bucket_depth_b += new_request.bucket_depth_b;
                                            find_flag = true;
                                            break;
                                        }
                                    }
                                    if (!find_flag)
                                    {
                                        RSVP_request_map[last_node.ip_name].push_back(new_request);
                                    }
                                }
                                // 输出RSVP_LOCK_PACKET提示
                                std::cout << "RSVP_LOCK_PACKET: " << duration.count() << "ms, from " << src_node.ip_name << " to " << dst_node.ip_name << std::endl;
                                node_inf next_node;
                                get_next_node_inf(&now_node, &src_node, &next_node);
                                // 转发给下一跳节点
                                if (sockfd_map[next_node.ip_name] == -1)
                                {
                                    sockfd_map[next_node.ip_name] = pre_send(dst_map[next_node.ip_name].c_str(), KEYRELAY_PORT);
                                }
                                while (data_packet.send_data(sockfd_map[next_node.ip_name]) == -1)
                                {
                                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                                    printf("send RSVP_LOCK_PACKET failed\n");
                                }
                            }
                        }
                    }
                }
            }
            if (begin_flag == 1)
            {
                // 加载初始请求队列
                for (auto it = RSVP_request_list.begin(); it != RSVP_request_list.end(); it++)
                {
                    // 进行请求探测，发送请求探测包
                    if (std::chrono::high_resolution_clock::now() >= begin_time + std::chrono::milliseconds(it->send_beign_time) && it->active_flag == false && now_node.ip_name == it->src_name)
                    {
                        // 获取源节点信息
                        node_inf src_node;
                        get_node_inf(dst_map[it->src_name], &src_node);
                        // 获取目的节点信息
                        node_inf dst_node;
                        get_node_inf(dst_map[it->dst_name], &dst_node);
                        // 检查路由表，获取下一跳节点信息
                        node_inf next_node;
                        get_next_node_inf(&now_node, &dst_node, &next_node);
                        // 当当前节点密钥量足够时发送请求探测包
                        if (key_pool_map[next_node.ip_name].encrypt_key_num >= it->bucket_depth_b)
                        {
                            packet probe_packet(inet_addr(dst_map[it->src_name].c_str()), inet_addr(dst_map[it->dst_name].c_str()), RSVP_PROBE_PACKET, 0);
                            RSVP_service_rate_calculate(*it);
                            RSVP_inf_set(*it, probe_packet.data.packet_inf);
                            if (sockfd_map[next_node.ip_name] == -1)
                            {
                                sockfd_map[next_node.ip_name] = pre_send(dst_map[next_node.ip_name].c_str(), KEYRELAY_PORT);
                            }
                            while (probe_packet.send_data(sockfd_map[next_node.ip_name]) == -1)
                            {
                                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                                printf("send probe_packet failed\n");
                            }
                        }
                        it->send_beign_time += PROBE_RTT_RSVP;
                    }
                    // 如果到了请求时间且请求已经激活，则将请求加入请求队列
                    if (std::chrono::high_resolution_clock::now() >= begin_time + std::chrono::milliseconds(it->send_beign_time) && it->active_flag == true && now_node.ip_name == it->src_name)
                    {
                        // 获取源节点信息
                        node_inf src_node;
                        get_node_inf(dst_map[it->src_name], &src_node);
                        // 获取目的节点信息
                        node_inf dst_node;
                        get_node_inf(dst_map[it->dst_name], &dst_node);
                        // 检查路由表，获取下一跳节点信息
                        node_inf next_node;
                        get_next_node_inf(&now_node, &dst_node, &next_node);
                        // 将其作为一个新的RSVP请求放入RSVP_request_map中
                        if (RSVP_request_map.find(next_node.ip_name) == RSVP_request_map.end())
                        {
                            RSVP_request_map[next_node.ip_name].push_back(*it);
                        }
                        else
                        {
                            bool find_flag = false;
                            for (auto it2 = RSVP_request_map[next_node.ip_name].begin(); it2 != RSVP_request_map[next_node.ip_name].end(); it2++)
                            {
                                if (it2->src_name == it->src_name && it2->dst_name == it->dst_name)
                                {
                                    it2->packet_num += it->packet_num;
                                    find_flag = true;
                                }
                            }
                            if (!find_flag)
                            {
                                RSVP_request_map[next_node.ip_name].push_back(*it);
                            }
                        }
                        it->src_name = "DELETE"; // 将其标记为删除
                    }
                }
                // 遍历请求队列，发送请求
                for (auto it = RSVP_request_map.begin(); it != RSVP_request_map.end(); it++)
                {
                    if (it->second.size() > 0)
                    {
                        for (auto re_it = it->second.begin(); re_it != it->second.end(); re_it++)
                        {
                            if (std::chrono::high_resolution_clock::now() >= begin_time + std::chrono::milliseconds(re_it->send_beign_time) && re_it->active_flag == true && re_it->bucket_depth_b > 0 && re_it->packet_num > 0)
                            {
                                // 输出当前时间
                                auto now_time = std::chrono::high_resolution_clock::now();
                                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now_time - begin_time);
                                // 发送请求
                                packet key_packet(inet_addr(dst_map[re_it->src_name].c_str()), inet_addr(dst_map[re_it->dst_name].c_str()), KEYRELAY_PACKET, 0);
                                key_packet.set_key_zero();
                                // 检查socket是否存在
                                if (sockfd_map[it->first] == -1)
                                {
                                    sockfd_map[it->first] = pre_send(dst_map[it->first].c_str(), KEYRELAY_PORT);
                                }
                                while (key_packet.send_data(sockfd_map[it->first]) == -1)
                                {
                                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                                    printf("send key_packet failed\n");
                                }
                                // 减少密钥池中的密钥数量
                                re_it->bucket_depth_b--;
                                // 当请求密钥池中的密钥数量为0时，将其标记为非充足请求
                                if (re_it->bucket_depth_b == 0)
                                {
                                    re_it->enough_flag = false;
                                }
                                // 请求密钥量减少
                                re_it->packet_num--;
                                // 计算下一次发送的时间
                                if (re_it->enough_flag == true)
                                {
                                    re_it->send_beign_time = duration.count() + ceil(KEYFILE_SIZE * 8.0 * 1000.0 / re_it->service_rate_R); // 单位为ms
                                }
                                else
                                {
                                    re_it->send_beign_time = duration.count() + round(KEYFILE_SIZE * 8.0 / (re_it->send_rate_r * 100 * 10 / 2.0)); // 单位为ms,十倍
                                }
                                send_time_out << duration.count() << std::endl;
                                // 当请求包数目为0时，将其标记为非活跃请求,待补充：退出机制
                            }
                        }
                    }
                }
                // 收集数据并存储在表格中，需要收集的数据包括，当前时间，密钥池中的密钥数量，密钥池的速率，请求队列中的请求完成的包数目
                auto now_time = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now_time - begin_time);
                if (duration.count() >= collect_time)
                {
                    // 输出当前时间
                    out << duration.count() << ","; // 当前时间
                    // 输出密钥池中的密钥数量
                    for (auto it = key_pool_map.begin(); it != key_pool_map.end(); it++)
                    {
                        out << it->second.encrypt_key_num << "," << it->second.decrypt_key_num << "," << it->second.key_rate << ",";
                    }
                    // 输出请求队列中的请求完成的包数目
                    for (auto it = finish_req_map.begin(); it != finish_req_map.end(); it++)
                    {
                        out << it->second << ",";
                    }
                    // 输出请求队列中的请求丢包数目
                    for (auto it = drop_req_map.begin(); it != drop_req_map.end(); it++)
                    {
                        out << it->second << ",";
                    }
                    out << std::endl;
                    collect_time += collect_interval;
                }
            }
        }
    }
    return 0;
}