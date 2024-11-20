#define NLMSG_MAX_SIZE 65535
#define NETLINK_USER 31
#define HASH_SIZE 128
// 定义过滤规则结构
#define htonll(x) (((__u64)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) (((__u64)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
// 用户空间的 firewall_rule 结构体（没有 struct list_head）
typedef struct tinywall_rule_user
{
    __be32 src_ip;
    __be32 dst_ip;
    __be16 smask;
    __be16 dmask;
    __be16 src_port_min;
    __be16 src_port_max;
    __be16 dst_port_min;
    __be16 dst_port_max;
    __be16 protocol;
    __be16 action;
    __be16 logging;
} tinywall_rule_user;

// 内核空间的 tinywall_conn 结构体
typedef struct tinywall_conn_user
{
    __be32 saddr;
    __be32 daddr;
    __u8 protocol;
    union
    {
        struct
        {
            __u8 type;
            __u8 code;
        } icmp;
        struct
        {
            __be16 sport;
            __be16 dport;
            __u8 state;
        } tcp;
        struct
        {
            __be16 sport;
            __be16 dport;
        } udp;
    };
    __be64 timeout;
} tinywall_conn_user;
// 定义规则操作
enum TINYWALL_REQUEST_TYPE
{
    TINYWALL_TYPE_ADD_RULE,
    TINYWALL_TYPE_DEL_RULE,
    TINYWALL_TYPE_LIST_RULES,
    TINYWALL_TYPE_CLEAR_RULES,
    TINYWALL_TYPE_STORE_RULES,
    TINYWALL_TYPE_LOAD_RULES,
    TINYWALL_TYPE_SHOW_CONNS,
    TINYWALL_TYPE_SHOW_LOGS,
};

// 定义防火墙返回结构
struct TINYWALL_response
{
    __u8 type;
    __be32 len;
    __u8 msg[0];
};

enum TINYWALL_TCP_STATE
{
    TINYWALL_SYN_RECEIVED,
    TINYWALL_SYN_ACK_RECEIVED,
    TINYWALL_TCP_ESTABLISHED
};