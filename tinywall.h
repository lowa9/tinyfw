// tinywall.h
// 内核中用到的数据结构
#ifndef TINYWALL_H
#define TINYWALL_H
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/fs.h>      // 包含文件操作相关的头文件
#include <linux/uaccess.h> // 包含用户空间访问相关的头文件
#include "public.h"

#define MODULE_NAME "tinywall"

/* >----------------------------------rule entity----------------------------------<*/
typedef struct tinywall_rule
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
    struct list_head list;
} tinywall_rule;

/* >----------------------------------conn entity----------------------------------<*/
typedef struct tinywall_conn
{
    __be32 saddr;
    __be32 daddr;
    __u8 protocol;
    union
    {
        struct icmp
        {
            __u8 type;
            __u8 code;
        } icmp;
        struct tcp
        {
            __be16 sport;
            __be16 dport;
            __u8 state;
        } tcp;
        struct udp
        {
            __be16 sport;
            __be16 dport;
        } udp;
    };
    __be64 timeout;
    struct hlist_node node;
} tinywall_conn;

typedef struct tinywall_log
{
    __be32 idx;
    __be64 ts;
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
    __be16 len;
    __be32 action;
    struct list_head node;
} tinywall_log;

/* >----------------------------------规则表----------------------------------<*/
struct tinywall_rule_table
{
    rwlock_t lock; // 读写锁
    __u32 rule_count;
    struct list_head head; // 哈希链表头
};

/* >----------------------------------连接表----------------------------------<*/
struct tinywall_conn_table
{
    rwlock_t lock;
    __u32 conn_count;
    struct hlist_head table[HASH_SIZE];
};

/* >----------------------------------日志表----------------------------------<*/
struct tinywall_log_table
{
    struct mutex lock;
    unsigned int log_num;
    struct list_head head;
};
/* >----------------------------------函数声明----------------------------------<*/
int tinywall_rule_add(tinywall_rule *new_rule);

int tinywall_rule_remove(unsigned int rule_id);

void tinywall_rules_list(void);

void tinywall_rules_clear(void);

void tinywall_conn_show(void);

void tinywall_log_show(void);

struct tinywall_conn *tinywall_connection_create(struct iphdr *iph);

struct tinywall_rule *tinywall_rule_match(struct tinywall_conn *conn);
// // hash函数
// static inline size_t tinywall_hash(struct tinywall_conn *conn)
// {
//     size_t hash = 0;
//     hash = jhash_2words(ntohs(conn->saddr), ntohs(conn->daddr), hash);
//     hash = jhash_2words(conn->protocol, 0, hash);
//     switch (conn->protocol)
//     {
//     case IPPROTO_TCP:
//         hash = jhash_2words(ntohs(conn->tcp.sport), ntohs(conn->tcp.dport), hash);
//         break;
//     case IPPROTO_UDP:
//         hash = jhash_2words(ntohs(conn->udp.sport), ntohs(conn->udp.dport), hash);
//         break;
//     case IPPROTO_ICMP:
//         hash = jhash_2words(conn->icmp.type, conn->icmp.code, hash);
//         break;
//     }
//     return hash % HASH_SIZE;
// }

// 修改后的哈希函数
static inline size_t tinywall_hash(struct tinywall_conn *conn)
{
    size_t hash = 0;

    // 确保源地址和目的地址是有序的
    __be32 addr1 = conn->saddr;
    __be32 addr2 = conn->daddr;
    __be16 port1 = 0;
    __be32 port2 = 0;
    
    u32 protocol_32 = (u32)conn->protocol;
    if (ntohl(addr1) > ntohl(addr2)) {
        swap(addr1, addr2);
    }

    // 计算源地址和目的地址的哈希值
    hash = jhash_2words(ntohl(addr1), ntohl(addr2), hash);
    // 计算协议的哈希值
    hash = jhash_2words(protocol_32, 0, hash);

    // 根据协议类型进一步计算哈希值
    switch (conn->protocol)
    {
    case IPPROTO_TCP:
        // 确保源端口和目的端口是有序的
        port1 = conn->tcp.sport;
        port2 = conn->tcp.dport;
        if (ntohs(port1) > ntohs(port2)) {
            swap(port1, port2);
        }
        hash = jhash_2words(ntohs(port1), ntohs(port2), hash);
        break;
    case IPPROTO_UDP:
        // 确保源端口和目的端口是有序的
        port1 = conn->udp.sport;
        port2 = conn->udp.dport;
        if (ntohs(port1) > ntohs(port2)) {
            swap(port1, port2);
        }
        hash = jhash_2words(ntohs(port1), ntohs(port2), hash);
        break;
    case IPPROTO_ICMP:
        break;
    }
    // 返回最终的哈希值
    return hash % HASH_SIZE;
}
#endif
