// tinywall.c
#include "tinywall.h"

#ifdef __BIG_ENDIAN__
#define htonll(x) (x)
#define ntohll(x) (x)
#else
#define htonll(x) (((__u64)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) (((__u64)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif
#define tinywall_PR_INFO(...) pr_info(__VA_ARGS__)
#define ktime_add_sec(kt, sval) (ktime_add_ns((kt), (sval) * NSEC_PER_SEC))

static unsigned int tinywall_CLEAN_CONN_INVERVAL_SEC = 10;
static int default_timeout_tcp = 300;
static int default_timeout_udp = 180;
static int default_timeout_icmp = 100;
static int default_timeout_others = 100;
static unsigned int default_action = NF_ACCEPT;
static unsigned short default_logging = 1;
// 初始化规则链表和锁
static struct tinywall_rule_table rule_table;
// 初始化连接表
struct tinywall_conn_table conn_table;
// 初始化日志表
struct tinywall_logtable log_table;
// 连接超时定时器表
static struct timer_list conn_timer;

/* >----------------------------------规则表部分----------------------------------<*/
// RULE TABLE INIT FUNCTION
void tinywall_rule_table_init(void)
{
    // 初始化规则链表和锁
    INIT_LIST_HEAD(&rule_table.head);
    rwlock_init(&rule_table.lock);
    rule_table.rule_count = 0;
    return;
}
// 弃用
//  struct tinywall_rule *tinywall_rule_made_from_conn(struct tinywall_conn *conn)
//  {
//      struct tinywall_rule *rule = (struct tinywall_rule *)kmalloc(sizeof(struct tinywall_rule), GFP_KERNEL);
//      rule->src_ip = conn->saddr;
//      rule->dst_ip = conn->daddr;
//      rule->protocol = conn->protocol;
//      rule->logging = default_logging;
//      switch (conn->protocol)
//      {
//      case IPPROTO_TCP:
//          rule->src_port_min = rule->src_port_max = conn->tcp.sport;
//          rule->dst_port_min = rule->dst_port_max = conn->tcp.dport;
//          rule->action = default_action;
//          break;
//      case IPPROTO_UDP:
//          rule->src_port_min = rule->src_port_max = conn->udp.sport;
//          rule->dst_port_min = rule->dst_port_max = conn->udp.dport;
//          rule->action = default_action;
//          break;
//      case IPPROTO_ICMP:
//          rule->src_port_min = rule->src_port_max = 0;
//          rule->dst_port_min = rule->dst_port_max = 0;
//          rule->action = default_action;
//          break;
//      default:
//          return NULL;
//      }
//      return NULL;
//  }
//  RULE TABLE ADD FUNCTION
int tinywall_rule_add(tinywall_rule *new_rule)
{
    if (!new_rule)
        return -ENOMEM;

    tinywall_rule *rule = kmalloc(sizeof(*rule), GFP_KERNEL);
    if (!rule)
        return -ENOMEM;
    rule->src_ip = new_rule->src_ip;
    rule->dst_ip = new_rule->dst_ip;
    rule->src_port_min = new_rule->src_port_min;
    rule->src_port_max = new_rule->src_port_max;
    rule->dst_port_min = new_rule->dst_port_min;
    rule->dst_port_max = new_rule->dst_port_max;
    rule->protocol = new_rule->protocol;
    rule->action = new_rule->action;
    rule->smask = new_rule->smask;
    rule->dmask = new_rule->dmask;
    rule->logging = new_rule->logging;
    printk("tinywall_rule_add");
    write_lock(&rule_table.lock);
    list_add_tail(&rule->list, &rule_table.head);
    rule_table.rule_count++;
    write_unlock(&rule_table.lock);

    // 将 __be32 类型的 IP 地址转换为 struct in_addr 类型
    struct in_addr src_ip, dst_ip;
    src_ip.s_addr = rule->src_ip;
    dst_ip.s_addr = rule->dst_ip;
    printk(KERN_INFO MODULE_NAME ": Add a new rule: %pI4:%d-%d smask:%d -> %pI4:%d-%d dmask:%d, proto: %u, action: %u, logging: %u\n",
           &src_ip, ntohs(rule->src_port_min), ntohs(rule->src_port_max), ntohs(rule->smask),
           &dst_ip, ntohs(rule->dst_port_min), ntohs(rule->dst_port_max), ntohs(rule->dmask),
           ntohs(rule->protocol), ntohs(rule->action), ntohs(rule->logging));
    return 0;
}

// RULE DEL FUNCTION
int tinywall_rule_remove(unsigned int rule_id)
{
    tinywall_rule *rule;
    bool found = 0;
    int rule_number = 0;
    printk("tinywall_rule_remove: rule_id=%d\n", rule_id);
    write_lock(&rule_table.lock);
    list_for_each_entry(rule, &rule_table.head, list)
    {
        rule_number++;
        if (rule_number == rule_id)
        {
            list_del(&rule->list);
            printk(KERN_INFO MODULE_NAME ": Deleted rule %d\n", rule_number);
            kfree(rule);
            found = 1;
            break;
        }
    }
    write_unlock(&rule_table.lock);
    if (!found)
    {
        printk(KERN_ERR MODULE_NAME ": Rule %d not found\n", rule_id);
        return -EINVAL;
    }
    return 0;
}

// RULE LIST FUNCTION
void tinywall_rules_list(void)
{
    struct tinywall_rule *rule;
    bool has_rules = false;
    int rule_number = 0; // 用于记录规则的序号

    read_lock(&rule_table.lock);
    // 遍历 rule_table
    list_for_each_entry(rule, &rule_table.head, list)
    {
        has_rules = true;
        rule_number++;
        struct in_addr src_ip, dst_ip; // 将 __be32 类型的 IP 地址转换为 struct in_addr 类型
        src_ip.s_addr = rule->src_ip;
        dst_ip.s_addr = rule->dst_ip;
        printk(KERN_INFO MODULE_NAME ":[%d]: %pI4:%d-%d smask:%d -> %pI4:%d-%d dmask:%d, proto: %u, action: %u, logging: %u\n",
               rule_number,
               &src_ip, ntohs(rule->src_port_min), ntohs(rule->src_port_max), ntohs(rule->smask),
               &dst_ip, ntohs(rule->dst_port_min), ntohs(rule->dst_port_max), ntohs(rule->dmask),
               ntohs(rule->protocol), ntohs(rule->action), ntohs(rule->logging));
    }

    // 如果没有规则，输出 "NO RULES"
    if (!has_rules)
    {
        printk(KERN_INFO MODULE_NAME ": NO RULES\n");
    }

    read_unlock(&rule_table.lock);
    return;
}

// RULE CLEAR FUNCTION
void tinywall_rules_clear(void)
{

    struct tinywall_rule *rule, *tmp;

    write_lock(&rule_table.lock);
    list_for_each_entry_safe(rule, tmp, &rule_table.head, list)
    {
        list_del(&rule->list);
        kfree(rule);
    }
    printk(KERN_INFO MODULE_NAME ": Cleared all rules\n");
    write_unlock(&rule_table.lock);
}

// RULE TABLE DESTROY FUNCTION
void tinywall_rule_table_destroy(void)
{
    struct tinywall_rule *rule, *tmp;

    // 清空规则链表
    write_lock(&rule_table.lock);
    list_for_each_entry_safe(rule, tmp, &rule_table.head, list)
    {
        list_del(&rule->list);
        kfree(rule);
    }
    write_unlock(&rule_table.lock);
}

// 查找是否存在这个rule
struct tinywall_rule *tinywall_rule_match(struct tinywall_conn *conn)
{
    bool flag = false;
    struct tinywall_rule *rule = NULL;

    read_lock(&rule_table.lock);
    list_for_each_entry(rule, &rule_table.head, list)
    {
        if (!(conn->protocol == rule->protocol &&
              (conn->saddr & rule->smask) == (rule->src_ip & rule->smask) &&
              (conn->daddr & rule->dmask) == (rule->dst_ip & rule->dmask)))
        {
            continue;
        }
        switch (conn->protocol)
        {
        case IPPROTO_TCP:
            flag = conn->tcp.sport >= rule->src_port_min &&
                   conn->tcp.sport <= rule->src_port_max &&
                   conn->tcp.dport >= rule->dst_port_min &&
                   conn->tcp.dport <= rule->dst_port_max;
            break;
        case IPPROTO_UDP:
            flag = conn->udp.sport >= rule->src_port_min &&
                   conn->udp.sport <= rule->src_port_max &&
                   conn->udp.dport >= rule->dst_port_min &&
                   conn->udp.dport <= rule->dst_port_max;
            break;
        case IPPROTO_ICMP:
            flag = true;
            break;
        default:
            flag = true;
        }
        if (flag)
            break;
    }
    read_unlock(&rule_table.lock);

    return flag ? rule : NULL;

    return NULL;
}
/* >----------------------------------连接表部分----------------------------------<*/
/* CONNTABLE INIT FUNCTIONS */
void tinywall_conn_table_init(void)
{
    int i = 0;
    // INIT_LIST_HEAD(&conn_table->table);
    for (i = 0; i < HASH_SIZE; i++)
    {
        INIT_HLIST_HEAD(&conn_table.table[i]);
    }
    rwlock_init(&conn_table.lock);
    conn_table.conn_count = 0;
    return;
}

struct tinywall_conn *tinywall_connection_create(struct iphdr *iph)
{
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    struct icmphdr *icmph = NULL;
    struct tinywall_conn *conn = kmalloc(sizeof(*conn), GFP_KERNEL);
    if (!conn)
        return NULL;
    conn->saddr = iph->saddr;
    conn->daddr = iph->daddr;
    conn->protocol = iph->protocol;
    switch (iph->protocol)
    {
    case IPPROTO_TCP:
        tcph = (void *)iph + iph->ihl * 4;
        conn->tcp.sport = tcph->source;
        conn->tcp.dport = tcph->dest;
        conn->timeout =
            htonll(ktime_add_sec(ktime_get_real(), default_timeout_tcp));
        break;
    case IPPROTO_UDP:
        udph = (void *)iph + iph->ihl * 4;
        conn->udp.sport = udph->source;
        conn->udp.dport = udph->dest;
        conn->timeout =
            htonll(ktime_add_sec(ktime_get_real(), default_timeout_udp));
        break;
    case IPPROTO_ICMP:
        icmph = (void *)iph + iph->ihl * 4;
        conn->icmp.type = icmph->type;
        conn->icmp.code = icmph->code;
        conn->timeout = htonll(ktime_add_sec(ktime_get_real(), default_timeout_icmp));
        break;
    default:
        conn->timeout =
            conn->timeout = htonll(ktime_add_sec(ktime_get_real(), default_timeout_others));
    }
    return conn;
}

// 添加一个连接
void tinywall_conn_add(struct tinywall_conn *conn)
{
    size_t hash = tinywall_hash(conn);

    write_lock(&conn_table.lock);
    hlist_add_head(&conn->node, &conn_table.table[hash]);
    write_unlock(&conn_table.lock);
}

// 根据当前conn获得完整的连接,好像有点多余了...
struct tinywall_conn *tinywall_conn_get_entry(struct tinywall_conn *conn)
{
    if (!conn)
    {
        // printk(KERN_ERR MODULE_NAME ": conn is NULL\n");
        return NULL;
    }
    read_lock(&conn_table.lock);
    size_t hash = tinywall_hash(conn);
    struct tinywall_conn *entry;
    hlist_for_each_entry(entry, &conn_table.table[hash], node)
    {
        if (entry->saddr == conn->saddr &&
            entry->daddr == conn->daddr &&
            entry->protocol == conn->protocol &&
            (entry->protocol == IPPROTO_TCP ? (entry->tcp.sport == conn->tcp.sport && entry->tcp.dport == conn->tcp.dport) : (entry->protocol == IPPROTO_UDP ? (entry->udp.sport == conn->udp.sport && entry->udp.dport == conn->udp.dport) : (entry->icmp.type == conn->icmp.type && entry->icmp.code == conn->icmp.code))))
        {
            return entry;
        }
    }
    read_unlock(&conn_table.lock);
    return NULL;
}

// 查询是否存在这个连接
bool tinywall_conn_match(struct tinywall_conn *conn, bool is_reverse)
{
    if (!conn)
    {
        printk(KERN_ERR MODULE_NAME ": conn is NULL\n");
        return false;
    }

    // 反向连接
    if (is_reverse)
    {
        swap(conn->saddr, conn->daddr);
        switch (conn->protocol)
        {
        case IPPROTO_ICMP: // 没有所谓的连接端口,只有type和code
            break;
        case IPPROTO_TCP:
            swap(conn->tcp.sport, conn->tcp.dport);
            break;
        case IPPROTO_UDP:
            swap(conn->udp.sport, conn->udp.dport);
            break;
        default:
            break;
        }
    }

    read_lock(&conn_table.lock);
    size_t hash = tinywall_hash(conn);
    struct tinywall_conn *entry;
    hlist_for_each_entry(entry, &conn_table.table[hash], node)
    {
        if (entry->saddr == conn->saddr &&
            entry->daddr == conn->daddr &&
            entry->protocol == conn->protocol &&
            (entry->protocol == IPPROTO_TCP ? (entry->tcp.sport == conn->tcp.sport && entry->tcp.dport == conn->tcp.dport) : (entry->protocol == IPPROTO_UDP ? (entry->udp.sport == conn->udp.sport && entry->udp.dport == conn->udp.dport) : (entry->icmp.type == conn->icmp.type && entry->icmp.code == conn->icmp.code))))
        {
            return true;
        }
    }
    read_unlock(&conn_table.lock);
    return false;
}

// 销毁连接表
static void tinywall_conn_table_destroy(void)
{
    int i;
    struct tinywall_conn *conn;
    struct hlist_node *tmp;
    // 获取写锁
    write_lock(&conn_table.lock);

    // 遍历哈希表中的每个桶
    for (i = 0; i < HASH_SIZE; i++)
    {
        // 遍历桶中的每个连接项
        hlist_for_each_entry_safe(conn, tmp, &conn_table.table[i], node)
        {
            // 从哈希表中删除连接项
            hlist_del(&conn->node);

            // 释放连接项占用的内存
            kfree(conn);
        }
    }
    // 释放哈希表本身（如果它是动态分配的）
    // 注意：这里假设哈希表是静态分配的，不需要释放
    // 如果是动态分配的，可以使用 kfree(table->table);
    // 重置连接计数
    conn_table.conn_count = 0;
    // INIT_LIST_HEAD(&conn_table->table);
    for (i = 0; i < HASH_SIZE; i++)
    {
        INIT_HLIST_HEAD(&conn_table.table[i]);
    }
    // 释放读写锁
    write_unlock(&conn_table.lock);
}

void tinywall_conn_table_clean_by_timer(struct tinywall_conn_table *table)
{
    int i = 0;
    struct hlist_node *tmp;
    struct tinywall_conn *conn;
    printk(KERN_ERR MODULE_NAME ": Clean the connection table by timer");
    write_lock(&table->lock);
    hlist_for_each_entry_safe(conn, tmp, &table->table[i], node)
    {
        struct in_addr src_ip, dst_ip;
        src_ip.s_addr = conn->saddr;
        dst_ip.s_addr = conn->daddr;
        if (!ktime_before(ktime_get_real(), ntohll(conn->timeout))) // 当前时间大于后面的conn->timeout,说明超时
        {
            switch (conn->protocol)
            {
            case IPPROTO_TCP:
                tinywall_PR_INFO("Delete connection: [TCP] %pI4,%d > %pI4,%d",
                                 &src_ip, ntohs(conn->tcp.sport),
                                 &dst_ip, ntohs(conn->tcp.dport));
                break;
            case IPPROTO_UDP:
                tinywall_PR_INFO("Delete connection: [UDP] %pI4,%d > %pI4,%d",
                                 &src_ip, ntohs(conn->udp.sport),
                                 &dst_ip, ntohs(conn->udp.dport));
                break;
            case IPPROTO_ICMP:
                tinywall_PR_INFO("Delete connection: [ICMP] %pI4 > %pI4",
                                 &src_ip, &dst_ip);
                break;
            default:
                break;
            }
            hash_del(&conn->node);
            kfree(conn);
            table->conn_count--;
        }
    }
    write_unlock(&table->lock);
}
void tinywall_timer_callback(struct timer_list *t)
{
    tinywall_conn_table_clean_by_timer(&conn_table);
    conn_timer.expires = jiffies + tinywall_CLEAN_CONN_INVERVAL_SEC * HZ;
    add_timer(&conn_timer);
}

/* >----------------------------------日志部分----------------------------------<*/

// 创建日志
struct tinywall_log *tinywall_log_create(struct sk_buff *skb, unsigned int action)
{
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    struct icmphdr *icmph = NULL;
    struct tinywall_log *log = kvzalloc(sizeof(*log), GFP_KERNEL);
    if (!log)
        return NULL;

    log->ts = htonll(ktime_get_real());
    log->saddr = iph->saddr;
    log->daddr = iph->daddr;
    log->protocol = iph->protocol;
    log->len = iph->tot_len;
    log->action = htonl(action);
    switch (iph->protocol)
    {
    case IPPROTO_TCP:
        tcph = (void *)iph + iph->ihl * 4;
        log->tcp.sport = tcph->source;
        log->tcp.dport = tcph->dest;
        break;
    case IPPROTO_UDP:
        udph = (void *)iph + iph->ihl * 4;
        log->udp.sport = udph->source;
        log->udp.dport = udph->dest;
        break;
    case IPPROTO_ICMP:
        icmph = (void *)iph + iph->ihl * 4;
        log->icmp.type = icmph->type;
        log->icmp.code = icmph->code;
        break;
    default:
        break;
    }

    return log;
}

// 初始化日志表
void tinywall_log_table_init(void)
{
    // 初始化规则链表和锁
    INIT_LIST_HEAD(&log_table.head);
    mutex_init(&log_table.lock);
    log_table.log_num = 0;
    return;
}

void tinywall_log_add(struct tinywall_log *log)
{
    mutex_lock(&log_table.lock);
    log->idx = htonl(log_table.log_num);
    list_add_tail(&log->node, &log_table.head);
    log_table.log_num++;
    mutex_unlock(&log_table.lock);
}

// 日志展示

void tinywall_log_show(void)
{
    struct tinywall_log *log;
    struct file *file;
    mm_segment_t oldfs;
    char buffer[4096]; // 用于存储日志信息的缓冲区

    // 打开文件，使用 O_WRONLY | O_CREAT | O_APPEND 选项
    file = filp_open("./log.txt", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (IS_ERR(file))
    {
        printk(KERN_ERR "Failed to open log.txt\n");
        return;
    }

    mutex_lock(&log_table.lock);
    // 锁定日志表
    list_for_each_entry(log, &log_table.head, node)
    {
        // 格式化基本日志信息到缓冲区
        snprintf(buffer, sizeof(buffer), "Index: %u, Timestamp: %llu, Source: %u, Destination: %u, Protocol: %u\n",
                 ntohl(log->idx), (unsigned long long)ntohll(log->ts),
                 ntohl(log->saddr), ntohl(log->daddr), log->protocol);

        // 根据协议类型添加详细信息
        if (log->protocol == IPPROTO_TCP)
        {
            snprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer),
                     "TCP - Source Port: %u, Destination Port: %u, State: %u\n",
                     ntohs(log->tcp.sport), ntohs(log->tcp.dport), log->tcp.state);
        }
        else if (log->protocol == IPPROTO_UDP)
        {
            snprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer),
                     "UDP - Source Port: %u, Destination Port: %u\n",
                     ntohs(log->udp.sport), ntohs(log->udp.dport));
        }
        else if (log->protocol == IPPROTO_ICMP)
        {
            snprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer),
                     "ICMP - Type: %u, Code: %u\n",
                     log->icmp.type, log->icmp.code);
        }

        // 将缓冲区内容写入文件
        vfs_write(file, buffer, strlen(buffer), &file->f_pos);
    }
    mutex_unlock(&log_table.lock);

    // 关闭文件
    filp_close(file, NULL);
}

// 销毁日志表
void tinywall_log_table_destroy(void)
{
    struct tinywall_log *log, *tmp;
    mutex_lock(&log_table.lock);
    list_for_each_entry_safe(log, tmp, &log_table.head, node)
    {
        list_del(&log->node);
        kfree(log);
    }
    log_table.log_num = 0;
    INIT_LIST_HEAD(&log_table.head);
    mutex_unlock(&log_table.lock);
}
/* >----------------------------------子模块部分----------------------------------<*/
static unsigned int firewall_hook(void *priv,
                                  struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    bool new_conn = false;
    int res = 0;
    unsigned int action = default_action;
    struct iphdr *iph = ip_hdr(skb);
    if (!iph)
    {
        printk(KERN_ERR MODULE_NAME ": Invalid IP header.\n");
        return NF_DROP;
    }

    struct tinywall_conn *conn = tinywall_connection_create(iph);
    if (!conn)
    {
        printk(KERN_ERR MODULE_NAME ": Failed to create connection.\n");
        return NF_DROP;
    }

    printk(KERN_INFO MODULE_NAME ": Created connection: saddr=%pI4, daddr=%pI4, protocol=%u",
           &conn->saddr, &conn->daddr, conn->protocol);

    if (conn->protocol == IPPROTO_TCP)
    {
        printk(", sport=%u, dport=%u, state=%u\n",
               ntohs(conn->tcp.sport), ntohs(conn->tcp.dport), conn->tcp.state);
    }
    else if (conn->protocol == IPPROTO_UDP)
    {
        printk(", sport=%u, dport=%u\n",
               ntohs(conn->udp.sport), ntohs(conn->udp.dport));
    }
    else if (conn->protocol == IPPROTO_ICMP)
    {
        printk(", type=%u, code=%u\n",
               conn->icmp.type, conn->icmp.code);
    }
    else
    {
        printk("\n");
    }

    struct tinywall_rule *rule = NULL;
    struct tinywall_log *log = NULL;

    // 在conn_table中查找当前连接
    // 一个连接分双向,那么就需要有个标志位来选择是什么方向来的包
    if (tinywall_conn_match(conn, true) || tinywall_conn_match(conn, false))
    {
        printk(KERN_INFO MODULE_NAME ": Connection exists, ACCEPT.\n");
        action = NF_ACCEPT;
        if (default_logging)
        {
            log = tinywall_log_create(skb, NF_ACCEPT);
        }
        goto out;
    }

    // 没匹配到现有连接,从规则表中查找
    // 如果是tcp,那么肯定是SYN包来请求新建连接
    if (iph->protocol == IPPROTO_TCP && tcp_flag_word((void *)iph + iph->ihl * 4) != TCP_FLAG_SYN)
    {
        printk(KERN_INFO MODULE_NAME ": Not a SYN packet, DROP.\n");
        action = NF_DROP;
        if (default_logging)
        {
            log = tinywall_log_create(skb, NF_DROP);
            tinywall_log_add(log);
        }
        goto out;
    }

    // 如果是icmp包,那么一定是echo请求
    if (iph->protocol == IPPROTO_ICMP)
    {
        struct icmphdr *icmphr = (void *)iph + iph->ihl * 4;
        if (icmphr->type != ICMP_ECHO)
        {
            printk(KERN_INFO MODULE_NAME ": Not a echo request, DROP.\n");
            action = NF_DROP;
            if (default_logging)
            {
                log = tinywall_log_create(skb, NF_DROP);
                tinywall_log_add(log);
            }
            goto out;
        }
    }

    // 开始匹配rule_table的各个entry
    rule = tinywall_rule_match(conn);
    if (rule)
    {
        res = ntohl(rule->action);
        if (rule->logging)
        {
            printk(KERN_INFO MODULE_NAME ": Logging enabled.\n");
            log = tinywall_log_create(skb, ntohl(rule->action));
            tinywall_log_add(log);
        }
        printk(KERN_INFO MODULE_NAME ": Rule matched, action: %d\n", res);
        if (res == NF_ACCEPT)
        {
            new_conn = true;
            tinywall_conn_add(conn);
            printk(KERN_INFO MODULE_NAME ": New connection added.\n");
        }
        else
        {
            res = default_action;
            if (default_logging)
            {
                log = tinywall_log_create(skb, default_action);
                tinywall_log_add(log);
            }
            printk(KERN_INFO MODULE_NAME ": No match rules,use the default action.\n");
            if (res == NF_ACCEPT)
            {
                new_conn = true;
                tinywall_conn_add(conn);
                printk(KERN_INFO MODULE_NAME ": New connection added.\n");
            }
        }
    }

out:
    if (!new_conn)
    {
        kfree(conn);
    }
    return res;
}
// struct iphdr *ip_header;
// struct tcphdr *tcp_header;
// struct udphdr *udp_header;
// struct icmphdr *icmp_header;
// tinywall_rule *rule;
// int match = -1; // 匹配动作

// /*空数据包或者空ip头*/
// if (!skb)
// {
//     return NF_ACCEPT;
// }

// ip_header = ip_hdr(skb);

// if (!ip_header)
// {
//     return NF_ACCEPT;
// }

// // 处理ICMP协议
// /*TODO_1:每一个有效ACCEPT都要在连接表中新建连接
// TODO_2:根据rule.logging字段是否记录日志*/
// if (ip_header->protocol == IPPROTO_ICMP)
// {
//     // printk("not tcp");
//     return NF_ACCEPT;
// }

// if (ip_header->protocol == IPPROTO_TCP)
// {
//     tcp_header = tcp_hdr(skb);
//     if (!tcp_header)
//     {
//         printk(KERN_ERR MODULE_NAME ": TCP header is NULL\n");
//         return NF_ACCEPT;
//     }
//     // 检测是否匹配上规则
//     tinywall_rule *rule;
//     read_lock(&rule_table.lock);
//     list_for_each_entry(rule, &rule_table.head, list)
//     {
//         if (((rule->src_ip == ip_header->saddr || rule->src_ip == 0) ||
//              (rule->src_ip & rule->smask) == (ip_header->saddr & rule->smask)) &&
//             ((rule->dst_ip == ip_header->daddr || rule->dst_ip == 0) ||
//              (rule->dst_ip & rule->dmask) == (ip_header->daddr & rule->dmask)) &&
//             (ntohs(tcp_header->source) >= rule->src_port_min && ntohs(tcp_header->source) <= rule->src_port_max) &&
//             (ntohs(tcp_header->dest) >= rule->dst_port_min && ntohs(tcp_header->dest) <= rule->dst_port_max) &&
//             (rule->protocol == ip_header->protocol || rule->protocol == 0))
//         {
//             match = rule->action;
//             break;
//         }
//     }
//     read_unlock(&rule_table.lock);

//     if (match == NF_ACCEPT)
//     {
//         printk(KERN_INFO MODULE_NAME ": Packet matched rule, rule's action is NF_ACCEPT.\n");
//         return NF_ACCEPT;
//     }
//     else if (match == NF_DROP)
//     {
//         printk(KERN_INFO MODULE_NAME ": Packet matched rule, rule's action is NF_DROP.\n");
//         return NF_DROP;
//     }
//     return NF_ACCEPT;

//     if (match == NF_ACCEPT)
//     {
//         printk(KERN_INFO MODULE_NAME ": Packet matched rule, rule's action is NF_ACCEPT.\n");
//         return NF_ACCEPT;
//     }
//     else if (match == NF_DROP)
//     {
//         printk(KERN_INFO MODULE_NAME ": Packet matched rule, rule's action is NF_DROP.\n");
//         return NF_DROP;
//     }
//     return NF_ACCEPT;
// }
// // 默认通过
// return NF_ACCEPT;

// 定义Netfilter钩子
static struct nf_hook_ops firewall_nfho = {
    .hook = firewall_hook,
    .pf = PF_INET,
    //.hooknum = NF_INET_FORWARD,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

// 模块初始化
static int __init firewall_init(void)
{
    int ret;
    // 初始化规则表
    tinywall_rule_table_init();
    // 初始化连接表
    tinywall_conn_table_init();
    // 初始化日志表
    tinywall_log_table_init();
    // 注册Netfilter钩子
    ret = nf_register_net_hook(&init_net, &firewall_nfho);
    if (ret)
    {
        printk(KERN_ERR MODULE_NAME ": Failed to register nethook\n");
        return ret;
    }

    printk(KERN_INFO MODULE_NAME ": Firewall module loaded.\n");
    timer_setup(&conn_timer, tinywall_timer_callback, 0);
    conn_timer.expires = jiffies + HZ * 10;
    add_timer(&conn_timer);
    return 0;
}

// 模块退出
static void __exit firewall_exit(void)
{
    // 注销Netfilter钩子
    nf_unregister_net_hook(&init_net, &firewall_nfho);
    printk(KERN_INFO MODULE_NAME ": Netfilter hook unregistered.\n");
    // 销毁定时器
    del_timer(&conn_timer);
    printk(KERN_INFO MODULE_NAME ": Timer destroyed.\n");
    // 销毁连接表
    tinywall_conn_table_destroy();
    printk(KERN_INFO MODULE_NAME ": Connection table destroyed.\n");
    // 销毁规则表
    tinywall_rule_table_destroy();
    printk(KERN_INFO MODULE_NAME ": Rule table destroyed.\n");
    // 销毁日志表
    tinywall_log_table_destroy();
    printk(KERN_INFO MODULE_NAME ": Log table destroyed.\n");

    printk(KERN_INFO MODULE_NAME ": Firewall module unloaded.\n");
}

module_init(firewall_init);
module_exit(firewall_exit);

EXPORT_SYMBOL(tinywall_rules_list);
EXPORT_SYMBOL(tinywall_rule_remove);
EXPORT_SYMBOL(tinywall_rule_add);
EXPORT_SYMBOL(tinywall_rules_clear);
EXPORT_SYMBOL(tinywall_log_show);
EXPORT_SYMBOL(rule_table);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sun Xiaokai suxiaokai34@gmail.com");
MODULE_DESCRIPTION("A Tiny Netfilter Firewall Module");