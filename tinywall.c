// tinywall.c
#include "tinywall.h"
#define tinywall_PR_INFO(...) pr_info(__VA_ARGS__)
#define ktime_add_sec(kt, sval) (ktime_add_ns((kt), (sval) * NSEC_PER_SEC))

static unsigned int tinywall_CLEAN_CONN_INVERVAL_SEC = 10;
static int default_timeout_tcp = 30;
static int default_timeout_udp = 10;
static int default_timeout_icmp = 10;
static int default_timeout_others = 10;
static int loop_timeout = 10;
static unsigned short default_action = NF_DROP;
static unsigned short default_logging = 1;
// 初始化规则链表和锁
struct tinywall_rule_table rule_table;
// 初始化连接表
struct tinywall_conn_table conn_table;
// 初始化日志表
struct tinywall_log_table log_table;
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

    write_lock(&rule_table.lock);
    list_add_tail(&rule->list, &rule_table.head);
    rule_table.rule_count++;
    write_unlock(&rule_table.lock);
    printk(KERN_INFO MODULE_NAME ": Added successfully!");
    // // 将 __be32 类型的 IP 地址转换为 struct in_addr 类型
    // struct in_addr src_ip, dst_ip;
    // src_ip.s_addr = rule->src_ip;
    // dst_ip.s_addr = rule->dst_ip;
    // printk(KERN_INFO MODULE_NAME ": Add a new rule: %pI4:%d-%d smask:%d -> %pI4:%d-%d dmask:%d, proto: %u, action: %u, logging: %u\n",
    //        &src_ip, ntohs(rule->src_port_min), ntohs(rule->src_port_max), ntohs(rule->smask),
    //        &dst_ip, ntohs(rule->dst_port_min), ntohs(rule->dst_port_max), ntohs(rule->dmask),
    //        ntohs(rule->protocol), ntohs(rule->action), ntohs(rule->logging));
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
        if (rule_number == rule_id)
        {
            list_del(&rule->list);
            printk(KERN_INFO MODULE_NAME ": Deleted rule %d\n", rule_number);
            kfree(rule);
            found = 1;
            break;
        }
        rule_number++;
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
static __be32 tinywall_get_subnet_mask(unsigned int mask_bits)
{
    if (mask_bits == 0)
        return 0;
    else if (mask_bits == 32)
        return cpu_to_be32(0xFFFFFFFF);
    else
        return cpu_to_be32((0xFFFFFFFF << (32 - mask_bits)) & 0xFFFFFFFF);
        //return cpu_to_be32((1 << mask_bits) - 1);
}

struct tinywall_rule *tinywall_rule_match(struct tinywall_conn *conn)
{
    bool flag = false;
    struct tinywall_rule *rule = NULL;
    struct tinywall_rule *tmp = NULL;
    read_lock(&rule_table.lock);
    list_for_each_entry(rule, &rule_table.head, list)
    {
        __be32 src_mask = tinywall_get_subnet_mask(ntohs(rule->smask));
        __be32 dst_mask = tinywall_get_subnet_mask(ntohs(rule->dmask));
        __be32 tmp1 = conn->saddr & src_mask;
        __be32 tmp2 = rule->src_ip & src_mask;
        __be32 tmp3 = conn->daddr & dst_mask;
        __be32 tmp4 = rule->dst_ip & dst_mask;
        printk("conn->saddr:%pI4, conn->daddr:%pI4, src_mask = %pI4, dst_mask = %pI4, rule->saddr = %pI4, rule->daddr = %pI4\n",
               &conn->saddr, &conn->daddr, &src_mask, &dst_mask, &rule->src_ip, &rule->dst_ip);
        if (conn->protocol == ntohs(rule->protocol) && tmp1 == tmp2 && tmp3 == tmp4)
        {
            printk("tmp1:%pI4, tmp2:%pI4, tmp3:%pI4, tmp4:%pI4\n",&tmp1,&tmp2,&tmp3,&tmp4);
            printk(KERN_INFO MODULE_NAME ": MATCHED!\n");
            switch (ntohs(rule->protocol))
            {
            case IPPROTO_TCP:
                flag = (conn->tcp.sport >= rule->src_port_min) &&
                       (conn->tcp.sport <= rule->src_port_max) &&
                       (conn->tcp.dport >= rule->dst_port_min) &&
                       (conn->tcp.dport <= rule->dst_port_max);
                break;
            case IPPROTO_UDP:
                flag = (conn->udp.sport >= rule->src_port_min) &&
                       (conn->udp.sport <= rule->src_port_max) &&
                       (conn->udp.dport >= rule->dst_port_min) &&
                       (conn->udp.dport <= rule->dst_port_max);
                break;
            case IPPROTO_ICMP:
                flag = true;
                break;
            default:
                flag = true;
            }
            if (flag)
            {
                printk(KERN_ERR" RULE_MATCH: flag = true and return rule! tmp1:%pI4, tmp2:%pI4, tmp3:%pI4, tmp4:%pI4",&tmp1,&tmp2,&tmp3,&tmp4);
                tmp = rule;
                break;
            }
        }
        else
        {
            printk(KERN_ERR" RULE_MATCH: NO MATCHED BUT I'M HERE ANYWAY!\n");
        }
    }
    read_unlock(&rule_table.lock);

    return flag ? tmp : NULL;
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
    printk(KERN_ERR " New Hash: %d\n", hash);
    write_lock(&conn_table.lock);
    hlist_add_head(&conn->node, &conn_table.table[hash]);
    conn_table.conn_count++;
    printk(KERN_ERR MODULE_NAME ": Conn added\n");
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
    __be32 addr_max = ntohl(conn->saddr) > ntohl(conn->daddr) ? conn->saddr : conn->daddr;
    __be32 addr_min = ntohl(conn->saddr) > ntohl(conn->daddr) ? conn->daddr : conn->saddr;
    __be16 port_max = 0;
    __be16 port_min = 0;
    read_lock(&conn_table.lock);
    size_t hash = tinywall_hash(conn);
    struct tinywall_conn *entry = NULL;
    struct tinywall_conn *tmp = NULL;
    hlist_for_each_entry(entry, &conn_table.table[hash], node)
    {
        if (conn->protocol == IPPROTO_TCP)
        {
            port_max = conn->saddr == addr_max ? conn->tcp.sport : conn->tcp.dport;
            port_min = conn->saddr == addr_min ? conn->tcp.sport : conn->tcp.dport;
            if ((entry->saddr == addr_max && entry->daddr == addr_min && entry->tcp.sport == port_max && entry->tcp.dport == port_min) || (entry->saddr == addr_min && entry->daddr == addr_max) && entry->tcp.sport == port_min && entry->tcp.dport == port_max)
            {
                tmp = entry;
                break;
            }
        }
        else if (conn->protocol == IPPROTO_UDP)
        {
            port_max = conn->saddr == addr_max ? conn->udp.sport : conn->udp.dport;
            port_min = conn->saddr == addr_min ? conn->udp.sport : conn->udp.dport;
            if ((entry->saddr == addr_max && entry->daddr == addr_min && entry->udp.sport == port_max && entry->udp.dport == port_min) || (entry->saddr == addr_min && entry->daddr == addr_max) && entry->udp.sport == port_min && entry->udp.dport == port_max)
            {
                tmp = entry;
                break;
            }
        }
        else if (conn->protocol == IPPROTO_ICMP)
        {
            if ((entry->saddr == addr_max && entry->daddr == addr_min) || (entry->saddr == addr_min && entry->daddr == addr_max))
            {
                tmp = entry;
                break;
            }
        }
    }
    read_unlock(&conn_table.lock);
    return tmp;
}

// 查询是否存在这个连接
bool tinywall_conn_match(struct tinywall_conn *conn)
{
    return tinywall_conn_get_entry(conn) != NULL;
}

void tinywall_conn_show(void)
{
    struct tinywall_conn *conn;
    struct file *file;
    char buffer[1024]; // 用于存储日志信息的缓冲区
    int i;
    // 打开文件，使用 O_WRONLY | O_CREAT | O_TRUNC 选项
    file = filp_open("./conn_table.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(file))
    {
        printk(KERN_ERR "Failed to open conn_table.txt\n");
        return;
    }

    read_lock(&conn_table.lock);

    // 读锁保护连接表
    for (i = 0; i < HASH_SIZE; i++)
    {
        hlist_for_each_entry(conn, &conn_table.table[i], node)
        {
            printk(KERN_INFO "CONNList: saddr=%pI4, daddr=%pI4, protocol=%u, timeout=%llu\n",
                   &conn->saddr, &conn->daddr, conn->protocol, ntohll(conn->timeout));
            if (conn->protocol == IPPROTO_TCP)
            {
                snprintf(buffer, sizeof(buffer), "TCP - Connection: saddr=%pI4, daddr=%pI4, protocol=TCP, sport=%u, dport=%u, timeout=%llu\n",
                         &conn->saddr, &conn->daddr,
                         ntohs(conn->tcp.sport), ntohs(conn->tcp.dport), ntohll(conn->timeout));
                // 使用 kernel_write 替代 vfs_write 写入文件
                int rs = kernel_write(file, buffer, strlen(buffer), &file->f_pos);
                if (rs < 0)
                {
                    printk(KERN_ERR MODULE_NAME " CONN: kernel_write failed with error %d\n", rs);
                }
                else if (rs != strlen(buffer))
                {
                    printk(KERN_ERR MODULE_NAME " CONN: kernel_write wrote only %d bytes out of %zu\n", rs, strlen(buffer));
                }
                else
                {
                    printk(KERN_INFO MODULE_NAME " CONN: Successfully wrote %d bytes to conn_table.\n", rs);
                }

                memset(buffer, 0, sizeof(buffer)); // 清空缓冲区
            }
            if (conn->protocol == IPPROTO_UDP)
            {
                snprintf(buffer, sizeof(buffer), "UDP - Connection: saddr=%pI4, daddr=%pI4, protocol=UDP, sport=%u, dport=%u,timeout=%llu\n",
                         &conn->saddr, &conn->daddr,
                         ntohs(conn->udp.sport), ntohs(conn->udp.dport), ntohll(conn->timeout));
                // 使用 kernel_write 替代 vfs_write 写入文件
                int rs = kernel_write(file, buffer, strlen(buffer), &file->f_pos);
                if (rs < 0)
                {
                    printk(KERN_ERR MODULE_NAME " CONN: kernel_write failed with error %d\n", rs);
                }
                else if (rs != strlen(buffer))
                {
                    printk(KERN_ERR MODULE_NAME " CONN: kernel_write wrote only %d bytes out of %zu\n", rs, strlen(buffer));
                }
                else
                {
                    printk(KERN_INFO MODULE_NAME " CONN: Successfully wrote %d bytes to conn_table.\n", rs);
                }

                memset(buffer, 0, sizeof(buffer)); // 清空缓冲区
            }
            if (conn->protocol == IPPROTO_ICMP)
            {
                snprintf(buffer, sizeof(buffer), "ICMP - Connection: saddr=%pI4, daddr=%pI4, protocol=ICMP, type=%u, code=%u, timeout=%llu\n",
                         &conn->saddr, &conn->daddr,
                         conn->icmp.type, conn->icmp.code, ntohll(conn->timeout));
                // 使用 kernel_write 替代 vfs_write 写入文件
                int rs = kernel_write(file, buffer, strlen(buffer), &file->f_pos);
                if (rs < 0)
                {
                    printk(KERN_ERR MODULE_NAME " CONN: kernel_write failed with error %d\n", rs);
                }
                else if (rs != strlen(buffer))
                {
                    printk(KERN_ERR MODULE_NAME " CONN: kernel_write wrote only %d bytes out of %zu\n", rs, strlen(buffer));
                }
                else
                {
                    printk(KERN_INFO MODULE_NAME " CONN: Successfully wrote %d bytes to conn_table.\n", rs);
                }

                memset(buffer, 0, sizeof(buffer)); // 清空缓冲区
            }
        }
    }
    read_unlock(&conn_table.lock);
    filp_close(file, NULL);
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
    printk(KERN_INFO "Got the lock");
    for (i = 0; i < HASH_SIZE; i++)
    {
        hlist_for_each_entry_safe(conn, tmp, &table->table[i], node)
        {
            printk(KERN_INFO "REAL_TIME: %lld, TIMEOUT: %lld", ktime_get_real(), ntohll(conn->timeout));
            if (!ktime_before(ktime_get_real(), ntohll(conn->timeout))) // 当前时间大于后面的conn->timeout,说明超时
            {
                switch (conn->protocol)
                {
                case IPPROTO_TCP:
                    printk(KERN_INFO MODULE_NAME ": Delete connection: [TCP] %pI4:%d > %pI4:%d",
                           &conn->saddr, ntohs(conn->tcp.sport),
                           &conn->daddr, ntohs(conn->tcp.dport));
                    break;
                case IPPROTO_UDP:
                    printk(KERN_INFO MODULE_NAME "Delete connection: [UDP] %pI4:%d > %pI4:%d",
                           &conn->saddr, ntohs(conn->udp.sport),
                           &conn->daddr, ntohs(conn->udp.dport));
                    break;
                case IPPROTO_ICMP:
                    printk(KERN_INFO MODULE_NAME "Delete connection: [ICMP] %pI4 > %pI4",
                           &conn->saddr, &conn->daddr);
                    break;
                default:
                    break;
                }
                hash_del(&conn->node);
                kfree(conn);
                table->conn_count--;
            }
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
struct tinywall_log *tinywall_log_create(struct sk_buff *skb, unsigned short action)
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
    log->action = htons(action);
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
    char buffer[1024]; // 用于存储日志信息的缓冲区
    size_t offset = 0;
    // 打开文件，使用 O_WRONLY | O_CREAT | O_APPEND 选项
    file = filp_open("./log.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(file))
    {
        printk(KERN_ERR "Failed to open log.txt\n");
        return;
    }

    mutex_lock(&log_table.lock); // 锁定日志表
    list_for_each_entry(log, &log_table.head, node)
    {
        // 格式化基本日志信息到缓冲区
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "Index: %u, Timestamp: %llu, saddr: %pI4, daddr: %pI4\n",
                           ntohl(log->idx), (unsigned long long)ntohll(log->ts),
                           &log->saddr, &log->daddr);

        // 根据协议类型添加详细信息
        if (log->protocol == IPPROTO_TCP)
        {
            offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                               "    protocol:TCP - Source Port: %u, Destination Port: %u,",
                               ntohs(log->tcp.sport), ntohs(log->tcp.dport));

            if (log->tcp.state == TINYWALL_TCP_SYN_RECEIVED)
            {
                offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                                   " State: SYN_RECEIVED.");
            }
            else if (log->tcp.state == TINYWALL_TCP_ESTABLISHED)
            {
                offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                                   " State: ESTABLISHED.");
            }
            else if (log->tcp.state == TINYWALL_TCP_CLOSED)
            {
                offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                                   " State: CLOSED.");
            }
        }
        else if (log->protocol == IPPROTO_UDP)
        {
            offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                               "    protocol:UDP - Source Port: %u, Destination Port: %u",
                               ntohs(log->udp.sport), ntohs(log->udp.dport));
        }
        else if (log->protocol == IPPROTO_ICMP)
        {
            offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                               "    protocol:ICMP - Type: %u, Code: %u",
                               log->icmp.type, log->icmp.code);
        }
        if (ntohs(log->action) == NF_ACCEPT)
        {
            offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                               " Action: NF_ACCEPT.\n");
        }
        else if (ntohs(log->action) == NF_DROP)
        {
            offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                               " Action: NF_DROP.\n");
        }

        // 使用 kernel_write 替代 vfs_write 写入文件
        int rs = kernel_write(file, buffer, strlen(buffer), &file->f_pos);
        if (rs < 0)
        {
            printk(KERN_ERR MODULE_NAME " LOG: kernel_write failed with error %d\n", rs);
        }
        else if (rs != strlen(buffer))
        {
            printk(KERN_ERR MODULE_NAME " LOG: kernel_write wrote only %d bytes out of %zu\n", rs, strlen(buffer));
        }
        else
        {
            printk(KERN_INFO MODULE_NAME " LOG: Successfully wrote %d bytes to log.txt\n", rs);
        }

        memset(buffer, 0, sizeof(buffer)); // 清空缓冲区
        offset = 0;
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
// 捕获所有入站的报文部分
static unsigned int firewall_hook(void *priv,
                                  struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    bool is_new_conn = false;
    int action = 0;
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcphr = NULL;
    struct tinywall_rule *rule = NULL;
    struct tinywall_log *log = NULL;
    struct tinywall_conn *conn = NULL;
    if (!iph)
    {
        printk(KERN_ERR MODULE_NAME ": Invalid IP header.\n");
        return NF_DROP;
    }

    // 从skb结构中创建连接对象
    conn = tinywall_connection_create(iph);

    if (!conn)
    {
        printk(KERN_ERR MODULE_NAME ": Failed to create connection.\n");
        return NF_DROP;
    }

    printk(KERN_INFO MODULE_NAME ": Created a connection: saddr=%pI4, daddr=%pI4",
           &conn->saddr, &conn->daddr);

    if (conn->protocol == IPPROTO_TCP)
    {
        printk("    protocol: TCP, sport=%u, dport=%u, state=%u\n",
               ntohs(conn->tcp.sport), ntohs(conn->tcp.dport), conn->tcp.state);
    }
    else if (conn->protocol == IPPROTO_UDP)
    {
        printk("    protocol: UDP, sport=%u, dport=%u\n",
               ntohs(conn->udp.sport), ntohs(conn->udp.dport));
    }
    else if (conn->protocol == IPPROTO_ICMP)
    {
        printk("    protocol: ICMP, type=%u, code=%u\n",
               conn->icmp.type, conn->icmp.code);
    }

    // /* >----------------------------------查找现存连接----------------------------------<*/
    // // 一个连接分双向,不过hash函数已经对顺序进行了处理,不必再考虑
    // if (tinywall_conn_match(conn))
    // {
    //     printk(KERN_INFO MODULE_NAME "CONN: Connection exists, ACCEPT.\n");
    //     if (default_logging)
    //     {
    //         log = tinywall_log_create(skb, NF_ACCEPT);
    //         log->tcp.state = TINYWALL_TCP_ESTABLISHED;
    //         tinywall_log_add(log);
    //         action = NF_ACCEPT;
    //     }
    //     goto out;
    // }

    /* >----------------------------------匹配现存连接----------------------------------<*/
    // 如果是tcp,那么只能由syn包来创建连接,检验是不是syn包
    if (conn->protocol == IPPROTO_TCP)
    {
        // 一个连接分双向,不过match函数已经对顺序进行了处理,不必再考虑
        if (tinywall_conn_match(conn))
        {
            printk(KERN_INFO MODULE_NAME "CONN: Connection exists, ACCEPT.\n");
            if (default_logging)
            {
                log = tinywall_log_create(skb, NF_ACCEPT);
                log->tcp.state = TINYWALL_TCP_ESTABLISHED;
                tinywall_log_add(log);
            }
            action = NF_ACCEPT;
            goto out;
        }
        else if (tcp_flag_word((void *)iph + iph->ihl * 4) == TCP_FLAG_SYN || tcp_flag_word((void *)iph + iph->ihl * 4) == TCP_FLAG_SYN | TCP_FLAG_ACK)
        {
            rule = tinywall_rule_match(conn);
            if (rule != NULL && ntohs(rule->action) == NF_ACCEPT && ntohs(rule->logging))
            {
                is_new_conn = true;
                conn->tcp.state = TINYWALL_TCP_SYN_RECEIVED;
                tinywall_conn_add(conn);
                printk(KERN_INFO MODULE_NAME ": New TCP connection added, action: NF_ACCEPT.\n");
                if (rule->logging)
                {
                    log = tinywall_log_create(skb, NF_ACCEPT);
                    log->tcp.state = TINYWALL_TCP_SYN_RECEIVED;
                    tinywall_log_add(log);
                }
                action = NF_ACCEPT;
            }
            else if (rule != NULL && ntohs(rule->action) == NF_DROP && ntohs(rule->logging))
            {
                printk(KERN_INFO MODULE_NAME ": Logging enabled.\n");
                log = tinywall_log_create(skb, NF_DROP);
                log->tcp.state = TINYWALL_TCP_CLOSED;
                tinywall_log_add(log);
                action = NF_DROP;
            }
            else if (rule == NULL && default_action == NF_ACCEPT && default_logging)
            {
                printk(KERN_ERR MODULE_NAME ": No matching rule found, Default accept. Default_logging enabled!.\n");
                is_new_conn = true;
                conn->tcp.state = TINYWALL_TCP_SYN_RECEIVED; // 默认接受,那么开始接受连接
                tinywall_conn_add(conn);
                printk(KERN_INFO MODULE_NAME ": Added one tcp conn due to the default action: NF_ACCEPT.\n");
                log = tinywall_log_create(skb, default_action);
                log->tcp.state = TINYWALL_TCP_SYN_RECEIVED;
                tinywall_log_add(log);
                action = NF_ACCEPT;
            }
            else if (rule == NULL && default_action == NF_DROP && default_logging)
            {
                printk(KERN_ERR MODULE_NAME ": No matching rule found, Default drop. Default_logging enabled!\n");
                log = tinywall_log_create(skb, NF_DROP);
                log->tcp.state = TINYWALL_TCP_CLOSED;
                tinywall_log_add(log);
                action = NF_DROP;
            }
        }
        else // 不是syn包,也在rule_table里面查找
        {
            rule = tinywall_rule_match(conn);
            if (rule != NULL && ntohs(rule->action) == NF_ACCEPT && ntohs(rule->logging)) // 主要就是指的本地回环地址的许多tcp报文
            {
                log = tinywall_log_create(skb, NF_ACCEPT);
                tinywall_log_add(log);
                action = NF_ACCEPT;
            }
            else if (rule != NULL && ntohs(rule->action) == NF_ACCEPT && !ntohs(rule->logging)) // 主要就是指的本地回环地址的许多tcp报文
            {
                action = NF_ACCEPT;
            }
            else if (rule != NULL && ntohs(rule->action) == NF_DROP && ntohs(rule->logging))
            {
                printk(KERN_INFO MODULE_NAME ": Matched a rule, Action: Drop, Logging enabled.\n");
                log = tinywall_log_create(skb, NF_DROP);
                log->tcp.state = TINYWALL_TCP_CLOSED;
                action = NF_DROP;
            }
        }
        goto out;
    }

    // 如果是icmp包,那么只有拥有对应echorequest的echo reply包可以通过,检验是否是echo reply包
    if (conn->protocol == IPPROTO_ICMP)
    {
        struct tinywall_conn *former_conn = NULL;
        if (conn->icmp.type == ICMP_ECHOREPLY)
        {
            former_conn = tinywall_conn_get_entry(conn);
            if (former_conn != NULL)
            {
                printk(KERN_INFO MODULE_NAME ": Found a echo request, check its type.\n");
                if (former_conn->protocol == IPPROTO_ICMP && former_conn->icmp.type == ICMP_ECHO)
                {
                    printk(KERN_INFO MODULE_NAME ": Matched echo reply, ACCEPT.\n");
                    log = tinywall_log_create(skb, NF_ACCEPT);
                    tinywall_log_add(log);
                    action = NF_ACCEPT;
                }
                else
                {
                    printk(KERN_INFO MODULE_NAME ": Didn't match a echo request, DROP.\n");
                    action = NF_DROP;
                }
            }
            else
            {
                printk(KERN_INFO MODULE_NAME ": Didn't find a echo request, DROP.\n");
                action = NF_DROP;
            }
        }
        else
        {
            printk(KERN_INFO MODULE_NAME ": Not a echo reply, DROP.\n");
            if (default_logging)
            {
                log = tinywall_log_create(skb, NF_DROP);
                tinywall_log_add(log);
            }
            action = NF_DROP;
        }
        goto out;
    }

    // UDP 包
    if (iph->protocol == IPPROTO_UDP)
    {
        rule = tinywall_rule_match(conn);
        // 匹配到规则
        if (rule && ntohs(rule->action) == NF_ACCEPT && ntohs(rule->logging))
        {
            printk(KERN_INFO MODULE_NAME ": UDP rule matched, rule_action: NF_ACCEPT.rule_logging: enabled!\n");
            is_new_conn = true;
            tinywall_conn_add(conn);
            log = tinywall_log_create(skb, ntohs(rule->action));
            tinywall_log_add(log);
            action = NF_ACCEPT;
        }
        else if (rule && ntohs(rule->action) == NF_ACCEPT)
        {
            printk(KERN_INFO MODULE_NAME ": UDP rule matched, rule_action: NF_ACCEPT.rule_logging: unabled!\n");
            is_new_conn = true;
            tinywall_conn_add(conn);
            action = NF_ACCEPT;
        }
        else if (rule && ntohs(rule->action) == NF_DROP && ntohs(rule->logging))
        {
            printk(KERN_INFO MODULE_NAME ": UDP rule matched, rule_action: NF_DROP, rule_logging: enabled!\n");
            log = tinywall_log_create(skb, ntohs(rule->action));
            tinywall_log_add(log);
            action = NF_DROP;
        }
        else if (rule == NULL && default_action == NF_ACCEPT && default_logging)
        { // 没有匹配到规则,使用默认动作
            printk(KERN_INFO MODULE_NAME ": UDP rule not matched, default_action: NF_ACCEPT, default_logging: enabled!\n");
            is_new_conn = true;
            tinywall_conn_add(conn);
            log = tinywall_log_create(skb, default_action);
            tinywall_log_add(log);
            action = NF_ACCEPT;
        }
        else if (rule == NULL && default_action == NF_ACCEPT)
        { // 没有匹配到规则,使用默认动作
            printk(KERN_INFO MODULE_NAME ": UDP rule not matched, default_action: NF_ACCEPT, default_logging: unabled!\n");
            is_new_conn = true;
            tinywall_conn_add(conn);
            action = NF_ACCEPT;
        }
        else if (rule == NULL && default_action == NF_DROP && default_logging)
        {
            printk(KERN_INFO MODULE_NAME ": UDP rule not matched, default_action: NF_DROP, default_logging: enabled!\n");
            log = tinywall_log_create(skb, default_action);
            tinywall_log_add(log);
            action = NF_DROP;
        }
    }
out:
    if (!is_new_conn)
    {
        kfree(conn);
    }
    return action;
}
// 处理本地出站流量,主要是处理icmp请求报文和发出去的tcp syn报文
unsigned int handle_local_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph = ip_hdr(skb);
    if (!iph)
    {
        printk(KERN_ERR " LOCAL_OUT: Invalid IP header.\n");
    }
    bool is_new_conn = false;
    tinywall_conn *conn;
    conn = tinywall_connection_create(iph);
    tinywall_conn *former_conn;
    tinywall_rule *rule;
    tinywall_log *log;
    unsigned int action = NF_DROP;
    // 处理发出去的icmp请求报文,建立虚拟连接以用来等待对端的响应echo reply
    if (iph->protocol == IPPROTO_ICMP)
    {
        printk("LOCAL OUT: ICMP packet detected.");
        former_conn = tinywall_conn_get_entry(conn);
        rule = tinywall_rule_match(conn);
        if (former_conn != NULL)
        {
            printk(KERN_INFO MODULE_NAME " LOCAL OUT: ICMP connection already exists.\n");
            action = NF_ACCEPT;
        }
        else if (rule == NULL)
        {
            printk(KERN_INFO MODULE_NAME " LOCAL OUT: ICMP request sent, but no rule matched.Dropped.\n");
            action = NF_DROP;
        }
        else if (conn->icmp.type == ICMP_ECHO && ntohs(rule->action) == NF_ACCEPT)
        {
            is_new_conn = true;

            tinywall_conn_add(conn);
            if (ntohs(rule->logging))
            {
                log = tinywall_log_create(skb, NF_ACCEPT);
                tinywall_log_add(log);
            }

            printk(KERN_INFO MODULE_NAME " LOCAL OUT: New ICMP connection added.\n");
            action = NF_ACCEPT;
        }
        else if (conn->icmp.type == ICMP_ECHO && ntohs(rule->action) == NF_DROP && ntohs(rule->logging))
        {
            log = tinywall_log_create(skb, NF_DROP);
            tinywall_log_add(log);
            printk(KERN_INFO MODULE_NAME " LOCAL OUT: New ICMP ECHO packet Dropped.\n");
            action = NF_DROP;
        }
        else
        {
            printk(KERN_INFO MODULE_NAME " LOCAL OUT: conn->protocol:%u,ntohs(rule->action):%u, conn->icmp.type :%u \n",
                   conn->protocol, ntohs(rule->action), conn->icmp.type);
        }
    }
    else if (iph->protocol == IPPROTO_TCP)
    {
        // 处理发出去的tcp syn报文,建立虚拟连接以用来等待对端的响应syn reply
        former_conn = tinywall_conn_get_entry(conn);
        rule = tinywall_rule_match(conn);
        if(rule){
            printk("FFFFFFFF:%u",ntohs(rule->action));
        }
        if (former_conn != NULL)
        {
            printk(KERN_INFO MODULE_NAME " LOCAL OUT: TCP connection already exists.\n");
            action = NF_ACCEPT;
        }
        else if (rule == NULL)
        {
            printk(KERN_INFO MODULE_NAME " LOCAL OUT: TCP sent, but no rule matched.Dropped.\n");
            action = NF_DROP;
        }
        else if (ntohs(rule->action) == NF_ACCEPT)
        {
            is_new_conn = true;
            if (ntohs(rule->logging))
            {
                log = tinywall_log_create(skb, NF_ACCEPT);
                tinywall_log_add(log);
            }
            conn->tcp.state = TINYWALL_TCP_SYN_SENT;
            tinywall_conn_add(conn);
            printk(KERN_INFO MODULE_NAME " LOCAL OUT: New TCP connection added.\n");
            action = NF_ACCEPT;
        }
        else if (ntohs(rule->action) == NF_DROP && ntohs(rule->logging))
        {
            log = tinywall_log_create(skb, NF_DROP);
            tinywall_log_add(log);
            printk(KERN_INFO MODULE_NAME " LOCAL OUT: New TCP SYN packet Dropped.\n");
            action = NF_DROP;
        }
    }

    if (!is_new_conn)
    {
        kfree(conn);
    }
    return action;
}

// 定义Netfilter钩子
static struct nf_hook_ops firewall_nfho[] = {
    {
        .hook = firewall_hook,
        .pf = PF_INET,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = handle_local_out,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FIRST,
    },
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
    ret = nf_register_net_hooks(&init_net, firewall_nfho, 2);
    if (ret)
    {
        printk(KERN_ERR MODULE_NAME ": Failed to register nethook\n");
        return ret;
    }

    printk(KERN_INFO MODULE_NAME ": Firewall module loaded.\n");
    timer_setup(&conn_timer, tinywall_timer_callback, 0);
    conn_timer.expires = jiffies + HZ * 5;
    add_timer(&conn_timer);
    return 0;
}

// 模块退出
static void __exit firewall_exit(void)
{
    // 注销Netfilter钩子
    nf_unregister_net_hooks(&init_net, firewall_nfho, 2);
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
EXPORT_SYMBOL(tinywall_conn_show);
EXPORT_SYMBOL(rule_table);
EXPORT_SYMBOL(conn_table);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sun Xiaokai suxiaokai34@gmail.com");
MODULE_DESCRIPTION("A Tiny Netfilter Firewall Module");