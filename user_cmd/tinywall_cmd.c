#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

#define MAX_PAYLOAD 1024

// 假设 tinywall_rule_user 结构体已经定义在 tinywall.h 中
#include "../public.h"

/* >----------------------------------rule operations----------------------------------<*/
// 增加规则
static unsigned int seq = 0;
int rule_add(int sock_fd, struct sockaddr_nl *dest_addr, struct tinywall_rule_user *rule)
{
    struct nlmsghdr *nlh = malloc(NLMSG_SPACE(sizeof(tinywall_rule_user)));
    if (!nlh)
    {
        perror("malloc");
        return -1;
    }

    nlh->nlmsg_type = TINYWALL_TYPE_ADD_RULE;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = ++seq; // 使用递增的序列号
    nlh->nlmsg_pid = getpid();

    // 设置消息长度
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(tinywall_rule_user));
    // 将规则数据拷贝到消息中
    memcpy(NLMSG_DATA(nlh), rule, sizeof(tinywall_rule_user));
    // 构造消息头和数据
    struct iovec iov = {.iov_base = (void *)nlh, .iov_len = nlh->nlmsg_len};
    struct msghdr msg = {.msg_name = (void *)dest_addr, .msg_namelen = sizeof(*dest_addr), .msg_iov = &iov, .msg_iovlen = 1};

    printf("Sending message to kernel...\n");
    if (sendmsg(sock_fd, &msg, 0) < 0)
    {
        perror("sendmsg");
        free(nlh);
        return -2;
    }

    printf("Rule added successfully.\n");
    free(nlh);
    return 0;
}

// 移除规则
void rule_remove(int sock_fd, struct nlmsghdr *nlh, struct sockaddr_nl *dest_addr)
{
    printf("Enter rule ID to remove: ");
    unsigned int rule_id;
    scanf("%u", &rule_id);
    nlh->nlmsg_type = TINYWALL_TYPE_DEL_RULE;
    nlh->nlmsg_flags = rule_id;
    struct iovec iov = {.iov_base = (void *)nlh, .iov_len = nlh->nlmsg_len};
    struct msghdr msg = {.msg_name = (void *)dest_addr, .msg_namelen = sizeof(*dest_addr), .msg_iov = &iov, .msg_iovlen = 1};

    if (sendmsg(sock_fd, &msg, 0) < 0)
    {
        perror("sendmsg");
    }
}

// 列出规则
void rules_list(int sock_fd, struct nlmsghdr *nlh, struct sockaddr_nl *dest_addr)
{
    nlh->nlmsg_type = TINYWALL_TYPE_LIST_RULES;

    struct iovec iov = {.iov_base = (void *)nlh, .iov_len = nlh->nlmsg_len};
    struct msghdr msg = {.msg_name = (void *)dest_addr, .msg_namelen = sizeof(*dest_addr), .msg_iov = &iov, .msg_iovlen = 1};
    if (sendmsg(sock_fd, &msg, 0) < 0)
    {
        perror("sendmsg");
    }
}

// 清空规则
void rules_clear(int sock_fd, struct nlmsghdr *nlh, struct sockaddr_nl *dest_addr)
{
    nlh->nlmsg_type = TINYWALL_TYPE_CLEAR_RULES;
    struct iovec iov = {.iov_base = (void *)nlh, .iov_len = nlh->nlmsg_len};
    struct msghdr msg = {.msg_name = (void *)dest_addr, .msg_namelen = sizeof(*dest_addr), .msg_iov = &iov, .msg_iovlen = 1};
    if (sendmsg(sock_fd, &msg, 0) < 0)
    {
        perror("sendmsg");
    }
}

// 从文件中读取规则并添加
int load_rules_from_file(int sock_fd, struct sockaddr_nl *dest_addr, const char *filename)
{
    int ret = 0;
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        perror("fopen");
        return -1;
    }
    printf("Reading rules from %s\n", filename);
    char line[256];

    while (fgets(line, sizeof(line), file))
    {
        tinywall_rule_user rule;
        char src_ip_str[16], dst_ip_str[16];
        unsigned short smask, dmask, src_port_min, src_port_max, dst_port_min, dst_port_max = 0;
        int n = sscanf(line, "%15s %hu %15s %hu %hu %hu %hu %hu %hu %hu %hu",
                       &src_ip_str, &smask,
                       &dst_ip_str, &dmask,
                       &src_port_min, &src_port_max,
                       &dst_port_min, &dst_port_max,
                       &rule.protocol, &rule.action, &rule.logging);

        if (n != 11)
        {
            fprintf(stderr, "Invalid rule format: %s", line);
            continue;
        }

        if (inet_pton(AF_INET, src_ip_str, &rule.src_ip) <= 0)
        {
            fprintf(stderr, "Invalid source IP address: %s\n", src_ip_str);
            continue;
        }

        if (inet_pton(AF_INET, dst_ip_str, &rule.dst_ip) <= 0)
        {
            fprintf(stderr, "Invalid destination IP address: %s\n", dst_ip_str);
            continue;
        }
        rule.smask = htons(smask);
        rule.dmask = htons(dmask);
        rule.src_port_min = htons(src_port_min);
        rule.src_port_max = htons(src_port_max);
        rule.dst_port_min = htons(dst_port_min);
        rule.dst_port_max = htons(dst_port_max);
        rule.protocol = htons(rule.protocol);
        rule.action = htons(rule.action);
        rule.logging = htons(rule.logging);
        printf("|| src_ip: %s\n", inet_ntoa(*(struct in_addr *)&rule.src_ip));
        printf("|| dst_ip: %s\n", inet_ntoa(*(struct in_addr *)&rule.dst_ip));
        printf("|| sport rage: %hu->%hu  dport rage: %hu->%hu\n", ntohs(rule.src_port_min), ntohs(rule.src_port_max),
               ntohs(rule.dst_port_min), ntohs(rule.dst_port_max));
        printf("|| protocol: %hu action: %hu\n", ntohs(rule.protocol), ntohs(rule.action));
        ret = rule_add(sock_fd, dest_addr, &rule);
        if (ret == -2)
        {
            printf("Error adding rule\n");
            return ret;
        }
    }

    fclose(file);
    return ret;
}

// 将规则表保存为文件
void rules_store(int sock_fd, struct nlmsghdr *nlh, struct sockaddr_nl *dest_addr)
{
    nlh->nlmsg_type = TINYWALL_TYPE_STORE_RULES;
    // 发送缓冲区
    struct iovec iov = {.iov_base = (void *)nlh, .iov_len = nlh->nlmsg_len};
    struct msghdr msg = {.msg_name = (void *)dest_addr, .msg_namelen = sizeof(*dest_addr), .msg_iov = &iov, .msg_iovlen = 1};

    // // 接收缓冲区
    // char buffer[65535];
    // struct iovec iov_recv = {buffer, sizeof(buffer)};
    // struct msghdr msg_recv = {NULL};
    // struct nlmsghdr *nlh_recv = NULL;
    // int ret;
    // int count = 0;
    // // 从内核接受数据
    // msg_recv.msg_name = (void *)&dest_addr;
    // msg_recv.msg_namelen = sizeof(dest_addr);
    // msg_recv.msg_iov = &iov_recv;
    // msg_recv.msg_iovlen = 1;
    // 发送store命令
    sendmsg(sock_fd, &msg, 0);
    // while (1)
    // {
    //     int num;
    //     ret = recvmsg(sock_fd, &msg_recv, 0);
    //     if (ret < 0)
    //     {
    //         perror("recvmsg");
    //         break;
    //     }

    //     nlh = (struct nlmsghdr *)buffer;

    //     // 规则数量
    //     num = nlh->nlmsg_flags;
    //     while (NLMSG_OK(nlh, ret))
    //     {
    //         if (nlh->nlmsg_type == NLMSG_DONE)
    //         {
    //             tinywall_rule_user *rule = (tinywall_rule_user *)NLMSG_DATA(nlh);

    //             // 打开文件
    //             FILE *fp = fopen("rule_table.txt", "w");
    //             if (fp == NULL)
    //             {
    //                 perror("fopen");
    //                 break;
    //             }

    //             // 写入规则
    //             fprintf(fp, "%s %d %s %d %d %d %d %d %d %d %d\n",
    //                     inet_ntoa(*(struct in_addr *)&rule->src_ip),
    //                     ntohs(rule->smask),
    //                     inet_ntoa(*(struct in_addr *)&rule->dst_ip),
    //                     ntohs(rule->dmask),
    //                     ntohs(rule->src_port_min),
    //                     ntohs(rule->src_port_max),
    //                     ntohs(rule->dst_port_min),
    //                     ntohs(rule->dst_port_max),
    //                     ntohs(rule->protocol),
    //                     ntohs(rule->action),
    //                     ntohs(rule->logging));
    //             count++;
    //             fclose(fp);
    //             printf("Rule added to rule_table.txt\n");
    //         }
    //         nlh = NLMSG_NEXT(nlh, ret);
    //     }
    //     printf("num: %d\n", num);
    //     printf("count: %d\n", count);
    //     if (count == num)
    //         break;
    // }
}

void log_show(int sock_fd, struct nlmsghdr *nlh, struct sockaddr_nl *dest_addr)
{
    nlh->nlmsg_type = TINYWALL_TYPE_SHOW_LOGS;
    struct iovec iov = {.iov_base = (void *)nlh, .iov_len = nlh->nlmsg_len};
    struct msghdr msg = {.msg_name = (void *)dest_addr, .msg_namelen = sizeof(*dest_addr), .msg_iov = &iov, .msg_iovlen = 1};
    sendmsg(sock_fd, &msg, 0);
}

void show_connections(int sock_fd, struct nlmsghdr *nlh, struct sockaddr_nl *dest_addr)
{
    nlh->nlmsg_type = TINYWALL_TYPE_SHOW_CONNS;
    struct iovec iov = {.iov_base = (void *)nlh, .iov_len = nlh->nlmsg_len};
    struct msghdr msg = {.msg_name = (void *)dest_addr, .msg_namelen = sizeof(*dest_addr), .msg_iov = &iov, .msg_iovlen = 1};
    sendmsg(sock_fd, &msg, 0);
}

void load_kernel_modules()
{
    // 加载 tinywall.ko 和 tinywall_nl.ko
    if (system("sudo insmod tinywall.ko") != 0)
    {
        perror("Failed to load tinywall.ko");
        exit(1);
    }
    if (system("sudo insmod tinywall_nl.ko") != 0)
    {
        perror("Failed to load tinywall_nl.ko");
        exit(1);
    }
}

void unload_kernel_modules()
{
    // 卸载 tinywall.ko 和 tinywall_nl.ko
    if (system("sudo rmmod tinywall_nl.ko") != 0)
    {
        perror("Failed to unload tinywall_nl.ko");
        exit(1);
    }
    if (system("sudo rmmod tinywall.ko") != 0)
    {
        perror("Failed to unload tinywall.ko");
        exit(1);
    }
}
int main()
{
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    int sock_fd;
    int ret = 0;
    tinywall_rule_user rule;
    char src_ip_str[16], dst_ip_str[16];
    unsigned short smask, dmask, src_port_min, src_port_max, dst_port_min, dst_port_max = 0;
    load_kernel_modules();
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    src_addr.nl_groups = 0;

    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0)
    {
        perror("socket");
        exit(1);
    }

    if (bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0)
    {
        perror("bind");
        exit(1);
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; // Kernel PID
    dest_addr.nl_groups = 0;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if (!nlh)
    {
        perror("malloc");
        exit(1);
    }
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct tinywall_rule_user));
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    /*添加默认规则表*/
    printf("Load Default Rules\n");
    load_rules_from_file(sock_fd, &dest_addr, "DEFAULT_RULES");

    while (1)
    {
        printf("\nMenu:\n");
        printf("0. EXIT\n");
        printf("1. Add a Rule\n");
        printf("2. Delete a Rule\n");
        printf("3. Clear Rules\n");
        printf("4. Load Rule from file\n");
        printf("5. Store Rules to file\n");
        printf("6. Show Connections\n");
        printf("7. Show Logs\n");
        printf("Choose an option: ");

        int choice = 0;
    menu:
        scanf("%d", &choice);

        switch (choice)
        {
        case 0:
            goto exit;
        case 1:
            printf("Enter source IP:\n");
            scanf("%15s", src_ip_str);
            if (inet_pton(AF_INET, src_ip_str, &rule.src_ip) <= 0)
            {
                fprintf(stderr, "Invalid source IP address: %s\n", src_ip_str);
                break;
            }
            printf("Enter source_mask in Integer(0-32):");
            scanf("%hu", &smask);
            printf("Enter min source port:");
            scanf("%hu", &src_port_min);
            printf("Enter max source port:");
            scanf("%hu", &src_port_max);

            printf("Enter destination IP:\n");
            scanf("%15s", dst_ip_str);
            if (inet_pton(AF_INET, dst_ip_str, &rule.dst_ip) <= 0)
            {
                fprintf(stderr, "Invalid destination IP address: %s\n", dst_ip_str);
                break;
            }
            printf("Enter destination_mask in Integer(0-32):");
            scanf("%hu", &dmask);
            printf("Enter min destination port:");
            scanf("%hu", &dst_port_min);
            printf("Enter max destination port:");
            scanf("%hu", &dst_port_max);
            printf("Enter protocol(1-255):");
            scanf("%hu", &rule.protocol);
            printf("Enter action(0 for drop, 1 for accept):");
            scanf("%hu", &rule.action);
            printf("Enter logging(0 for no logging, 1 for logging):");
            scanf("%hu", &rule.logging);

            rule.smask = htons(smask);
            rule.dmask = htons(dmask);
            rule.src_port_min = htons(src_port_min);
            rule.src_port_max = htons(src_port_max);
            rule.dst_port_min = htons(dst_port_min);
            rule.dst_port_max = htons(dst_port_max);
            rule.protocol = htons(rule.protocol);
            rule.action = htons(rule.action);
            rule.logging = htons(rule.logging);
            ret = rule_add(sock_fd, &dest_addr, &rule);
            if (ret == -2)
            {
                printf("Error adding rule\n");
            }
            break;
        case 2:
            rule_remove(sock_fd, nlh, &dest_addr);
            break;
        case 3:
            rules_clear(sock_fd, nlh, &dest_addr);
            break;
        case 4:
            printf("Enter rule filename:\n");
            char filename[256];
            scanf("%s", filename);
            ret = load_rules_from_file(sock_fd, &dest_addr, filename);
            if (ret == -1)
            {
                printf("Error: file doesn't exist\n");
                goto menu;
            }
            else if (ret == -2)
            {
                printf("Error: socket发送rule失败!");
                goto exit;
            }
            break;
        case 5:
            rules_store(sock_fd, nlh, &dest_addr);
            break;
        case 6:
            show_connections(sock_fd, nlh, &dest_addr);
            break;
        case 7:
            log_show(sock_fd, nlh, &dest_addr);
            break;
        default:
            printf("Invalid choice. Please try again.\n");
            goto menu;
        }
    }

exit:
    close(sock_fd);
    free(nlh);
    unload_kernel_modules();
    return 0;
}