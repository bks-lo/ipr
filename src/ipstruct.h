/**
 * 
 * \file ipstruct.h
 * \version 0.1
 * 
 * \brief ip结构和相关操作的定义
 */

#ifndef __ipstruct_h__
#define __ipstruct_h__
#include <stdint.h>
#include <netinet/in.h>


#define IPV4_BIT_NUM        32          /* IPv4的二进制形式 有32位 */
#define IPV6_BIT_NUM        128         /* IPv6的二进制形式 有128位 */
#define IPV6_STRLEN_MAX     39          /* ipv6字符串的最大长度 1234:1234:1234:1234:1234:1234:1234:1234 */
#define IP_MASKSTR_MAX      15          /* 掩码字符串最大长度 255.255.255.255 */
#define IPV6_STORELEN_MAX   64          /* IPv6字符串存储最大长度，向上对齐 */
#define IPV4_STORELEN_MAX   16          /* IPv4字符串存储最大长度，向上对齐 */
#define IP_RANGESTR_MAX     128         /* IP段字符串最大长度 2xIPV6_STORELEN_MAX */

/** 根据size开辟空间，开辟失败返回ret */
#define MALLOC_RETURN(result, size, ret) do { \
    result = malloc(size); \
    if (result == NULL) { \
        write_log(LOG_ERROR, "malloc size %d failed !!!", (size));   \
        return ret; \
    }   \
    memset(result, 0, size); \
} while (0)

typedef enum
{
    IPTYPE_V4 = 0,
    IPTYPE_V6,
} iptype_em;

/** IP结构 */
typedef struct ip_st
{
    iptype_em type;
    union {
        struct in_addr v4;      /**< IPv4, 网络序 */
        struct in6_addr v6;     /**< IPv6, 网络序 */
    };
} ip_st;

/** IP段结构，是一个闭区间 [start, end] */
typedef struct ip_range_st
{
    ip_st start;
    ip_st end;
} ip_range_st;

/** IP段数组结构 */
typedef struct ip_ranges_st
{
    int cur;                /**< 当前使用到数组个数 */
    int max;                /**< iprs数组的最大个数 */
    ip_range_st **iprarr;   /**< iprs数组，用于存放ip_range_st 指针 */
} ip_ranges_st;

/** IP比较结果定义 */
typedef enum
{
    IPCMP_LESS = -2,                /**< 小于 */
    IPCMP_EQUAL = 0,                /**< 等于 */
    IPCMP_TYPE_NOMATCH = 1,         /**< 类型不匹配 */
    IPCMP_MORE = 2,                 /**< 大于 */
} ipcmp_em;

typedef enum
{
    IPRCMP_1INCLUDE2 = 1,           /**< ip段1 包含 ip段2，包含ip段1 等于 ip段2 的情况 */
    IPRCMP_2INCLUDE1 = -1,          /**< ip段2 包含 ip段1 */
    IPRCMP_LESS = -2,               /**< ip段1 比 ip段2 更靠左 */
    IPRCMP_MORE = 2,                /**< ip段1 比 ip段2 更靠右 */
} iprcmp_em;


/**
 * \brief 比较两个ip的大小
 * 
 * \param [in]	ip1 字符串
 * \param [in]	ip2 字符串
 * \return	int  
 * \retval 
 *        0：ip1 == ip2
 *        1：ip1->type != ip2->type
 *        2：ip1 > ip2
 *       -2：ip1 < ip2
 */
int ipst_cmp(ip_st *ip1, ip_st *ip2);

/**
 * \brief 将IP字符串（一行）转换成ip_range_st结构
 * \detail 支持IPv4,IPv6的单ip、ip段（ip1-ip2）、 IP掩码（ip1/23）的三种形态解析
 * \param [in]  ipstr 字符串
 * \param [in]  len 字符串长度
 * \return  ip_range_st*    失败：返回NULL；成功：返回填充完毕的ip_range_st
 * 
 */
ip_range_st *ip_string_parser(const char *ipstr, int len);

#if 0
/**
 * \brief ip匹配
 * 
 * \param [in]	ipranges ip范围数组
 * \param [in]	num      ip范围个数
 * \param [in]	ip***    需要匹配的ip数据
 * \return	int     匹配成功：返回命中的数组下标（>= 0）；匹配失败，返回-1
 */
int ip_in4_match(ip_range_st **ipranges, int num, struct in_addr *ipv4);
int ip_in6_match(ip_range_st **ipranges, int num, struct in6_addr *ipv6);
int ip_string_match(ip_range_st **ipranges, int num, const char *ipstr);
#endif

/**
 * \brief 创建ip段数组
 * 
 * \param [in]  num 创建的数组大小
 * \param [in|out]  iprs ip段数组指针 
 * \return NULL：创建失败；其他：创建成功
 */
int ipranges_create(ip_ranges_st *iprs, int num);

/**
 * \brief 销毁ip段数组结构
 * 
 * \param [in]  iprs ip段数组指针
 */
void ipranges_destroy(ip_ranges_st *iprs);

/**
 * \brief 向ip段数组 iprs 中，添加一个ip段ipr
 * \detail 这种增加是会合并ip段数组中的元素
 *      1. 当待插入的ipr能包含数组中的元素时，会删除数组中的元素
 *      2. 当数组中的元素能包含待插入的ipr时，会删除待插入的元素
 *      3. 其他情况会正常插入，并按 ip段的 由小到大排列ip段数组
 * 
 * \param [in|out]  iprs ip段数组
 * \param [in|out]  ipr 待增加的ip段，当ip段能被数组中的元素包含时，会将 *ipr 释放，并置空
 * \return int  0:增加成功  -1：增加失败
 */
int ipranges_add(ip_ranges_st *iprs, ip_range_st **ipr);

/** 
 * \brief 加载ip黑白名单列表
 * \detial 解析字符串时使用状态转换，
 *         主要考虑到到会有多种情况的空格出现，ip段解析接口不支持输入多余的空格，
 *         并且行缓冲区有大小限制，需要尽可能的过滤掉空格。
 *         合法的输入：
 *              " 1.1.1.1  \\n"
 *              "  1.1.1.1    -    2.2.2.2        \\n"
 *              "  1.1.1.1   /   24   \\n"
 *              " # aaaaaaaa \\n "
 *              "1.1.1.1 # bbbbb\\n"
 *         非法输入：
 *              " 1. 1. 1. 1  \\n"
 *              " 1.1.1.1  -  \\n"
 *              " 1.1.1.1 /   \\n"
 *              "1.1.1.1 / # 24 \\n"
 *         非法输入返回-1，外层需要调用清理函数，清理iprs，否则会导致内存泄露
 * 
 * \param [out] iprs ip段数组结构
 * \param [in]  wbstr 黑白名单字符串
 * \param [in]  len 字符串长度
 * \return 解析成功：返回0；解析失败，返回-1，需要外层调用清理函数；
 */
int ipranges_load(ip_ranges_st *iprs, char *wbstr, int len);

/**
 * \brief 匹配ip段数组结构
 * 
 * \param [in]	iprs  ip段结构
 * \param [in]	ipv4/ipv6/ipstr ip格式
 * \return	int 匹配失败，返回-1；其他（>= 0），匹配成功；
 */
int ipranges_in4_match(ip_ranges_st *iprs, struct in_addr *ipv4);
int ipranges_in6_match(ip_ranges_st *iprs, struct in6_addr *ipv6);
int ipranges_string_match(ip_ranges_st *iprs, const char *ipstr);
#endif