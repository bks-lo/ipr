/**
 * 
 * \file ipstruct.c
 * \version 0.1
 * 
 * \brief ip 相关接口实现
 */

#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "ipstruct.h"
#include "debug.h"

/* 8位掩码 的16进制罗列 */
static uint8_t mask_uint8[] = {
    0x00, 0x80, 0xC0, 0xE0,
    0xF0, 0xF8, 0xFC, 0xFE
};

/**
 * \brief 打印IP结构
 * 
 * \param [in]  ipst IP结构
 * \return void
 */
static void debug_ip_st(ip_st *ipst)
{
    const char *dst = NULL;
    char tmp[IPV6_STORELEN_MAX] = {0};
    if (ipst->type == IPTYPE_V4) {
        dst = inet_ntop(AF_INET, (void *)&(ipst->v4), tmp, IPV6_STORELEN_MAX);
    } else {
        dst = inet_ntop(AF_INET6, (void *)&(ipst->v6), tmp, IPV6_STORELEN_MAX);
    }

    if (dst == NULL) {
        write_log(LOG_DEBUG, "type:%d parse failed", ipst->type);
        return ;
    }
    write_log(LOG_DEBUG, "type:%s %s", ipst->type == IPTYPE_V4 ? "ipv4" : "ipv6",
        tmp);
}

/**
 * \brief 打印IP段结构
 * 
 * \param [in]	ipr IP段结构
 * \return void
 */
static void debug_iprange_st(ip_range_st *ipr)
{
    const char *dsts = NULL;
    const char *dste = NULL;
    char start[IPV6_STORELEN_MAX] = {0};
    char end[IPV6_STORELEN_MAX] = {0};
    if (ipr->start.type == IPTYPE_V4) {
        dsts = inet_ntop(AF_INET, (void *)&(ipr->start.v4), start, IPV6_STORELEN_MAX);
        dste = inet_ntop(AF_INET, (void *)&(ipr->end.v4), end, IPV6_STORELEN_MAX);
    } else {
        dsts = inet_ntop(AF_INET6, (void *)&(ipr->start.v6), start, IPV6_STORELEN_MAX);
        dste = inet_ntop(AF_INET6, (void *)&(ipr->end.v6), end, IPV6_STORELEN_MAX);
    }

    if (dsts == NULL || dste == NULL) {
        write_log(LOG_DEBUG, "type:%d parse failed", ipr->start.type);
        return ;
    }
    write_log(LOG_DEBUG, "type:%s %s-%s", ipr->start.type == IPTYPE_V4 ? "ipv4" : "ipv6",
        start, end);
}

/**
 * \brief 比较两个ip
 * 
 * \param [in]	ip1 待比较的第一个ip
 * \param [in]	ip2 待比较的第二个ip
 * \return	int ip1 == ip2，返回0；ip1 > ip2，返回大于0；ip1 < ip2，返回小于0；
 */
int ipst_cmp(ip_st *ip1, ip_st *ip2)
{
    if (ip1->type != ip2->type) {
        if (ip1->type == IPTYPE_V6)
            return IPCMP_MORE;
        else
            return IPCMP_LESS;
    }

    int ret = 0;
    if (ip1->type == IPTYPE_V6)
        ret = memcmp(&(ip1->v6), &(ip2->v6), sizeof(ip1->v6));
    else
        ret = memcmp(&(ip1->v4), &(ip2->v4), sizeof(ip1->v4));

    if (ret == 0)
        return IPCMP_EQUAL;
    
    ret = ret > 0 ? IPCMP_MORE : IPCMP_LESS;
    return ret;
}

/**
 * \brief 解析单个ip字符串， 转换成 ip_st 结构，由外部提供结果空间
 * 
 * \param [out]	ipst 单ip结构
 * \param [in]	str  ip字符串
 * \param [in]	len  ip字符串长度
 * \return	int 解析成功，返回0；解析失败，返回-1；
 *          解析失败时，调用者需要注意空间的释放
 */
static int single_parser2(ip_st *ipst, const char *str, int len)
{
    assert(ipst != NULL && str != NULL && len > 0);

    /* 长度非法 */
    if (len > IPV6_STRLEN_MAX) {
        write_log(LOG_WARNING, "ip format invalid len[%d] %s", len, str);
        return -1;
    }

    int ret = 0;
    char tmp[IPV6_STORELEN_MAX] = {0};
    memcpy(tmp, str, len);

    if (strchr(tmp, ':') != NULL) {     /** IPv6 */
        ipst->type = IPTYPE_V6;
        ret = inet_pton(AF_INET6, tmp, (void *)&(ipst->v6));
    } else {                            /** IPv4 */
        ipst->type = IPTYPE_V4;
        ret = inet_pton(AF_INET, tmp, (void *)&(ipst->v4));
    }

    /* 转换失败 */
    if (ret <= 0) {
        write_log(LOG_WARNING, "ip str \"%s\" conver binary failed, type=%d", tmp, ipst->type);
        return -1;
    }

    return 0;
}

/**
 * \brief 解析单个ip字符串， 转换成 ip_st 结构， 内部开辟结果空间
 * 
 * \param [in]	ipstr ip字符串
 * \param [in]	len ip字符串长度
 * \return	ip_st*  解析成功，返回ip结构指针；解析失败，返回NULL;
 */
static ip_st *single_parser(const char *ipstr, int len)
{
    assert(ipstr != NULL && len > 0);

    ip_st *ipst = malloc(sizeof(ip_st));
    if (ipst == NULL) {
        write_log(LOG_ERROR, "malloc size %d failed !!!", sizeof(ipst));
        return NULL;
    }

    /* 转换失败 */
    if (single_parser2(ipst, ipstr, len) < 0) {
        free(ipst);
        return NULL;
    }

    return ipst;
}

/**
 * \brief 将点分十进制格式的掩码，转换成位数格式的掩码
 * \detial  255.255.0.0 -> 16
 *          255.254.0.0 -> 15
 *          255.255.224 -> 19
 * 
 * \param [in]	inmask 点分十进制的掩码格式
 * \return	int 转换成功，返回掩码位数；转换失败，返回-1；
 */
static int in_addr_to_mask(uint32_t inmask)
{
    int idx = 0;
    int i = 0;

    int bitlen = IPV4_BIT_NUM;
    for ( ; i < bitlen; ++i) {
        if (inmask & ((uint32_t)1 << i)) {
            ++idx;
            continue;
        }

        if (idx != 0) {
            write_log(LOG_WARNING, "IPv4 mask [0x%X] form invalid", inmask);
            return -1;
        }
    }

    return idx;
}

/**
 * \brief 判断掩码是否合法，不合法返回-1，合法返回mask所表示的位数   
 *        255.255.255.255   IPv4/24  IPv6/96 等格式 
 *        注意 规范规定IPv6的掩码只支持(0~128的)数字格式，不支持全0xff(ffff:ffff::0)的IPv6地址格式
 *        所以掩码字符串的最大长为 strlen("255.255.255.255") = 15
 * 
 * \param [in]	mask 掩码字符串
 * \param [in]	mlen 掩码字符串长度
 * \return	int int 解析成功，返回掩码位数；解析失败，返回-1；
 */
static int mask_parser(const char *mask, int mlen)
{
    assert(mask != NULL && mlen > 0);

    /* ip长度非法 */
    if (mlen > IP_MASKSTR_MAX) {
        write_log(LOG_WARNING, "mask len [%d] invalid !!!", mlen);
        return -1;
    }

    char tmp[IPV4_STORELEN_MAX] = {0};
    memcpy(tmp, mask, mlen);

    /* 出现了IPv6地址格式的掩码，认为非法 */
    if (strchr(tmp, ':') != NULL) {
        write_log(LOG_WARNING, "mask is IPv6 addr form, invalid !!!");
        return -1;
    }

    int ret = 0;
    if (strchr(tmp, '.') != NULL) {
        uint32_t v4mask;
        if (inet_pton(AF_INET, tmp, (void *)&v4mask) <= 0) {
            write_log(LOG_WARNING, "mask \"%s\" is invalid IPv4 form !!!", tmp);
            return -1;
        }

        v4mask = ntohl(v4mask);
        ret = in_addr_to_mask(v4mask);
    } else {
        char *end = NULL;
        long num = strtol(tmp, &end, 10);
        if (*end != '\0') {
            write_log(LOG_WARNING, "mask num string conver failed mask=%s end=%s", tmp, end);
            return -1;
        }

        ret = (int)num;
    }

    return ret;
}

/** */

/**
 * \brief 根据掩码，将pstart, pend格式化成ip段的起始和结束ip 
 * 
 * \param [in|out]	pstart 起始ip 通过uint8_t数组表示
 * \param [in|out]	pend 结束ip 通过uint8_t数组表示
 * \param [in]	len pstart和pend数组长度
 * \param [in]	mask 掩码位数
 * \return void
 */
static void set_range(uint8_t *pstart, uint8_t *pend, int len, int mask)
{
    int i;
    int idx = mask / 8;
    int step = mask % 8;

    /* 32 或者 128的掩码，不处理直接退出 */
    if (idx == len)
        return;
    
    pstart[idx] &=  mask_uint8[step];
    pend[idx] |= ~mask_uint8[step];

    for (i = idx + 1; i < len; ++i) {
        pstart[i] = 0;
        pend[i] = 0xff;
    }
}

/**
 * \brief 根据ip掩码 设置ip段范围
 * 
 * \param [in|out]	ipr ip段结构
 * \param [in]	mask    掩码位数
 * \return void
 */
static void ip_range_mask_set(ip_range_st *ipr, int mask)
{
    ip_st *psta = &(ipr->start);
    ip_st *pend = &(ipr->end);
    
    if (psta->type == IPTYPE_V4) {
        set_range((uint8_t *)&(psta->v4.s_addr), (uint8_t *)&(pend->v4.s_addr), 
                  IPV4_BIT_NUM / 8, mask);
    } else {
        set_range(psta->v6.s6_addr, pend->v6.s6_addr, IPV6_BIT_NUM / 8, mask);
    }

    return;
}

/**
 * \brief 将掩码格式的ipstr转换成ip段格式 
 * \detial 输入包括192.168.1.141/24  2020:ffff::0141/112 等
 * 
 * \param [in]	ipstr ip掩码字符串
 * \param [in]	len   字符串长度
 * \param [in]	idx   分隔符下标 (斜杠的下标)
 * \return	ip_range_st*  解析成功，返回ip段结构；解析失败，返回NULL；
 */
static ip_range_st *ip_maskstr_parser(const char *ipstr, int len, int idx)
{
    ip_range_st *iprange = NULL;
    ip_st *ipst = single_parser(ipstr, idx);
    if (ipst == NULL) {
        write_log(LOG_WARNING, "%s parse ip failed !!!", ipstr);
        return NULL;
    }

    int mask = mask_parser(&ipstr[idx + 1], len - idx - 1);
    if (ipst->type == IPTYPE_V4 && (mask <0 || mask > IPV4_BIT_NUM)) {
        write_log(LOG_WARNING, "%s parse mask failed, len %d invilad !!!", ipstr, mask);
        goto imp_ret;
    } else if (ipst->type == IPTYPE_V6 && (mask < 0 || mask > IPV6_BIT_NUM)) {
        write_log(LOG_WARNING, "%s parse mask failed, len %d invilad !!!", ipstr, mask);
        goto imp_ret;
    }

    iprange = malloc(sizeof(ip_range_st));
    if (iprange == NULL) {
        write_log(LOG_WARNING, "malloc size %d failed !!!", sizeof(ip_range_st));
        goto imp_ret;
    }

    memset(iprange, 0, sizeof(ip_range_st));
    memcpy(&(iprange->start), ipst, sizeof(ip_st));
    memcpy(&(iprange->end), ipst, sizeof(ip_st));
    ip_range_mask_set(iprange, mask);

imp_ret:
    free(ipst);
    return iprange;
}

/**
 * \brief 将ip段字符串转换成ip段二进制结构
 * \detial 输入包括1.1.1.1-2.2.2.2   2020::1111-2020::2222
 * 
 * \param [in]	ipstr ip掩码字符串
 * \param [in]	len   字符串长度
 * \param [in]	idx   分隔符下标 (短横线的下标)
 * \return	ip_range_st*  解析成功，返回ip段结构；解析失败，返回NULL；
 */
static ip_range_st *ip_segstr_parser(const char *ipstr, int len, int idx)
{
    ip_range_st *iprange = NULL;

    ip_st *ipst_s = single_parser(ipstr, idx);
    if (ipst_s == NULL) {
        write_log(LOG_WARNING, "%s parse start ip failed !!!", ipstr);
        return NULL;
    }

    ip_st *ipst_e = single_parser(ipstr + idx + 1, len - idx - 1);
    if (ipst_e == NULL) {
        write_log(LOG_WARNING, "%s parse ip failed !!!", ipstr);
        goto isp_ret;
    }

    if (ipst_s->type != ipst_e->type) {
        write_log(LOG_WARNING, "ip range %s parse failed : ip type not match !!!", ipstr);
        goto isp_ret;
    }

    if (ipst_cmp(ipst_s, ipst_e) == IPCMP_MORE) {
        write_log(LOG_WARNING, "ip range %s parse failed : start > end !!!", ipstr);
        goto isp_ret;
    }

    iprange = malloc(sizeof(ip_range_st));
    memcpy(&(iprange->start), ipst_s, sizeof(ip_st));
    memcpy(&(iprange->end), ipst_e, sizeof(ip_st));

isp_ret:
    if (ipst_s != NULL)
        free(ipst_s);
    if (ipst_e != NULL)
        free(ipst_e);

    return iprange;
}

/**
 * \brief 将单ip字符串，转换成ip段二进制结构
 * 
 * \param [in]	ipstr 单ip字符串
 * \param [in]	len   字符串长度
 * \return	ip_range_st* 解析成功，返回ip段结构；解析失败，返回NULL；
 */
static ip_range_st *ip_singlestr_parser(const char *ipstr, int len)
{
    ip_range_st *ipr = malloc(sizeof(ip_range_st));
    
    if (single_parser2(&(ipr->start), ipstr, len) != 0) {
        free(ipr);
        return NULL;
    }

    memcpy(&(ipr->end), &(ipr->start), sizeof(ipr->start));
    return ipr;
}


/**
 * \brief 将ip字符串(ipv6和ipv4的单ip、ip段、ip掩码) 转换成ip段二进制结构
 * 
 * \param [in]	ipstr ip字符串
 * \param [in]	len 字符串长度
 * \return	ip_range_st* 解析成功，返回ip段结构；解析失败，返回NULL；
 */
ip_range_st *ip_string_parser(const char *ipstr, int len)
{
    if (ipstr == NULL || len == 0) {
        write_log(LOG_WARNING, "param invalid ipstr=%p  len=%d", ipstr, len);
        return NULL;
    }

    char *mask = strchr(ipstr, '/');
    if (mask != NULL) {
        return ip_maskstr_parser(ipstr, len, mask - ipstr);
    }

    char *seg = strchr(ipstr, '-');
    if (seg != NULL) {
        return ip_segstr_parser(ipstr, len, seg - ipstr);
    } 

    return ip_singlestr_parser(ipstr, len);
}

/**
 * \brief 使用单ip 和 ip段进行比较
 * 
 * \param [in]	ipr ip段
 * \param [in]	ipst 单ip
 * \return	int 1：ip在ip段的左侧；0：ip在ip段的内部；-1：ip在ip段的右侧
 */
static int iprange_cmp1(ip_range_st *ipr, ip_st *ipst)
{
    int ret = ipst_cmp(&(ipr->start), ipst);
    if (ret == IPCMP_EQUAL)
        return 0;

    if (ret == IPCMP_MORE)
        return 1;
    
    ret = ipst_cmp(&(ipr->end), ipst);
    if (ret == IPCMP_MORE || ret == IPCMP_EQUAL)
        return 0;

    return -1;
}

/**
 * 比较两个ip段
 * |_ _ _ _ _ _ _ _ _ _ _ _ _ _|
 * 0                           255
 *  ip1: |_ _ _ _ _|
 *      ip2: |_ _ _ _ _|
 * ip1 比 ip2 更靠左, ip2 比 ip1 更靠右
 * 返回值：
 *      1: ipr1 包含 ipr2 (包含 ipr1 == ipr2 等情况)
 *     -1：ipr1 被 ipr2 包含
 *     -2：ipr1 表示的范围比 ipr2 更靠左
 *      2：ip21 表示的范围比 ipr2 更靠右
 */
static int iprange_cmp2(ip_range_st *ipr1, ip_range_st *ipr2)
{
    int ret = 0;
    int rs = ipst_cmp(&(ipr1->start), &(ipr2->start));
    int re = ipst_cmp(&(ipr1->end), &(ipr2->end));

    if (rs <= 0 && re >= 0) {               /* ipr1 包含 ipr2 */
        ret = IPRCMP_1INCLUDE2;
    } else if (rs >= 0 && re <= 0) {        /* ipr2 包含 ipr1 */
        ret = IPRCMP_2INCLUDE1;
    } else {                                /* 比较end位置，end位置决定 ip段的大小 */
        ret = re > 0 ? IPRCMP_MORE : IPRCMP_LESS;
    }

    return ret;
}

#if 0
接口不完善，不能正常排序，下方有ipranges_add接口，可以替代排序功能，删掉这个接口
/**
 * 对ip段数组进行排序，使用选择排序
 * 按start做升序排列
 * 0：排序成功  其他：排序失败
 */
int ip_ranges_sort(ip_range_st **ipranges, int num)
{
    int i, j;
    ip_range_st tmp = {{0}, {0}};
    int min = 0;

    for (i = 0; i < num; ++i) {
        min = i;
        for (j = i + 1; j < num; ++j) {
            if (ipst_cmp(&(ipranges[j]->start), &(ipranges[min]->start)) == IPCMP_LESS) {
                min = j;
            }
        }

        if (i == min)
            continue;

        memcpy(&tmp, ipranges[i], sizeof(ip_range_st));
        memcpy(ipranges[i], ipranges[min], sizeof(ip_range_st));
        memcpy(ipranges[min], &tmp, sizeof(ip_range_st));
    }

    return 0;
}
#endif

/**
 * \brief 在ip段 数组中找到能匹配ipst的段，匹配成功返回数组下标，匹配失败返回-1
 * 
 * \param [in|out]	iprarr IP段数组
 * \param [in|out]	num    数组元素个数
 * \param [in|out]	ipst   需要匹配的ip
 * \return	int 匹配失败返回小于0的值；匹配成功，返回大于等于0的值；
 */
int ip_rangearr_match(ip_range_st **iprarr, int num, ip_st *ipst)
{
    int start = 0;
    int end = num - 1;
    int mid = 0;
    int cmp = 0;
    
    while (start <= end) {
        mid = (start + end)/2;

        cmp = iprange_cmp1(iprarr[mid], ipst);
        if (cmp == 0) {
            return mid;
        }

        if (cmp > 0)
            end = mid - 1;
        else 
            start = mid + 1; 
    }
    return -1;
}

#if 0
int ip_in4_match(ip_range_st **ipranges, int num, struct in_addr *ipv4)
{
    ip_st ipst = {0};
    ipst.type = IPTYPE_V4;
    memcpy(&(ipst.v4), ipv4, sizeof(struct in_addr));

    return ip_rangearr_match(ipranges, num, &ipst);
}

int ip_in6_match(ip_range_st **ipranges, int num, struct in6_addr *ipv6)
{
    ip_st ipst = {0};
    ipst.type = IPTYPE_V6;
    memcpy(&(ipst.v6), ipv6, sizeof(struct in6_addr));

    return ip_rangearr_match(ipranges, num, &ipst);
}

int ip_string_match(ip_range_st **ipranges, int num, const char *ipstr)
{
    ip_st ipst = {0};
    if (single_parser2(&ipst, ipstr, strlen(ipstr)) != 0) {
        return -1;
    }
    
    return ip_rangearr_match(ipranges, num, &ipst);
}
#endif

/**
 * \brief ip段数组创建
 * 
 * \param [in|out]	iprs ip段数组结构
 * \param [in]	num 需要开辟的元素个数
 * \return	int  创建成功返回0；创建失败返回-1；
 */
int ipranges_create(ip_ranges_st *iprs, int num)
{
    assert(iprs != NULL && num > 0);

    ip_range_st **iprarr = malloc(sizeof(ip_range_st *) * num);
    MALLOC_RETURN(iprarr, sizeof(ip_range_st *) * num, -1);
    if (iprarr == NULL) {
        write_log(LOG_ERROR, "malloc size %d failed", sizeof(ip_range_st *) * num);
        free(iprs);
        return -1;
    }

    memset(iprarr, 0, sizeof(ip_range_st *) * num);
    iprs->max = num;
    iprs->iprarr = iprarr;
    return 0;
}

/**
 * \brief 销毁ip段数组结构
 * 
 * \param [in]  iprs ip段数组指针
 */
void ipranges_destroy(ip_ranges_st *iprs)
{
    if (iprs == NULL)
        return;

    int i;
    for (i = 0; i < iprs->cur; ++i) {
        if (iprs->iprarr[i] == NULL)
            continue;
        
        free(iprs->iprarr[i]);
        iprs->iprarr[i] = NULL;
    }

    free(iprs->iprarr);
    iprs->iprarr = NULL;
    iprs->max = 0;
    iprs->cur = 0;
}

/**
 * \brief ip段数组扩容
 * 
 * \param [in|out]	iprs ip段数组结构
 * \param [in]	add 需要增加的个数
 * \return	int  创建成功返回0；创建失败返回-1；
 */
static int ipranges_relloc(ip_ranges_st *iprs, int add)
{
    assert(iprs != NULL && add > 0);

    int num = iprs->max + add;
    ip_range_st **new = NULL;
    MALLOC_RETURN(new, sizeof(ip_range_st *) * num, -1);

    memcpy(new, iprs->iprarr, iprs->max * sizeof(ip_range_st *));
    free(iprs->iprarr);
    iprs->iprarr = new;
    iprs->max = num;
    return 0;
}

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
int ipranges_add(ip_ranges_st *iprs, ip_range_st **ipr)
{
    ip_range_st **arr = iprs->iprarr;
    int cmp = 0;            /* 比较结果 */
    int ins = 0;            /* 插入位置下标 */
    int i = iprs->cur - 1;
    int j = 0;

    while (i >= 0) {
        cmp = iprange_cmp2(arr[i], *ipr);
        
        /* 数组中的ip段能包含待插入的段，则不会真正add这个数据 */
        if (cmp == IPRCMP_1INCLUDE2) {
            write_log(LOG_DEBUG, "%d include ipr, return 0", i);
            free(*ipr);
            *ipr = NULL;
            return 0;
        }
        
        if (cmp == IPCMP_LESS) {    /* arr[i] < ipr */
            ins = i + 1;
            break;
        } else if (cmp == IPRCMP_2INCLUDE1) {   /* ipr 包含 arr[i] */
            /*  如果带插入数据 能包含数组中的元素，则删除元素，缩小数组范围, 继续向前寻找 */
            free(arr[i]);
            for (j = i + 1; j < iprs->cur; ++j) {
                arr[j - 1] = arr[j];
                arr[j] = NULL;
            }
            iprs->cur -= 1;
        }

        --i;
    }
    
    /* 当ip段数组已经满时，需要重新开辟空间 */
    if (iprs->cur >= iprs->max) {
        ipranges_relloc(iprs, 5);  /* 多开辟一些空间，避免频繁malloc */
        arr = iprs->iprarr;
    }

    i = iprs->cur;
    while (i > ins) {
        arr[i] = arr[i - 1];
        --i;
    }
    arr[ins] = *ipr;
    iprs->cur += 1;

    return 0;
}

/** 
 * IP段字符串解析状态定义
 * ipstr :   # aaaaaaa              \\n
 * state :0  1
 * 
 * ipstr :   1.1.1.1  -  2.2.2.2    \\n
 * state :0  2      3 4  5      6
 * 
 * ipstr :   1.1.1.1    /    24     \\n
 * state :0  2      3   7    8 9
 * 
 */
typedef enum {
    IPRSTAT_NULL = 0,       /**< 空状态 */
    IPRSTAT_COMT,           /**< 注释 */
    IPRSTAT_IP1S,           /**< 第一段ip 开始 */
    IPRSTAT_IP1E,           /**< 第一段ip 结束 */
    IPRSTAT_WIP2,           /**< 等待第二个ip段 */
    IPRSTAT_IP2S,           /**< 第二段ip 开始 */
    IPRSTAT_IP2E,           /**< 第二段ip 结束 */
    IPRSTAT_WMASK,          /**< 等待掩码 */
    IPRSTAT_MASKS,          /**< 掩码开始 */
    IPRSTAT_MASKE,          /**< 掩码结束 */
} iprstr_pstat_em;

/** 将解析到字符加入临时数组中 */
#define TMP_IPSTR_CHAR_SET(ch) do {                                         \
    if (ipidx + 1 >= IP_RANGESTR_MAX) {                                     \
        write_log(LOG_WARNING, "ipstr len[%d] invalid", ipidx);             \
        return -1;                                                          \
    }                                                                       \
                                                                            \
    tmp_ipstr[ipidx] = ch;                                                  \
    ipidx += 1;                                                             \
    tmp_ipstr[ipidx] = '\0';                                                \
} while(0)


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
int ipranges_load(ip_ranges_st *iprs, char *wbstr, int len)
{
    assert(iprs != NULL && wbstr != NULL && len >= 0);

    int i = 0;
    int ipidx = 0;
    int loop = 1;
    ip_range_st *tmp_ipr = NULL;
    iprstr_pstat_em state = IPRSTAT_NULL;
    char tmp_ipstr[IP_RANGESTR_MAX] = {0};
    char *end = NULL;

    for (i = 0; loop != 0; ++i) {
        switch(wbstr[i]) {
        case ' ':                       /* 遇到空格，代表几种状态的结束 */
            switch (state) {
            case IPRSTAT_IP1S:          /* "1.1.1.1 "*/
                state = IPRSTAT_IP1E;
                break;
            case IPRSTAT_IP2S:          /* "1.1.1.1-2.2.2.2 "*/
                state = IPRSTAT_IP2E;
                break;
            case IPRSTAT_MASKS:         /* "1.1.1.1/24 "*/
                state = IPRSTAT_MASKE;
                break;
            default: /* 其他状态保持原状态，不处理 */
                break;
            }
            break;
        case '-':
        case '/':
            TMP_IPSTR_CHAR_SET(wbstr[i]);

            switch (state) {
            case IPRSTAT_IP1S:      /* "1.1.1.1-" or "1.1.1.1/" */
            case IPRSTAT_IP1E:      /* "1.1.1.1 -" or "1.1.1.1 /" */
                state = (wbstr[i] == '-') ? IPRSTAT_WIP2 : IPRSTAT_WMASK;
                break;
            default:
                write_log(LOG_WARNING, "cur char is \'%c\',cur state [%d] not match. tmp_ipstr[%s]",
                          wbstr[i], state, tmp_ipstr);
                return -1;
            }
            break;
        case '#':       /* 有注释 */
            switch (state) {
            case IPRSTAT_NULL:      /* " # "*/
            case IPRSTAT_IP1S:      /* "1.1.1.1#" */
            case IPRSTAT_IP1E:      /* "1.1.1.1 #"*/
            case IPRSTAT_IP2S:      /* "1.1.1.1-2.2.2.2#" */
            case IPRSTAT_IP2E:      /* "1.1.1.1-2.2.2.2  #" */
            case IPRSTAT_MASKS:     /* "1.1.1.1/24#" */
            case IPRSTAT_MASKE:     /* "1.1.1.1/24  #" */
                end = strchr(wbstr + i, '\n');      /* 找到下一个行分隔符 */
                if (end == NULL)
                    i = len;                        /* 没有下一行 直接跳到 字符串末尾 */
                else
                    i = end - wbstr;                /* 跳到行分割符 */

                i -= 1;                             /* for循环最后还有一个++i 这里先提前减一 */
                break;
            default:
                /* 非法状态直接退出 */
                write_log(LOG_WARNING, "cur char is \'%c\',cur state [%d] not match. tmp_ipstr[%s]",
                        wbstr[i], state, tmp_ipstr);
                return -1;
            }
            break;
        case '\0':      /* 停止循环，并复用下面的ip段解析和添加逻辑 */
            loop = 0;
        case '\n':      /* 一行结束 */
            switch(state) {
            case IPRSTAT_IP1S:      /* "1.1.1.1\n" */
            case IPRSTAT_IP1E:      /* "1.1.1.1 \n"*/
            case IPRSTAT_IP2S:      /* "1.1.1.1-2.2.2.2\n" */
            case IPRSTAT_IP2E:      /* "1.1.1.1-2.2.2.2  \n" */
            case IPRSTAT_MASKS:     /* "1.1.1.1/24\n" */
            case IPRSTAT_MASKE:     /* "1.1.1.1/24  \n" */
                /* 解析记录的ip段信息 */
                tmp_ipr = ip_string_parser(tmp_ipstr, ipidx);
                if (tmp_ipr == NULL) {
                    write_log(LOG_WARNING, "ipstr[%d][%s] parser failed !!!", ipidx, tmp_ipstr);
                    return -1;
                }
                /* 将解析到的ip段加入到黑白名单数组中 */
                ipranges_add(iprs, &tmp_ipr);
                /* 这里不用break，复用下面的清理 */
            case IPRSTAT_NULL:
                /* 清理状态 */
                ipidx = 0;
                state = IPRSTAT_NULL;
                break;
            default:    /* 非法状态 */
                write_log(LOG_WARNING, "ipstr[%d][%s] parser failed state[%d]!!!", ipidx, tmp_ipstr, state);
                return -1;
            }
            break;
        default:
            TMP_IPSTR_CHAR_SET(wbstr[i]);

            switch (state) {
            case IPRSTAT_IP1S:              /* 这三种start状态，继续记录字符，状态不变 */
            case IPRSTAT_IP2S:
            case IPRSTAT_MASKS:
                break;
            case IPRSTAT_NULL:              /* 开始第一个ip地址解析 */
                state = IPRSTAT_IP1S;
                break;
            case IPRSTAT_WIP2:              /* "1.1.1.1-2" */
                state = IPRSTAT_IP2S;
                break;
            case IPRSTAT_WMASK:             /* "1.1.1.1/2" */
                state = IPRSTAT_MASKS;
                break;
            default:
                write_log(LOG_WARNING, "cur char is \'%c\',cur state [%d] not match. tmp_ipstr[%s]",
                          wbstr[i], state, tmp_ipstr);
                return -1;
            }
            break;
        }
    }
    return 0;
}


/* 匹配ip段数组结构，参数为struct in_addr的版本 */
int ipranges_in4_match(ip_ranges_st *iprs, struct in_addr *ipv4)
{
    ip_st ipst = {0};
    ipst.type = IPTYPE_V4;
    memcpy(&(ipst.v4), ipv4, sizeof(struct in_addr));

    return ip_rangearr_match(iprs->iprarr, iprs->cur, &ipst);
}

/* 匹配ip段数组结构，参数为struct in6_addr的版本 */
int ipranges_in6_match(ip_ranges_st *iprs, struct in6_addr *ipv6)
{
    ip_st ipst = {0};
    ipst.type = IPTYPE_V6;
    memcpy(&(ipst.v6), ipv6, sizeof(struct in6_addr));

    return ip_rangearr_match(iprs->iprarr, iprs->cur, &ipst);
}

/* 匹配ip段数组结构，参数为ip字符串的版本 */
int ipranges_string_match(ip_ranges_st *iprs, const char *ipstr)
{
    ip_st ipst = {0};
    if (single_parser2(&ipst, ipstr, strlen(ipstr)) != 0) {
        return -1;
    }
    
    return ip_rangearr_match(iprs->iprarr, iprs->cur, &ipst);;
}


#ifdef UNIT_TEST_IPR

#include <check.h>
#define STR_L(s) s, strlen(s)

#define STR_SLASH(s) s, strlen(s), (strchr(s, '/') - s)
#define STR_DASH(s) s, strlen(s), (strchr(s, '-') - s)

#define DEBUG_IP(ipst) do { \
    if (ipst != NULL) { \
        debug_ip_st(ipst); \
        free(ipst); \
        ipst = NULL; \
    } \
} while(0)

#define DEBUG_IPRANGE(ipr) do { \
    if (ipr != NULL) { \
        debug_iprange_st(ipr); \
        free(ipr); \
        ipr = NULL; \
    } \
} while(0)


/** 案例：测试单ip解析接口 */
START_TEST(test_single_parser)
{
    /* 正常ipv4 */
    char *ipstr = "192.168.1.1";
    struct in_addr in4 = {0};
    struct in6_addr in6 = {0};
    
    ip_st *ipst = single_parser(STR_L(ipstr));
    inet_pton(AF_INET, ipstr, &in4);
    ck_assert_msg(memcmp(&in4, &(ipst->v4), sizeof(in4)) == 0, "%s not equal !!!", ipstr);
    DEBUG_IP(ipst);

    /* 全零的ipv4 */
    ipstr = "0.0.0.0";
    ipst = single_parser(STR_L(ipstr));
    inet_pton(AF_INET, ipstr, &in4);
    ck_assert_msg(memcmp(&in4, &(ipst->v4), sizeof(in4)) == 0, "%s not equal !!!", ipstr);
    DEBUG_IP(ipst);
    

    /* 全1的ipv4 */
    ipstr = "255.255.255.255";
    ipst = single_parser(STR_L(ipstr));
    inet_pton(AF_INET, ipstr, &in4);
    ck_assert_msg(memcmp(&in4, &(ipst->v4), sizeof(in4)) == 0, "%s not equal !!!", ipstr);
    DEBUG_IP(ipst);

    /* 带ipv4格式的ipv6 */
    ipstr = "::192.168.1.1";
    ipst = single_parser(STR_L(ipstr));
    inet_pton(AF_INET6, ipstr, &in6);
    ck_assert_msg(memcmp(&in6, &(ipst->v6), sizeof(in6)) == 0, "%s not equal !!!", ipstr);
    DEBUG_IP(ipst);

    /* 混合ipv4格式的ipv6 */
    ipstr = "::ffff:192.168.1.1";
    ipst = single_parser(STR_L(ipstr));
    inet_pton(AF_INET6, ipstr, &in6);
    ck_assert_msg(memcmp(&in6, &(ipst->v6), sizeof(in6)) == 0, "%s not equal !!!", ipstr);
    DEBUG_IP(ipst);

    /* 正常ipv6格式 */
    ipstr = "1234:1234:1234:1234:1234:1234:1234:1234";
    ipst = single_parser(STR_L(ipstr));
    inet_pton(AF_INET6, ipstr, &in6);
    ck_assert_msg(memcmp(&in6, &(ipst->v6), sizeof(in6)) == 0, "%s not equal !!!", ipstr);
    DEBUG_IP(ipst);

    /* 全零的ipv6格式 */
    ipstr = "0000:0000:0000:0000:0000:0000:0000:0000";
    ipst = single_parser(STR_L(ipstr));
    inet_pton(AF_INET6, ipstr, &in6);
    ck_assert_msg(memcmp(&in6, &(ipst->v6), sizeof(in6)) == 0, "%s not equal !!!", ipstr);
    DEBUG_IP(ipst);
}
END_TEST

/** 测试掩码解析 */
START_TEST(test_mask_parser)
{
    /* 全1的IPv4格式掩码 */
    char *maskstr = "255.255.255.255";
    int mask = mask_parser(STR_L(maskstr));
    ck_assert_msg(mask == 32, "%s not equal !!!", maskstr);

    /* IPv4格式掩码 */
    maskstr = "255.255.255.248";
    mask = mask_parser(STR_L(maskstr));
    ck_assert_msg(mask == 29, "%s not equal !!!", maskstr);

    /* 非法的IPv4格式掩码 */
    maskstr = "255.255.254.254";
    mask = mask_parser(STR_L(maskstr));
    ck_assert_msg(mask == -1, "%s[%d] not equal !!!", maskstr, mask);

    /* 全0的ipv4格式掩码 */
    maskstr = "0.0.0.0";
    mask = mask_parser(STR_L(maskstr));
    ck_assert_msg(mask == 0, "%s not equal !!!", maskstr);

    /* 全1的ipv6格式掩码 */
    maskstr = "128";
    mask = mask_parser(STR_L(maskstr));
    ck_assert_msg(mask == 128, "%s not equal !!!", maskstr);

    /* 超限的ipv6格式掩码 */
    maskstr = "129";
    mask = mask_parser(STR_L(maskstr));
    ck_assert_msg(mask == 129, "%s not equal !!!", maskstr);

    /* 普通的数字格式掩码 */
    maskstr = "32";
    mask = mask_parser(STR_L(maskstr));
    ck_assert_msg(mask == 32, "%s not equal !!!", maskstr);

    /* 带有字符的非法掩码 */
    maskstr = "32haha";
    mask = mask_parser(STR_L(maskstr));
    ck_assert_msg(mask == -1, "%s not equal !!!", maskstr);

    /* 负数掩码 */
    maskstr = "-32";
    mask = mask_parser(STR_L(maskstr));
    ck_assert_msg(mask == -32, "%s not equal !!!", maskstr);
}
END_TEST

/** 比较ip段中的起始 == ips, 结束 == ipe */
static int test_ip_maskstr_cmp(ip_range_st *ipr, char *ips, char *ipe)
{
    int ret = 0;
    struct in_addr v4[2] = {0};
    struct in6_addr v6[2] = {0};

    if (ipr->start.type == IPTYPE_V4) {
        inet_pton(AF_INET, ips, &(v4[0]));
        inet_pton(AF_INET, ipe, &(v4[1]));

        ret = memcmp(&(v4[0]), &(ipr->start.v4), sizeof(struct in_addr));
        ret |= memcmp(&(v4[1]), &(ipr->end.v4), sizeof(struct in_addr));
    } else {
        inet_pton(AF_INET6, ips, &(v6[0]));
        inet_pton(AF_INET6, ipe, &(v6[1]));

        ret = memcmp(&(v6[0]), &(ipr->start.v6), sizeof(struct in6_addr));
        ret |= memcmp(&(v6[1]), &(ipr->end.v6), sizeof(struct in6_addr));
    }

    return ret;
}

/** 测试带有掩码的ip段解析 */
START_TEST(test_ip_maskstr_parser)
{
    ip_range_st *ipr = NULL;
    int ret = 0;
    char *ipstr = NULL;

    /* 带数字掩码的ipv4段 */
    ipstr = "192.168.1.100/16";
    ipr = ip_maskstr_parser(STR_SLASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "192.168.0.0", "192.168.255.255");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);

    /* 带ipv4格式掩码的ipv4段 */
    ipstr = "192.168.1.100/255.255.0.0";
    ipr = ip_maskstr_parser(STR_SLASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "192.168.0.0", "192.168.255.255");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);


    /* 特殊的ipv4格式掩码的ipv4段 */
    ipstr = "192.168.1.100/255.240.0.0";
    ipr = ip_maskstr_parser(STR_SLASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "192.160.0.0", "192.175.255.255");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);

    /* 特殊的ipv4格式掩码的ipv4段 */
    ipstr = "192.168.1.100/255.254.0.0";
    ipr = ip_maskstr_parser(STR_SLASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "192.168.0.0", "192.169.255.255");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);

    /* 全1的ipv4格式掩码的ipv4段 */
    ipstr = "192.168.1.100/255.255.255.255";
    ipr = ip_maskstr_parser(STR_SLASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "192.168.1.100", "192.168.1.100");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);

    /* 全0的ipv4格式掩码的ipv4段 */
    ipstr = "192.168.1.100/0.0.0.0";
    ipr = ip_maskstr_parser(STR_SLASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "0.0.0.0", "255.255.255.255");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);

    /* 120位掩码的ipv6段 */
    ipstr = "2020::ffff:ffff/120";
    ipr = ip_maskstr_parser(STR_SLASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "2020::ffff:ff00", "2020::ffff:ffff");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);

    /* 112位掩码的ipv6段 */
    ipstr = "2020::ffff:ffff/112";
    ipr = ip_maskstr_parser(STR_SLASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "2020:0:0:0:0:0:ffff:0", "2020::ffff:ffff");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);

    /* 108位掩码的ipv6段 */
    ipstr = "2020::ffff:ffff/108";
    ipr = ip_maskstr_parser(STR_SLASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "2020:0:0:0:0:0:fff0:0", "2020::ffff:ffff");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);

    /* 100位掩码的ipv6段 */
    ipstr = "2020::ffff:ffff/100";
    ipr = ip_maskstr_parser(STR_SLASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "2020:0:0:0:0:0:f000:0", "2020::ffff:ffff");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);

    /* 96位掩码的ipv6段 */
    ipstr = "2020::ffff:ffff/96";
    ipr = ip_maskstr_parser(STR_SLASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "2020:0:0:0:0:0:0:0", "2020::ffff:ffff");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);

    /* 97位掩码的ipv6段 */
    ipstr = "2020::ffff:ffff/97";
    ipr = ip_maskstr_parser(STR_SLASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "2020:0:0:0:0:0:8000:0", "2020::ffff:ffff");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);

    /* 0位掩码的ipv6段 */
    ipstr = "2020::ffff:ffff/0";
    ipr = ip_maskstr_parser(STR_SLASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "0::0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);

    /* 128位掩码的ipv6段 */
    ipstr = "2020::ffff:ffff/128";
    ipr = ip_maskstr_parser(STR_SLASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "2020::ffff:ffff", "2020::ffff:ffff");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);

    /* 128位掩码的ipv6段 */
    ipstr = "::192.168.1.100/111";
    ipr = ip_maskstr_parser(STR_SLASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "::192.168.0.0", "::192.169.255.255");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);

    /* 128位掩码的ipv6段 */
    ipstr = "::ffff:192.168.1.100/111";
    ipr = ip_maskstr_parser(STR_SLASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "::ffff:192.168.0.0", "::ffff:192.169.255.255");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);
}
END_TEST

/** 测试ip_st结构的比较函数 */
START_TEST(test_ipst_cmp)
{
    ip_st *ip1 = single_parser(STR_L("192.168.1.2"));
    ip_st *ip2 = single_parser(STR_L("192.168.1.3"));
    ck_assert_msg(ipst_cmp(ip1, ip2) < 0, "ipst_cmp not expect");
    free(ip1);
    free(ip2);

    ip1 = single_parser(STR_L("192.168.1.4"));
    ip2 = single_parser(STR_L("192.168.1.3"));
    ck_assert_msg(ipst_cmp(ip1, ip2) > 0, "ipst_cmp not expect");
    free(ip1);
    free(ip2);

    ip1 = single_parser(STR_L("192.168.1.3"));
    ip2 = single_parser(STR_L("192.168.1.3"));
    ck_assert_msg(ipst_cmp(ip1, ip2) == 0, "ipst_cmp not expect");
    free(ip1);
    free(ip2);

    ip1 = single_parser(STR_L("255.255.255.254"));
    ip2 = single_parser(STR_L("255.255.255.253"));
    ck_assert_msg(ipst_cmp(ip1, ip2) > 0, "ipst_cmp not expect");
    free(ip1);
    free(ip2);

    ip1 = single_parser(STR_L("254.255.255.255"));
    ip2 = single_parser(STR_L("253.255.255.255"));
    ck_assert_msg(ipst_cmp(ip1, ip2) > 0, "ipst_cmp not expect");
    free(ip1);
    free(ip2);

    ip1 = single_parser(STR_L("ffff::fffe"));
    ip2 = single_parser(STR_L("253.255.255.255"));
    ck_assert_msg(ipst_cmp(ip1, ip2) > 0, "ipst_cmp not expect");
    free(ip1);
    free(ip2);

    ip1 = single_parser(STR_L("ffff::fffe"));
    ip2 = single_parser(STR_L("ffff::fffe"));
    ck_assert_msg(ipst_cmp(ip1, ip2) == 0, "ipst_cmp not expect");
    free(ip1);
    free(ip2);

    ip1 = single_parser(STR_L("ffff::fffe"));
    ip2 = single_parser(STR_L("ffff::fffd"));
    ck_assert_msg(ipst_cmp(ip1, ip2) > 0, "ipst_cmp not expect");
    free(ip1);
    free(ip2);

    ip1 = single_parser(STR_L("fffd::fffe"));
    ip2 = single_parser(STR_L("fffe::fffd"));
    ck_assert_msg(ipst_cmp(ip1, ip2) < 0, "ipst_cmp not expect");
    free(ip1);
    free(ip2);

    ip1 = single_parser(STR_L("fffd::ffff"));
    ip2 = single_parser(STR_L("fffe::ffff"));
    ck_assert_msg(ipst_cmp(ip1, ip2) < 0, "ipst_cmp not expect");
    free(ip1);
    free(ip2);
}
END_TEST

/** 测试ip段解析函数 */
START_TEST(test_ip_segstr_parser)
{
    ip_range_st *ipr = NULL;
    int ret = 0;
    char *ipstr = NULL;

    ipstr = "192.168.1.1-192.168.1.2";
    ipr = ip_segstr_parser(STR_DASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "192.168.1.1", "192.168.1.2");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);
    
    ipstr = "0::0-fff::ffff";
    ipr = ip_segstr_parser(STR_DASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "::", "fff::ffff");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);


    ipstr = "::-fff::ffff";
    ipr = ip_segstr_parser(STR_DASH(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "::", "fff::ffff");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);

    ipstr = "192.168.1.3-192.168.1.2";
    ipr = ip_segstr_parser(STR_DASH(ipstr));
    ck_assert_msg(ipr == NULL, "%p not NULL !!!", ipstr);
}
END_TEST

/** 测试 将单ip转换成ip段的功能 */
START_TEST(test_ip_string_parser)
{
     ip_range_st *ipr = NULL;
    int ret = 0;
    char *ipstr = NULL;

    ipstr = "192.168.1.3";
    ipr = ip_string_parser(STR_L(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "192.168.1.3", "192.168.1.3");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);

    ipstr = "0.0.0.0";
    ipr = ip_string_parser(STR_L(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "0.0.0.0", "0.0.0.0");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);

    ipstr = "0.0.0.0/0";
    ipr = ip_string_parser(STR_L(ipstr));
    ret = test_ip_maskstr_cmp(ipr, "0.0.0.0", "255.255.255.255");
    ck_assert_msg(ret == 0, "%s[%d] not equal !!!", ipstr, ret);
    DEBUG_IPRANGE(ipr);
}
END_TEST

/** 测试ip段数组匹配功能 */
START_TEST(test_ip_rangearr_match)
{
    int i;
    ip_range_st *ipr1 = NULL;
    ip_range_st *ipr2 = NULL;
    ip_range_st *ipr3 = NULL;
    ip_range_st *ipr4 = NULL;
    ip_range_st *ipr5 = NULL;
    ip_range_st *ipr6 = NULL;
    ip_st *ipst = NULL;

    ipr1 = ip_string_parser(STR_L("0.0.0.0/0"));
    ipr2 = ip_string_parser(STR_L("0.0.0.0/255.255.254.0"));
    ipr3 = ip_string_parser(STR_L("192.168.1.100/17"));
    ipr4 = ip_string_parser(STR_L("255.255.255.255/255.255.255.255"));
    ipr5 = ip_string_parser(STR_L("::ffff:192.168.255.100/115"));
    ipr6 = ip_string_parser(STR_L("::ffff:192.168.255.100/114"));

    ip_ranges_st iprsx = {0};
    ip_ranges_st *piprs = &iprsx;
    ipranges_add(piprs, &ipr1);
    ipranges_add(piprs, &ipr2);
    ipranges_add(piprs, &ipr3);
    ipranges_add(piprs, &ipr4);
    ipranges_add(piprs, &ipr5);
    ipranges_add(piprs, &ipr6);
    
    ipst = single_parser(STR_L("255.255.255.230"));
    i = ip_rangearr_match(piprs->iprarr, piprs->cur, ipst);
    free(ipst);

    ck_assert_msg(i == 0, "match idx %d invalid !!!", i);
    DEBUG_IPRANGE(piprs->iprarr[i]);
    write_log(LOG_DEBUG, "sort result:");
    for (i = 0; i < piprs->cur; ++i) {
        DEBUG_IPRANGE(piprs->iprarr[i]);
    }
    ipranges_destroy(piprs);


    ipr3 = ip_string_parser(STR_L("192.168.1.100/24"));
    ipr2 = ip_string_parser(STR_L("192.168.0.18-192.168.1.254"));
    ipr1 = ip_string_parser(STR_L("1.1.1.1/25"));
    ipr4 = ip_string_parser(STR_L("255.255.255.255/255.255.255.192"));
    ipr5 = ip_string_parser(STR_L("192.168.1.5-192.168.1.20"));
    ipr6 = ip_string_parser(STR_L("::ffff:192.168.255.100/114"));

    ip_ranges_st iprsx1 = {0};
    piprs = &iprsx1;
    ipranges_add(piprs, &ipr1);
    ipranges_add(piprs, &ipr2);
    ipranges_add(piprs, &ipr3);
    ipranges_add(piprs, &ipr4);
    ipranges_add(piprs, &ipr5);
    ipranges_add(piprs, &ipr6);
    
    ipst = single_parser(STR_L("255.255.255.230"));
    i = ip_rangearr_match(piprs->iprarr, piprs->cur, ipst);
    free(ipst);
    ck_assert_msg(i == 3, "match idx %d invalid !!!", i);

    write_log(LOG_DEBUG, "sort result:");
    for (i = 0; i < piprs->cur; ++i) {
        DEBUG_IPRANGE(piprs->iprarr[i]);
    }
    ipranges_destroy(piprs);


    ipr3 = ip_string_parser(STR_L("192.168.1.100/24"));
    ipr2 = ip_string_parser(STR_L("192.168.0.18-192.168.1.254"));
    ipr1 = ip_string_parser(STR_L("1.1.1.1/25"));
    ipr4 = ip_string_parser(STR_L("255.255.255.255/255.255.255.192"));
    ipr5 = ip_string_parser(STR_L("192.168.1.5-192.168.1.20"));
    ipr6 = ip_string_parser(STR_L("::ffff:192.168.255.100/114"));

    ip_ranges_st iprsx2 = {0};
    piprs = &iprsx2;
    ipranges_add(piprs, &ipr1);
    ipranges_add(piprs, &ipr2);
    ipranges_add(piprs, &ipr3);
    ipranges_add(piprs, &ipr4);
    ipranges_add(piprs, &ipr5);
    ipranges_add(piprs, &ipr6);
    ipst = single_parser(STR_L("::ffff:192.168.192.1"));
    i = ip_rangearr_match(piprs->iprarr, piprs->cur, ipst);
    free(ipst);
    ck_assert_msg(i == 4, "match idx %d invalid !!!", i);
    
    write_log(LOG_DEBUG, "sort result:");
    for (i = 0; i < piprs->cur; ++i) {
        DEBUG_IPRANGE(piprs->iprarr[i]);
    }
    ipranges_destroy(piprs);


    ipr3 = ip_string_parser(STR_L("192.168.1.100/24"));
    ipr2 = ip_string_parser(STR_L("192.168.0.18-192.168.1.254"));
    ipr1 = ip_string_parser(STR_L("1.1.1.1/25"));
    ipr4 = ip_string_parser(STR_L("255.255.255.255/255.255.255.192"));
    ipr5 = ip_string_parser(STR_L("192.168.1.5-192.168.1.20"));
    ipr6 = ip_string_parser(STR_L("::ffff:192.168.255.100/114"));

    ip_ranges_st iprsx3 = {0};
    piprs = &iprsx3;
    ipranges_add(piprs, &ipr1);
    ipranges_add(piprs, &ipr2);
    ipranges_add(piprs, &ipr3);
    ipranges_add(piprs, &ipr4);
    ipranges_add(piprs, &ipr5);
    ipranges_add(piprs, &ipr6);
    
    ipst = single_parser(STR_L("1.1.1.128"));
    i = ip_rangearr_match(piprs->iprarr, piprs->cur, ipst);
    free(ipst);
    ck_assert_msg(i == -1, "match idx %d invalid !!!", i);
    
    write_log(LOG_DEBUG, "sort result:");
    for (i = 0; i < piprs->cur; ++i) {
        DEBUG_IPRANGE(piprs->iprarr[i]);
    }
    ipranges_destroy(piprs);



    ipr3 = ip_string_parser(STR_L("192.168.1.100/24"));
    ipr2 = ip_string_parser(STR_L("192.168.0.18-192.168.1.254"));
    ipr1 = ip_string_parser(STR_L("1.1.1.1/25"));
    ipr4 = ip_string_parser(STR_L("255.255.255.255/255.255.255.192"));
    ipr5 = ip_string_parser(STR_L("192.168.1.5-192.168.1.20"));
    ipr6 = ip_string_parser(STR_L("::ffff:192.168.255.100/114"));

    ip_ranges_st iprsx4 = {0};
    piprs = &iprsx4;
    ipranges_add(piprs, &ipr1);
    ipranges_add(piprs, &ipr2);
    ipranges_add(piprs, &ipr3);
    ipranges_add(piprs, &ipr4);
    ipranges_add(piprs, &ipr5);
    ipranges_add(piprs, &ipr6);
    
    ipst = single_parser(STR_L("1.1.1.1"));
    i = ip_rangearr_match(piprs->iprarr, piprs->cur, ipst);
    free(ipst);
    ck_assert_msg(i == 0, "match idx %d invalid !!!", i);
    
    write_log(LOG_DEBUG, "sort result:");
    for (i = 0; i < piprs->cur; ++i) {
        DEBUG_IPRANGE(piprs->iprarr[i]);
    }
    ipranges_destroy(piprs);


    ipr3 = ip_string_parser(STR_L("0101::0101"));
    ipr2 = ip_string_parser(STR_L("0202::0202"));
    ipr1 = ip_string_parser(STR_L("1010::1010"));
    ipr4 = ip_string_parser(STR_L("0707::0707"));
    ipr5 = ip_string_parser(STR_L("0808::0808"));
    ipr6 = ip_string_parser(STR_L("0303::0303"));

    ip_ranges_st iprsx5 = {0};
    piprs = &iprsx5;
    ipranges_add(piprs, &ipr1);
    ipranges_add(piprs, &ipr2);
    ipranges_add(piprs, &ipr3);
    ipranges_add(piprs, &ipr4);
    ipranges_add(piprs, &ipr5);
    ipranges_add(piprs, &ipr6);
    
    ipst = single_parser(STR_L("1010::1010"));
    i = ip_rangearr_match(piprs->iprarr, piprs->cur, ipst);
    free(ipst);
    ck_assert_msg(i == 5, "match idx %d invalid !!!", i);
    
    write_log(LOG_DEBUG, "sort result:");
    for (i = 0; i < piprs->cur; ++i) {
        DEBUG_IPRANGE(piprs->iprarr[i]);
    }
    ipranges_destroy(piprs);



    ipr3 = ip_string_parser(STR_L("0101::0101"));
    ipr2 = ip_string_parser(STR_L("0202::0202"));
    ipr1 = ip_string_parser(STR_L("1010::1010"));
    ipr4 = ip_string_parser(STR_L("0707::0707"));
    ipr5 = ip_string_parser(STR_L("0808::0808"));
    ipr6 = ip_string_parser(STR_L("10.0.8.141/25"));

    ip_ranges_st iprsx6 = {0};
    piprs = &iprsx6;
    ipranges_add(piprs, &ipr1);
    ipranges_add(piprs, &ipr2);
    ipranges_add(piprs, &ipr3);
    ipranges_add(piprs, &ipr4);
    ipranges_add(piprs, &ipr5);
    ipranges_add(piprs, &ipr6);
    
    ipst = single_parser(STR_L("10.0.8.141"));
    i = ip_rangearr_match(piprs->iprarr, piprs->cur, ipst);
    free(ipst);
    ck_assert_msg(i == 0, "match idx %d invalid !!!", i);
    
    write_log(LOG_DEBUG, "sort result:");
    for (i = 0; i < piprs->cur; ++i) {
        DEBUG_IPRANGE(piprs->iprarr[i]);
    }
    ipranges_destroy(piprs);
}
END_TEST

/** 测试黑白名单加载接口 */
START_TEST(test_ipranges_load)
{
    int ret = 0;
    ip_ranges_st iprs = {0};
    ip_ranges_st *piprs = &iprs;
    char *iprstr = NULL;
    
    
    iprstr =    "1.1.1.1\n" \
                "   2.2.2.2-3.3.3.3    \n" \
                "  4.4.4.4  -  5.5.5.5\n" \
                "6.6.6.6/24 \n" \
                " 7.7.7.7/ 24\n" \
                " 2.2.2.2-   3.3.3.3\n ";
    ret = ipranges_load(piprs, STR_L(iprstr));
    ck_assert_msg(ret == 0, "ret != 0");
    ck_assert_msg(piprs->cur == 5, "ret != 5");
    ret = ipranges_string_match(piprs, "7.7.7.7");
    ck_assert_msg(ret == 4, "ret != 4");
    ret = ipranges_string_match(piprs, "1.1.1.1");
    ck_assert_msg(ret == 0, "ret != 0");
    ipranges_destroy(piprs);


    iprstr =    "1.1.1.1-\n";
    ret = ipranges_load(piprs, STR_L(iprstr));
    ck_assert_msg(ret == -1, "ret != -1");
    ck_assert_msg(piprs->cur == 0, "ret != 0");
    ret = ipranges_string_match(piprs, "7.7.7.7");
    ck_assert_msg(ret == -1, "ret != -1");
    ret = ipranges_string_match(piprs, "1.1.1.1");
    ck_assert_msg(ret == -1, "ret != -1");
    ipranges_destroy(piprs);

    iprstr =    "1.1.1.1-2.2.2.2\n" \
                "   3.3.3.3/24";
    ret = ipranges_load(piprs, STR_L(iprstr));
    ck_assert_msg(ret == 0, "ret != 0");
    ck_assert_msg(piprs->cur == 2, "ret != 2");
    ret = ipranges_string_match(piprs, "3.3.3.10");
    ck_assert_msg(ret == 1, "ret != 1");
    ipranges_destroy(piprs);

    iprstr =    "1.1.1.1      /22";
    ret = ipranges_load(piprs, STR_L(iprstr));
    ck_assert_msg(ret == 0, "ret != 0");
    ck_assert_msg(piprs->cur == 1, "ret != 1");
    ret = ipranges_string_match(piprs, "1.1.1.255");
    ck_assert_msg(ret == 0, "ret != 0");
    ipranges_destroy(piprs);

    iprstr =    "1. 1. 1. 1      /22";
    ret = ipranges_load(piprs, STR_L(iprstr));
    ck_assert_msg(ret == -1, "ret != -1");
    ck_assert_msg(piprs->cur == 0, "ret != 0");
    ret = ipranges_string_match(piprs, "1.1.1.255");
    ck_assert_msg(ret == -1, "ret != -1");
    ipranges_destroy(piprs);

    iprstr =    "# 1.1.1.1\n" \
                "   2.2.2.2-3.3.3.3   #aaa \n" \
                "  4.4.4.4  -  5.5.5.5\n" \
                "6.6.6.6/24 \n" \
                " 7.7.7.7/ 24\n" \
                " 2.2.2.2#-   3.3.3.3\n ";
    ret = ipranges_load(piprs, STR_L(iprstr));
    ck_assert_msg(ret == 0, "ret != 0");
    ck_assert_msg(piprs->cur == 4, "ret != 4");
    ret = ipranges_string_match(piprs, "7.7.7.7");
    ck_assert_msg(ret == 3, "ret != 4");
    ret = ipranges_string_match(piprs, "1.1.1.1");
    ck_assert_msg(ret == -1, "ret != -1");
    ipranges_destroy(piprs);

    iprstr =    "# 1.1.1.1\n" \
                "  #   2.2.2.2-3.3.3.3   #aaa \n" \
                " #4.4.4.4  -  5.5.5.5\n" \
                "#6.6.6.6/24 \n" \
                "   # 7.7.7.7/ 24\n" \
                "# 2.2.2.2#-   3.3.3.3\n ";
    ret = ipranges_load(piprs, STR_L(iprstr));
    ck_assert_msg(ret == 0, "ret != 0");
    ck_assert_msg(piprs->cur == 0, "ret != 0");
    ret = ipranges_string_match(piprs, "7.7.7.7");
    ck_assert_msg(ret == -1, "ret != -1");
    ret = ipranges_string_match(piprs, "1.1.1.1");
    ck_assert_msg(ret == -1, "ret != -1");
    ipranges_destroy(piprs);

    iprstr =    "1.1.11 -#2.1.1.1\n";
    ret = ipranges_load(piprs, STR_L(iprstr));
    ck_assert_msg(ret == -1, "ret != -1");
    ck_assert_msg(piprs->cur == 0, "ret != 0");
    ret = ipranges_string_match(piprs, "7.7.7.7");
    ck_assert_msg(ret == -1, "ret != -1");
    ret = ipranges_string_match(piprs, "1.1.1.1");
    ck_assert_msg(ret == -1, "ret != -1");
    ipranges_destroy(piprs);

    iprstr =    "# 1.1.1.1\n" \
                "  #   2.2.2.2-3.3.3.3   #aaa \n" \
                " #4.4.4.4  -  5.5.5.5\n" \
                "#6.6.6.6/24 \n" \
                "   # 7.7.7.7/ 24\n" \
                "# 2.2.2.2#-   3.3.3.3";
    ret = ipranges_load(piprs, STR_L(iprstr));
    ck_assert_msg(ret == 0, "ret != 0");
    ck_assert_msg(piprs->cur == 0, "ret != 0");
    ret = ipranges_string_match(piprs, "7.7.7.7");
    ck_assert_msg(ret == -1, "ret != -1");
    ret = ipranges_string_match(piprs, "1.1.1.1");
    ck_assert_msg(ret == -1, "ret != -1");
    ipranges_destroy(piprs);

    iprstr =    "1.1.11 -#2.1.1.1";
    ret = ipranges_load(piprs, STR_L(iprstr));
    ck_assert_msg(ret == -1, "ret != -1");
    ck_assert_msg(piprs->cur == 0, "ret != 0");
    ret = ipranges_string_match(piprs, "7.7.7.7");
    ck_assert_msg(ret == -1, "ret != -1");
    ret = ipranges_string_match(piprs, "1.1.1.1");
    ck_assert_msg(ret == -1, "ret != -1");
    ipranges_destroy(piprs);

    iprstr =    "";
    ret = ipranges_load(piprs, STR_L(iprstr));
    ck_assert_msg(ret == 0, "ret != 0");
    ck_assert_msg(piprs->cur == 0, "ret != 0");
    ret = ipranges_string_match(piprs, "7.7.7.7");
    ck_assert_msg(ret == -1, "ret != -1");
    ret = ipranges_string_match(piprs, "1.1.1.1");
    ck_assert_msg(ret == -1, "ret != -1");
    ipranges_destroy(piprs);

    iprstr =    "1.1.1.1-2.2.2.2\n" \
                "3.3.3.3-4.4.4.4\n" \
                "5.5.5.5-6.6.6.6\n" \
                "7.7.7.7-8.8.8.8\n" \
                " 8.8.8.1-9.9.9.9\n" \
                "1.1.1.1-8.8.8.8";
    ret = ipranges_load(piprs, STR_L(iprstr));
    ck_assert_msg(ret == 0, "ret != 0");
    ck_assert_msg(piprs->cur == 2, "ret != 2");
    ret = ipranges_string_match(piprs, "9.9.9.1");
    ck_assert_msg(ret == 1, "ret != 1");
    ret = ipranges_string_match(piprs, "1.1.1.1");
    ck_assert_msg(ret == 0, "ret != 0");
    ret = ipranges_string_match(piprs, "8.8.8.2");
    ck_assert_msg(ret == 0, "ret != 0");
    ipranges_destroy(piprs);



    iprstr =    "2020::8:141 / 112\n" \
                "2020::7:141 / 112";
    ret = ipranges_load(piprs, STR_L(iprstr));
    ck_assert_msg(ret == 0, "ret != 0");
    ck_assert_msg(piprs->cur == 2, "ret != 2");
    ret = ipranges_string_match(piprs, "2020::8:141");
    ck_assert_msg(ret == 1, "ret != 1");
    ret = ipranges_string_match(piprs, "2020::7:1");
    ck_assert_msg(ret == 0, "ret != 0");
    ret = ipranges_string_match(piprs, "8.8.8.2");
    ck_assert_msg(ret == -1, "ret != -1");
    ipranges_destroy(piprs);

    iprstr =    "2020::8:141 / 112\n" \
                "2020::7:141 / 112";
    ret = ipranges_load(piprs, STR_L(iprstr));
    ck_assert_msg(ret == 0, "ret != 0");
    ck_assert_msg(piprs->cur == 2, "ret != 2");
    ret = ipranges_string_match(piprs, "2020::8:141");
    ck_assert_msg(ret == 1, "ret != 1");
    ret = ipranges_string_match(piprs, "2020::7:1");
    ck_assert_msg(ret == 0, "ret != 0");
    ret = ipranges_string_match(piprs, "8.8.8.2");
    ck_assert_msg(ret == -1, "ret != -1");
    ipranges_destroy(piprs);

    iprstr =    "2020::8:141 / 112\n" \
                "2020::7:141 / 104";
    ret = ipranges_load(piprs, STR_L(iprstr));
    ck_assert_msg(ret == 0, "ret != 0");
    ck_assert_msg(piprs->cur == 1, "ret != 1");
    ret = ipranges_string_match(piprs, "2020::8:141");
    ck_assert_msg(ret == 0, "ret != 0");
    ret = ipranges_string_match(piprs, "2020::7:1");
    ck_assert_msg(ret == 0, "ret != 0");
    ret = ipranges_string_match(piprs, "8.8.8.2");
    ck_assert_msg(ret == -1, "ret != -1");
    ipranges_destroy(piprs);

    iprstr =    "2020::8:141 / 112\n" \
                "  2020::6:0 - 2020::9:0  ";
    ret = ipranges_load(piprs, STR_L(iprstr));
    ck_assert_msg(ret == 0, "ret != 0");
    ck_assert_msg(piprs->cur == 1, "ret != 1");
    ret = ipranges_string_match(piprs, "2020::8:141");
    ck_assert_msg(ret == 0, "ret != 0");
    ret = ipranges_string_match(piprs, "2020::7:1");
    ck_assert_msg(ret == 0, "ret != 0");
    ret = ipranges_string_match(piprs, "8.8.8.2");
    ck_assert_msg(ret == -1, "ret != -1");
    ipranges_destroy(piprs);
}
END_TEST

/* 测试iprange_cmp2 */
START_TEST(test_iprange_cmp2)
{
    ip_range_st *ipr1 = NULL;
    ip_range_st *ipr2 = NULL;
    char *ipstr1 = NULL;
    char *ipstr2 = NULL;
    int ret = 0;

    ipstr1 = "1.1.1.1-2.2.2.2";
    ipstr2 = "1.1.1.1-2.2.2.2";
    ipr1 = ip_string_parser(STR_L(ipstr1));
    ipr2 = ip_string_parser(STR_L(ipstr2));
    ret = iprange_cmp2(ipr1, ipr2);
    ck_assert_msg(ret == IPRCMP_1INCLUDE2, "ret = %d", ret);
    free(ipr1);
    free(ipr2);

    ipstr1 = "1.1.1.2-2.2.2.2";
    ipstr2 = "1.1.1.1-2.2.2.2";
    ipr1 = ip_string_parser(STR_L(ipstr1));
    ipr2 = ip_string_parser(STR_L(ipstr2));
    ret = iprange_cmp2(ipr1, ipr2);
    ck_assert_msg(ret == IPRCMP_2INCLUDE1, "ret = %d", ret);
    free(ipr1);
    free(ipr2);

    ipstr1 = "1.1.1.0-2.2.2.2";
    ipstr2 = "1.1.1.1-2.2.2.2";
    ipr1 = ip_string_parser(STR_L(ipstr1));
    ipr2 = ip_string_parser(STR_L(ipstr2));
    ret = iprange_cmp2(ipr1, ipr2);
    ck_assert_msg(ret == IPRCMP_1INCLUDE2, "ret = %d", ret);
    free(ipr1);
    free(ipr2);

    ipstr1 = "1.1.1.1-2.2.2.3";
    ipstr2 = "1.1.1.1-2.2.2.2";
    ipr1 = ip_string_parser(STR_L(ipstr1));
    ipr2 = ip_string_parser(STR_L(ipstr2));
    ret = iprange_cmp2(ipr1, ipr2);
    ck_assert_msg(ret == IPRCMP_1INCLUDE2, "ret = %d", ret);
    free(ipr1);
    free(ipr2);

    ipstr1 = "1.1.1.2-2.2.2.3";
    ipstr2 = "1.1.1.1-2.2.2.2";
    ipr1 = ip_string_parser(STR_L(ipstr1));
    ipr2 = ip_string_parser(STR_L(ipstr2));
    ret = iprange_cmp2(ipr1, ipr2);
    ck_assert_msg(ret == IPRCMP_MORE, "ret = %d", ret);
    free(ipr1);
    free(ipr2);

    ipstr1 = "1.1.1.0-2.2.2.3";
    ipstr2 = "1.1.1.1-2.2.2.2";
    ipr1 = ip_string_parser(STR_L(ipstr1));
    ipr2 = ip_string_parser(STR_L(ipstr2));
    ret = iprange_cmp2(ipr1, ipr2);
    ck_assert_msg(ret == IPRCMP_1INCLUDE2, "ret = %d", ret);
    free(ipr1);
    free(ipr2);

    ipstr1 = "1.1.1.1-2.2.2.1";
    ipstr2 = "1.1.1.1-2.2.2.2";
    ipr1 = ip_string_parser(STR_L(ipstr1));
    ipr2 = ip_string_parser(STR_L(ipstr2));
    ret = iprange_cmp2(ipr1, ipr2);
    ck_assert_msg(ret == IPRCMP_2INCLUDE1, "ret = %d", ret);
    free(ipr1);
    free(ipr2);

    ipstr1 = "1.1.1.2-2.2.2.1";
    ipstr2 = "1.1.1.1-2.2.2.2";
    ipr1 = ip_string_parser(STR_L(ipstr1));
    ipr2 = ip_string_parser(STR_L(ipstr2));
    ret = iprange_cmp2(ipr1, ipr2);
    ck_assert_msg(ret == IPRCMP_2INCLUDE1, "ret = %d", ret);
    free(ipr1);
    free(ipr2);

    ipstr1 = "1.1.1.0-2.2.2.1";
    ipstr2 = "1.1.1.1-2.2.2.2";
    ipr1 = ip_string_parser(STR_L(ipstr1));
    ipr2 = ip_string_parser(STR_L(ipstr2));
    ret = iprange_cmp2(ipr1, ipr2);
    ck_assert_msg(ret == IPRCMP_LESS, "ret = %d", ret);
    free(ipr1);
    free(ipr2);
}
END_TEST

Suite *make_suite(void)
{
    Suite *s = suite_create("lutd");
    TCase *tc = tcase_create("ipstruct_c_test");

    tcase_add_test(tc, test_single_parser);
    tcase_add_test(tc, test_mask_parser);
    tcase_add_test(tc, test_ip_maskstr_parser);
    tcase_add_test(tc, test_ipst_cmp);
    tcase_add_test(tc, test_ip_segstr_parser);
    tcase_add_test(tc, test_ip_string_parser);
    tcase_add_test(tc, test_ip_rangearr_match);
    tcase_add_test(tc, test_ipranges_load);
    tcase_add_test(tc, test_iprange_cmp2);
    
    suite_add_tcase(s, tc);
    return s;
}

int main()
{
    int nf;
    Suite *s = make_suite();
    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);

    srunner_run_all(sr, CK_VERBOSE);
    nf = srunner_ntests_failed(sr);
    
    srunner_free(sr);
    return nf;
}

#endif