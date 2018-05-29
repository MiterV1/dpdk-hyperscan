### 1.如何实现端口过滤
### 2.如何实现协议过滤
dpdk收包  
    `nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst, MAX_PKT_BURST);`
解析包的五元组
    `l2fwd_parse_ipv4_5tuple(m, &tuple);`
判断五元组中port与协议与给定值是否相同
```
if (tuple.port_src == get_ui_port_filter_src_port() || tuple.port_dst == get_ui_port_filter_dst_port()) {
    dump_pcap_write(dump_fd, m);
    continue;
}

if (tuple.proto == proto) {
    dump_pcap_write(dump_fd, m);
    continue;
}
```
相同则将包数据写到pcap文件中

3.如何实现应用过滤
    先计算五元组的hash值，先在hash表中查看是否包含该hash项
    如果有该hash项则说明为某条应用流，直接dump到pcap文件
```
m_data.hash = rte_hash_hash(m_data.handle, &tuple);
m_data.tuple = &tuple;

int ret = rte_hash_lookup_with_hash(m_data.handle, &tuple, m_data.hash);
if (ret > 0) {
    dump_pcap_write(dump_fd, m);

    如果在hash表中未找到该hash项，那么说明需要对该数据包进行匹配，使用hyperscan提取其中的特征信息
    if (hs_scan_stream(g_streams[m_data.hash % 4096], rte_pktmbuf_mtod(m, char *),
            rte_pktmbuf_data_len(m), 0, g_scratch, eventHandler, &m_data) != HS_SUCCESS) {
        fprintf(stderr, "hs_scan_stream error.\n");
    }
    
    调用scan_stream函数对数据包匹配之前编译的规则信息，如果匹配成功则调用eventHandler函数
    该函数将添加该流信息到流表中，用于后续的流表匹配
static int eventHandler(unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags, void *ctx)
{
    printf("Match for pattern \"%d\" at offset %llu\n", id, to);

    struct matched_data *mdata = (struct matched_data *)ctx;
    rte_hash_add_key_with_hash(mdata->handle, mdata->tuple, mdata->hash);

    return 0;
}
```
