#include <stdint.h>
#include <stdio.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/time.h>

#include <rte_mbuf.h>

static long total_write;
static int pcap_fd;
static int pcap_id;

#define PCAP_SNAPLEN_DEFAULT 65535
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX_FILE_SIZE 1024 * 1024

struct __attribute__((__packed__)) pcap_header {
    uint32_t magic_number;  /* magic number */
    uint16_t version_major; /* major version number */
    uint16_t version_minor; /* minor version number */
    int32_t  thiszone;      /* GMT to local correction */
    uint32_t sigfigs;       /* accuracy of timestamps */
    uint32_t snaplen;       /* max length of captured packets, in octets */
    uint32_t network;       /* data link type */
};

struct pcap_packet_header {
    uint32_t timestamp;
    uint32_t microseconds;
    uint32_t packet_length;
    uint32_t packet_length_wire;
};

static void pcap_header_init(struct pcap_header *header, unsigned int snaplen)
{
    header->magic_number = 0xa1b2c3d4;
    header->version_major = 0x0002;
    header->version_minor = 0x0004;
    header->thiszone = 0;
    header->sigfigs = 0;
    header->snaplen = snaplen;
    header->network = 0x00000001;
}

void dump_pcap_init(void)
{
    char buffer[BUFSIZ] = {0};
    struct pcap_header header;

    if (pcap_fd != 0) {
	close(pcap_id);
    }

    sprintf(buffer, "./filter_dump%02d.pcap", pcap_id++);
    pcap_fd = open(buffer, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    //if (!pcap_fd) {
        //return -1;
    //}

    //Init the common pcap header
    pcap_header_init(&header, PCAP_SNAPLEN_DEFAULT);
    write(pcap_fd, &header, sizeof(struct pcap_header));
}

int dump_pcap_write(struct rte_mbuf *bufptr)
{
    int ret;
    struct timeval tv;
    int snap_len, pkt_len;
    struct pcap_packet_header header;

    if (total_write >= MAX_FILE_SIZE) {
        dump_pcap_init();
	total_write = 0;
    }

    gettimeofday(&tv, NULL);
    pkt_len = rte_pktmbuf_pkt_len(bufptr);
    snap_len = MIN(PCAP_SNAPLEN_DEFAULT, pkt_len);

    header.timestamp = (int32_t)tv.tv_sec;
    header.microseconds = (int32_t)tv.tv_usec;
    header.packet_length = snap_len;
    header.packet_length_wire = pkt_len;

    ret = write(pcap_fd, &header, sizeof(struct pcap_packet_header));
    if (ret < 0) {
        return -1;
    }

    int bytes_to_write;
    int remaining_bytes;

    remaining_bytes = snap_len;
    total_write += remaining_bytes;
    while (bufptr != NULL && remaining_bytes > 0) {
        bytes_to_write = MIN(rte_pktmbuf_data_len(bufptr), remaining_bytes);
        ret = write(pcap_fd, rte_pktmbuf_mtod(bufptr, void*), bytes_to_write);
        if (ret < 0) {
            return -1;
        }
        remaining_bytes -= bytes_to_write;
    }
}
