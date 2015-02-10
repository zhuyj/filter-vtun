/*read the patckets from /dev/net/vtun, then store these packets
 * in a local file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

int debug;
char *progname;

static uint32_t m_secs = 0;
static uint32_t m_usecs = 0;
// pcap header
typedef struct pcap_hdr_s {
	uint32_t magic_number;	/* magic number */
	uint16_t version_major;	/* major version number */
	uint16_t version_minor;	/* minor version number */
	int32_t thiszone;	/* GMT to local correction */
	uint32_t sigfigs;	/* accuracy of timestamps */
	uint32_t snaplen;	/* max length of captured packets, in octets */
	uint32_t network;	/* data link type */
} pcap_hdr_t;
//packet header
typedef struct pcaprec_hdr_s {
	uint32_t ts_sec;	/* timestamp seconds */
	uint32_t ts_usec;	/* timestamp microseconds */
	uint32_t incl_len;	/* number of octets of packet saved in file */
	uint32_t orig_len;	/* actual length of packet */
} pcaprec_hdr_t;

void open_pcap()
{
	FILE *fp = NULL;
	// Create pcap file.
	fp = fopen("/tmp/temp.pcap", "w+");
	if (fp) {
		// pcap header;
		struct pcap_hdr_s pcap_h;
		pcap_h.magic_number = 0xa1b2c3d4;
		pcap_h.version_major = 2;
		pcap_h.version_minor = 4;
		pcap_h.thiszone = 0;
		pcap_h.sigfigs = 0;
		pcap_h.snaplen = 65535;
		pcap_h.network = 1;
		fwrite(&pcap_h, 1, sizeof(pcap_h), fp);
	}
	fflush(fp);
	fclose(fp);
}

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags)
{

	struct ifreq ifr;
	int fd, err;

	if ((fd = open("/dev/net/vtun", O_RDWR)) < 0) {
		perror("Opening /dev/net/vtun");
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;

	if (*dev) {
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
		perror("ioctl(TUNSETIFF)");
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);

	return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n)
{

	int nread;

	if ((nread = read(fd, buf, n)) < 0) {
		perror("Reading data");
		exit(1);
	}
	return nread;
}

#if 0
/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n)
{

	int nwrite;

	if ((nwrite = write(fd, buf, n)) < 0) {
		perror("Writing data");
		exit(1);
	}
	return nwrite;
}
#endif
/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n)
{

	int nread, left = n;

	while (left > 0) {
		if ((nread = cread(fd, buf, left)) == 0) {
			return 0;
		} else {
			left -= nread;
			buf += nread;
		}
	}
	return n;
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...)
{

	va_list argp;

	if (debug) {
		va_start(argp, msg);
		vfprintf(stderr, msg, argp);
		va_end(argp);
	}
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...)
{

	va_list argp;

	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr,
		"%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n",
		progname);
	fprintf(stderr, "%s -h\n", progname);
	fprintf(stderr, "\n");
	fprintf(stderr,
		"-i <ifacename>: Name of interface to use (mandatory)\n");
	fprintf(stderr, "-d: outputs debug information while running\n");
	fprintf(stderr, "-h: prints this help text\n");
	exit(1);
}

int main(int argc, char *argv[])
{

	int tap_fd, option;
	int flags = IFF_TUN;
	char if_name[IFNAMSIZ] = "";
	int maxfd;
	uint16_t nread;
	char buffer[BUFSIZE];
	int sock_fd;
	unsigned long int tap2net = 0;

	progname = argv[0];

	/* Check command line options */
	while ((option = getopt(argc, argv, "i:sc:p:uahd")) > 0) {
		switch (option) {
		case 'd':
			debug = 1;
			break;
		case 'h':
			usage();
			break;
		case 'i':
			strncpy(if_name, optarg, IFNAMSIZ - 1);
			break;
		default:
			my_err("Unknown option %c\n", option);
			usage();
		}
	}

	argv += optind;
	argc -= optind;

	if (argc > 0) {
		my_err("Too many options!\n");
		usage();
	}

	if (*if_name == '\0') {
		my_err("Must specify interface name!\n");
		usage();
	}

	/* initialize tun/tap interface */
	if ((tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0) {
		my_err("Error connecting to tun/tap interface %s!\n", if_name);
		exit(1);
	}

	do_debug("Successfully connected to interface %s\n", if_name);

	if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket()");
		exit(1);
	}

	/* use select() to handle two descriptors at once */
	maxfd = tap_fd;
	open_pcap();
	while (1) {
		int ret;
		fd_set rd_set;

		FD_ZERO(&rd_set);
		FD_SET(tap_fd, &rd_set);

		ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

		if (ret < 0 && errno == EINTR) {
			continue;
		}

		if (ret < 0) {
			perror("select()");
			exit(1);
		}

		if (FD_ISSET(tap_fd, &rd_set)) {
			/* data from tun/tap: just read it and write it to the network */

			nread = cread(tap_fd, buffer, BUFSIZE);

			tap2net++;
			do_debug
			    ("TAP2NET %lu: Read %d bytes from the tap interface\n",
			     tap2net, nread);

			{
				FILE *fp = NULL;
				if ((fp =
				     fopen("/tmp/temp.pcap", "ab")) == NULL) {
					perror("fopen error");
					exit(1);
				}
				struct pcaprec_hdr_s pac_h;
				pac_h.ts_sec = m_secs++;
				pac_h.ts_usec = ++m_usecs;
				pac_h.incl_len = nread;
				pac_h.orig_len = nread;
				fwrite(&pac_h, 1, sizeof(pac_h), fp);
				// packet
				fwrite(buffer, 1, nread, fp);

				fclose(fp);
			}
		}	
	}

	return (0);
}
