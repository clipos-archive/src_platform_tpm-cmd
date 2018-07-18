// SPDX-License-Identifier: GPL-2.0
// Copyright © 2017-2018 ANSSI. All Rights Reserved.
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <stdarg.h>

#include <sys/stat.h>
#include <fcntl.h>

#include <tlcl.h>
#include "../lib/tlcl/oiaposap.h"

typedef enum {
	TPM_CMD_GETRANDOM=1,
	TPM_CMD_SEAL,
	TPM_CMD_UNSEAL,
	TPM_CMD_EXTEND,
} tpm_cmd_t;

int tpm_fd = -1;

int debug(const char *format, ...)
{
	int i;
	va_list args;

	va_start(args, format);
	i = vprintf(format, args);
	va_end(args);

	return i;
}

#define CONFIG_TLCL_DEBUG 1

int tis_senddata(const uint8_t * const sendbuf, size_t send_size)
{
	size_t res;

	res = write(tpm_fd, sendbuf, send_size);

	if (res == send_size)
		return TPM_SUCCESS;

	return TPM_E_COMMUNICATION_ERROR;
}

int tis_readresponse(uint8_t *recvbuf, size_t *recv_len)
{
	*recv_len = read(tpm_fd, recvbuf, 1024);

	if (*recv_len > 0)
		return TPM_SUCCESS;

	return TPM_E_COMMUNICATION_ERROR;
}

int tis_sendrecv(const uint8_t *sendbuf, size_t send_size,
		 uint8_t *recvbuf, size_t *recv_len)
{
	if (tis_senddata(sendbuf, send_size)) {
		fprintf(stderr, "%s:%d failed sending data to TPM\n",
		       __FILE__, __LINE__);
		return TPM_E_COMMUNICATION_ERROR;
	}

	return tis_readresponse(recvbuf, recv_len);
}

int tis_open(void)
{
	if (tpm_fd >= 0)
		return 0;

	debug("TPM: opening device /dev/tpm0\n");
	tpm_fd = open("/dev/tpm0", O_RDWR);
	if (tpm_fd < 0) {
		perror ("Error opening tpm device\n");
		exit(-1);
	}

	return 0;
}

int tis_init(void)
{
	return 0;
}

int tis_close(void)
{
	if (tpm_fd >= 0) {
		close(tpm_fd);
		tpm_fd = -1;
	}
	return 0;
}


uint8_t sboot_seal(const uint32_t pcrMap,
	const uint8_t *pcrInfo, uint32_t pcrInfoSize,
	const uint8_t *data, uint32_t dataSize,
	uint8_t *blob, uint32_t *blobSize)
{
	uint32_t result;

	uint8_t keyAuth[20];
	uint8_t dataAuth[20];

	/* Use WK-password for SRK and data */
	memset(keyAuth, 0, 20);
	memset(dataAuth, 0, 20);
	result = TlclSeal(0x40000000, pcrInfo,
	  pcrInfoSize, keyAuth, dataAuth,
	  data, dataSize, blob, blobSize);
	if (result != TPM_SUCCESS) {
		debug("sboot: Failed to seal data.\n");
		return -1;
	}

	return 0;
}

uint8_t sboot_unseal(const uint8_t *sealData, uint32_t sealDataSize,
	uint8_t *unsealData, uint32_t *unsealDataSize)
{
	uint32_t result;

	uint8_t keyAuth[20];
	uint8_t dataAuth[20];

	/* Use WK-password for SRK and data */
	memset(keyAuth, 0, 20);
	memset(dataAuth, 0, 20);
	result = TlclUnseal(0x40000000, keyAuth, dataAuth,
		sealData, sealDataSize, unsealData, unsealDataSize);
	if (result != TPM_SUCCESS) {
		debug("sboot: Failed to unseal data.\n");
		return -1;
	}

	return 0;
}


uint8_t GetRandom(void)
{
	struct tss_osapsess sess;
	uint32_t nonceSize;

	TlclGetRandom(sess.ononceOSAP, TPM_NONCE_SIZE, &nonceSize);

	return 0;
}

static void hex2buf(const char *in, size_t in_len, uint8_t *out, size_t out_len)
{
	unsigned int i;
	short tmpShort;

	if (out_len < (in_len/2)) {
		fprintf(stderr, "hex2buf: output buffer is too small!\n");
		return;
	}

	for (i = 0; i < (in_len / 2); i++) {
		sscanf(in + 2*i, "%2hx", &tmpShort);
		out[i] = tmpShort;
		//printf("out %d: %02x\n", i, tmpShort);
	}
}

static void usage(const char *progname)
{
	fprintf(stderr, "Usage: %s COMMAND [args]\n", progname);
	fprintf(stderr, "commands:\n");
	fprintf(stderr, "        random                      get random bytes from TPM\n");
	fprintf(stderr, "        seal <infile> <outfile>     seal input file (which PCRs ? ? ?)\n");
	fprintf(stderr, "        unseal <infile> <outfile>   unseal input file\n");
	fprintf(stderr, "        extend <pcr> <hash>         extend PCR with hash value (hash is hex-encoded)\n");
}


int main(int argc, char *argv[])
{
	int ret;
	tpm_cmd_t cmd=0;

	if (argc < 2) {
		usage(argv[0]);
		exit (-1);
	}

	if (strcmp(argv[1], "random")==0) {
		cmd = TPM_CMD_GETRANDOM;
	}
	if (strcmp(argv[1], "seal")==0) {
		cmd = TPM_CMD_SEAL;
	}
	if (strcmp(argv[1], "unseal")==0) {
		cmd = TPM_CMD_UNSEAL;
	}
	if (strcmp(argv[1], "extend")==0) {
		cmd = TPM_CMD_EXTEND;
	}

	if (cmd == 0) {
		fprintf(stderr, "Unknown command %s\n", argv[1]);
		usage(argv[0]);
		exit(-1);
	}

	TlclLibInit();
	TlclStartup();

	switch (cmd) {
	case TPM_CMD_GETRANDOM:
		GetRandom();
		break;
	case TPM_CMD_SEAL: {
		if (argc < 4) {
			fprintf(stderr, "error: not enough args for command\n");
			usage(argv[0]);
			exit (-1);
		}
		int fd = open(argv[2], O_RDONLY);
		if (fd < 0) {
			perror("could not open input file\n");
			exit (-1);
		}
		uint8_t pcrInfo[256];
		uint8_t *data;
		struct stat s;
		size_t sz;
		fstat(fd, &s);
		data = malloc(s.st_size);
		sz = read(fd, data, s.st_size);
		if ((off_t)sz != s.st_size) {
			perror("could not read input file\n");
			exit (-1);
		}

		uint8_t *out_data;
		uint32_t out_sz;
		out_data = malloc(4*sz);
		ret = sboot_seal(0x0, pcrInfo, 0, data, sz, out_data, &out_sz);
		if (ret != 0) {
			fprintf(stderr, "ERROR\n");
			exit (-1);
		}

		fd = open(argv[3], O_CREAT | O_TRUNC | O_WRONLY, 0666);
		if (fd < 0) {
			perror("could not open output file\n");
			exit (-1);
		}
		sz = write(fd, out_data, out_sz);
		if (sz != out_sz) {
			perror("could not read output file\n");
			exit (-1);
		}
		close(fd);

		break;
	}
	case TPM_CMD_UNSEAL: {
		if (argc < 4) {
			fprintf(stderr, "error: not enough args for command\n");
			usage(argv[0]);
			exit (-1);
		}
		int fd = open(argv[2], O_RDONLY);
		if (fd < 0) {
			perror("could not open input file\n");
			exit (-1);
		}
		uint8_t *data;
		struct stat s;
		size_t sz;
		fstat(fd, &s);
		data = malloc(s.st_size);
		sz = read(fd, data, s.st_size);
		if ((off_t)sz != s.st_size) {
			perror("could not read input file\n");
			exit (-1);
		}
		close(fd);

		uint8_t *out_data;
		uint32_t out_sz;
		out_data = malloc(4*sz);
		ret = sboot_unseal(data, sz, out_data, &out_sz);
		if (ret != 0) {
			fprintf(stderr, "ERROR\n");
			exit (-1);
		}

		fd = open(argv[3], O_CREAT | O_TRUNC | O_WRONLY, 0666);
		if (fd < 0) {
			perror("could not open output file\n");
			exit (-1);
		}
		sz = write(fd, out_data, out_sz);
		if (sz != out_sz) {
			perror("could not read output file\n");
			exit (-1);
		}
		close(fd);

		break;
	}
	case TPM_CMD_EXTEND: {
		// ex: tpm_cmd extend 8 $(sha1sum /dev/null | cut -f1 -d' ')
		if (argc < 4) {
			fprintf(stderr, "error: not enough args for command\n");
			usage(argv[0]);
			exit (-1);
		}

		if (strlen(argv[3]) != (2*kPcrDigestLength)) {
			fprintf(stderr, "error: hash must be hex-encoded and must be %d bytes long\n", 2*kPcrDigestLength);
			usage(argv[0]);
			exit (-1);
		}

		int pcrnum = -1;
		uint8_t in_digest[kPcrDigestLength];
		uint8_t out_digest[kPcrDigestLength];

		pcrnum = atoi(argv[2]);

		if (pcrnum < 0 || pcrnum > 24) {
			fprintf(stderr, "Invalid PCR number (must be in range [0:24])\n");
			exit (-1);
		}

		memset(in_digest, 0, kPcrDigestLength);
		hex2buf(argv[3], strlen(argv[3]), in_digest, kPcrDigestLength);

		ret = TlclExtend(pcrnum, in_digest, out_digest);

		break;
	}
	default:
		fprintf(stderr, "Unknown (or not yet implemented) command\n");
		usage(argv[0]);
		exit(-1);
	}

	tis_close();
	return 0;
}
