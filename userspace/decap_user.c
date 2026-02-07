/* Copyright (C) 2019-present, Facebook, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * Minimal libbpf-based loader/stats tool for the XDP decap program.
 * Replaces XdpDecap.cpp + folly + BpfAdapter + glog.
 *
 * Usage:
 *   decap_user load   -i <ifname> -o <bpf_obj> [-p <pin_path>] [-s <server_id>]
 *   decap_user unload -i <ifname>
 *   decap_user stats  [-p <pin_path>]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <getopt.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define DEFAULT_PIN_PATH "/sys/fs/bpf/decap"

struct decap_stats {
	__u64 decap_v4;
	__u64 decap_v6;
	__u64 total;
	__u64 tpr_misrouted;
	__u64 tpr_total;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s load   -i <ifname> -o <bpf_obj> [-p <pin_path>] [-s <server_id>]\n"
		"  %s unload -i <ifname>\n"
		"  %s stats  [-p <pin_path>]\n",
		prog, prog, prog);
}

static int ensure_pin_dir(const char *pin_path)
{
	struct stat st;

	if (stat(pin_path, &st) == 0) {
		if (S_ISDIR(st.st_mode))
			return 0;
		fprintf(stderr, "Error: %s exists but is not a directory\n",
			pin_path);
		return -1;
	}
	if (mkdir(pin_path, 0700) && errno != EEXIST) {
		fprintf(stderr, "Error: mkdir(%s): %s\n", pin_path,
			strerror(errno));
		return -1;
	}
	return 0;
}

static int cmd_load(int argc, char **argv)
{
	const char *ifname = NULL;
	const char *obj_path = NULL;
	const char *pin_path = DEFAULT_PIN_PATH;
	int server_id = -1;
	int opt;

	while ((opt = getopt(argc, argv, "i:o:p:s:")) != -1) {
		switch (opt) {
		case 'i':
			ifname = optarg;
			break;
		case 'o':
			obj_path = optarg;
			break;
		case 'p':
			pin_path = optarg;
			break;
		case 's':
			server_id = atoi(optarg);
			break;
		default:
			return -1;
		}
	}

	if (!ifname || !obj_path) {
		fprintf(stderr, "Error: -i <ifname> and -o <bpf_obj> required\n");
		return -1;
	}

	unsigned int ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		fprintf(stderr, "Error: interface '%s' not found\n", ifname);
		return -1;
	}

	/* Open and load BPF object */
	struct bpf_object *obj = bpf_object__open(obj_path);
	if (!obj) {
		fprintf(stderr, "Error: failed to open %s: %s\n", obj_path,
			strerror(errno));
		return -1;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "Error: failed to load BPF object: %s\n",
			strerror(errno));
		bpf_object__close(obj);
		return -1;
	}

	/* Find the XDP program */
	struct bpf_program *prog = bpf_object__find_program_by_name(obj,
								    "xdpdecap");
	if (!prog) {
		fprintf(stderr, "Error: program 'xdpdecap' not found in %s\n",
			obj_path);
		bpf_object__close(obj);
		return -1;
	}

	int prog_fd = bpf_program__fd(prog);

	/* Pin maps */
	if (ensure_pin_dir(pin_path))  {
		bpf_object__close(obj);
		return -1;
	}

	if (bpf_object__pin_maps(obj, pin_path)) {
		fprintf(stderr, "Error: failed to pin maps to %s: %s\n",
			pin_path, strerror(errno));
		bpf_object__close(obj);
		return -1;
	}
	printf("Maps pinned to %s\n", pin_path);

	/* Set server_id if provided */
	if (server_id >= 0) {
		struct bpf_map *map = bpf_object__find_map_by_name(obj,
								   "tpr_server_id");
		if (map) {
			int map_fd = bpf_map__fd(map);
			__u32 key = 0;
			__u32 val = (__u32)server_id;

			if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY)) {
				fprintf(stderr,
					"Warning: failed to set server_id: %s\n",
					strerror(errno));
			} else {
				printf("Server ID set to %d\n", server_id);
			}
		}
	}

	/* Attach XDP program */
	if (bpf_xdp_attach(ifindex, prog_fd, 0, NULL)) {
		fprintf(stderr, "Error: failed to attach XDP to %s: %s\n",
			ifname, strerror(errno));
		bpf_object__close(obj);
		return -1;
	}

	printf("XDP program attached to %s (ifindex %u)\n", ifname, ifindex);
	bpf_object__close(obj);
	return 0;
}

static int cmd_unload(int argc, char **argv)
{
	const char *ifname = NULL;
	int opt;

	while ((opt = getopt(argc, argv, "i:")) != -1) {
		switch (opt) {
		case 'i':
			ifname = optarg;
			break;
		default:
			return -1;
		}
	}

	if (!ifname) {
		fprintf(stderr, "Error: -i <ifname> required\n");
		return -1;
	}

	unsigned int ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		fprintf(stderr, "Error: interface '%s' not found\n", ifname);
		return -1;
	}

	if (bpf_xdp_detach(ifindex, 0, NULL)) {
		fprintf(stderr, "Error: failed to detach XDP from %s: %s\n",
			ifname, strerror(errno));
		return -1;
	}

	printf("XDP program detached from %s\n", ifname);
	return 0;
}

static int cmd_stats(int argc, char **argv)
{
	const char *pin_path = DEFAULT_PIN_PATH;
	int opt;

	while ((opt = getopt(argc, argv, "p:")) != -1) {
		switch (opt) {
		case 'p':
			pin_path = optarg;
			break;
		default:
			return -1;
		}
	}

	/* Build path to pinned map */
	char map_path[512];
	snprintf(map_path, sizeof(map_path), "%s/decap_counters", pin_path);

	int map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "Error: failed to open pinned map %s: %s\n",
			map_path, strerror(errno));
		return -1;
	}

	int num_cpus = libbpf_num_possible_cpus();
	if (num_cpus < 0) {
		fprintf(stderr, "Error: failed to get CPU count: %s\n",
			strerror(-num_cpus));
		close(map_fd);
		return -1;
	}

	struct decap_stats values[num_cpus];
	__u32 key = 0;

	if (bpf_map_lookup_elem(map_fd, &key, values)) {
		fprintf(stderr, "Error: failed to read map: %s\n",
			strerror(errno));
		close(map_fd);
		return -1;
	}

	/* Aggregate per-CPU values */
	struct decap_stats total = {};
	for (int i = 0; i < num_cpus; i++) {
		total.decap_v4 += values[i].decap_v4;
		total.decap_v6 += values[i].decap_v6;
		total.total += values[i].total;
		total.tpr_misrouted += values[i].tpr_misrouted;
		total.tpr_total += values[i].tpr_total;
	}

	printf("Decap Statistics (aggregated across %d CPUs):\n", num_cpus);
	printf("  decap_v4:       %llu\n", (unsigned long long)total.decap_v4);
	printf("  decap_v6:       %llu\n", (unsigned long long)total.decap_v6);
	printf("  total:          %llu\n", (unsigned long long)total.total);
	printf("  tpr_misrouted:  %llu\n",
	       (unsigned long long)total.tpr_misrouted);
	printf("  tpr_total:      %llu\n", (unsigned long long)total.tpr_total);

	close(map_fd);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	/* Reset getopt for subcommand parsing */
	const char *cmd = argv[1];
	argc--;
	argv++;
	optind = 1;

	int ret;
	if (strcmp(cmd, "load") == 0) {
		ret = cmd_load(argc, argv);
	} else if (strcmp(cmd, "unload") == 0) {
		ret = cmd_unload(argc, argv);
	} else if (strcmp(cmd, "stats") == 0) {
		ret = cmd_stats(argc, argv);
	} else {
		fprintf(stderr, "Unknown command: %s\n", cmd);
		usage(argv[0]);
		ret = 1;
	}

	if (ret < 0) {
		usage(argv[-1]);
		return 1;
	}
	return ret;
}
