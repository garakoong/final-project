#ifndef __LOADER_HELPERS_H
#define __LOADER_HELPERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/stat.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"
#include "../common/classifier_structs.h"

static const char *root_filename = "xdp_root.o";
static const char *fw_filename = "xdp_modular_firewall.o";
static const char *module_filename = "xdp_firewall_module.o";

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

/* Pinning maps under /sys/fs/bpf in subdir */
int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, struct config *cfg)
{
	char map_filename[PATH_MAX];
	int err, len;
	struct bpf_map *map;

	bpf_object__for_each_map(map, bpf_obj) {

		len = snprintf(map_filename, PATH_MAX, "%s/%s",
				cfg->pin_dir, bpf_map__name(map));
		if (len < 0) {
			fprintf(stderr, "ERR: creating map_name\n");
			return EXIT_FAIL_OPTION;
		}

		/* Existing/previous XDP prog might not have cleaned up */
		if (access(map_filename, F_OK ) != -1 ) {
			if (verbose)
				printf(" - Unpinning map '%s' in %s/\n",
					bpf_map__name(map), cfg->pin_dir);

			/* Basically calls unlink(3) on map_filename */
			err = bpf_map__unpin(map, map_filename);
			if (err) {
				fprintf(stderr, "ERR: UNpinning map '%s' in %s\n", bpf_map__name(map), cfg->pin_dir);
				return EXIT_FAIL_BPF;
			}
		}
		if (verbose)
			printf(" - Pinning map '%s' in %s/\n", bpf_map__name(map), cfg->pin_dir);

		/* This will pin all maps in our bpf_object */
		err = bpf_map__pin(map, map_filename);
		if (err)
			return EXIT_FAIL_BPF;
			
	}

	return 0;
}

int unpin_maps_in_bpf_object(struct bpf_object *bpf_obj, struct config *cfg)
{
	char map_filename[PATH_MAX];
	int err, len;
	struct bpf_map *map;

	bpf_object__for_each_map(map, bpf_obj) {

		len = snprintf(map_filename, PATH_MAX, "%s/%s",
				cfg->pin_dir, bpf_map__name(map));
		if (len < 0) {
			fprintf(stderr, "ERR: creating map_name\n");
			return EXIT_FAIL_OPTION;
		}

		/* Existing/previous XDP prog might not have cleaned up */
		if (access(map_filename, F_OK ) != -1 ) {
			if (verbose)
				printf(" - Unpinning map '%s' in %s/\n",
					bpf_map__name(map), cfg->pin_dir);

			/* Basically calls unlink(3) on map_filename */
			err = bpf_map__unpin(map, map_filename);
			if (err) {
				fprintf(stderr, "ERR: UNpinning map '%s' in %s\n", bpf_map__name(map), cfg->pin_dir);
				return EXIT_FAIL_BPF;
			}
		}
			
	}

	return 0;
}

int fw_loader(int reuse_maps)
{
	struct bpf_object *bpf_obj;
	int err, len;
	struct bpf_program *bpf_prog;
	int offload_ifindex = 0;
	int prog_fd = -1;
	int map_fd;
	char progarr_path[PATH_MAX];

	struct config cfg = {
		.reuse_maps = reuse_maps,
	};

	cfg.xdp_flags &= ~XDP_FLAGS_MODES;
	cfg.xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;

	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, fw_filename, sizeof(cfg.filename));
	
	len = snprintf(cfg.pin_dir, PATH_MAX, "%s/classifier", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname.\n");
		return EXIT_FAIL_OPTION;
	}

	if (cfg.reuse_maps)
		bpf_obj = load_bpf_object_file_reuse_maps(cfg.filename,
							  offload_ifindex,
							  cfg.pin_dir);
	else
		bpf_obj = load_bpf_object_file(cfg.filename, offload_ifindex);

	if (!bpf_obj) {
		fprintf(stderr, "ERR: loading file: %s.\n", cfg.filename);
		return EXIT_FAIL_BPF;
	}

	/* Use the --dev name as subdir for exporting/pinning maps */
	if (!cfg.reuse_maps) {
		err = pin_maps_in_bpf_object(bpf_obj, &cfg);
		if (err) {
			fprintf(stderr, "ERR: pinning maps\n");
			return err;
		}
	}

	if (cfg.progsec[0])
		/* Find a matching BPF prog section name */
		bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg.progsec);
	else
		/* Find the first program */
		bpf_prog = bpf_program__next(NULL, bpf_obj);

	if (!bpf_prog) {
		fprintf(stderr, "ERR: couldn't find a program in ELF section '%s'\n", cfg.progsec);
		return EXIT_FAIL_BPF;
	}

	strncpy(cfg.progsec, bpf_program__title(bpf_prog, false), sizeof(cfg.progsec));

	prog_fd = bpf_program__fd(bpf_prog);
	if (prog_fd <= 0) {
		fprintf(stderr, "ERR: bpf_program__fd failed\n");
		return EXIT_FAIL_BPF;
	}
	
	int index = 0;

	len = snprintf(progarr_path, PATH_MAX, "%s/firewall_program", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating firewall program path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(progarr_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening firewall program map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_update_elem(map_fd, &index, &prog_fd, 0)) {
		fprintf(stderr, "ERR: Installing firewall program.\n");
		return EXIT_FAIL_BPF;
	}


	return EXIT_OK;
}

int root_loader(struct config *cfg)
{
	struct bpf_object *bpf_obj;
	int err, len;
	struct bpf_program *bpf_prog;
	int offload_ifindex = 0;
	int prog_fd = -1;
	__u32 initval = 1;
	struct bpf_map_info info = { 0 };
	int map_fd;
	struct bpf_map_info map_expect = {
		.key_size	= sizeof(__u32),
		.value_size	= sizeof(__u32),
	};

	cfg->xdp_flags &= ~XDP_FLAGS_MODES;
	cfg->xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
	cfg->reuse_maps = 1;

	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg->filename, root_filename, sizeof(cfg->filename));

	map_fd = open_bpf_map_file(pin_basedir, "operating_dev", &info);
	if (map_fd < 0) {
		cfg->reuse_maps = 0;
	} else {
		err = check_map_fd_info(&info, &map_expect);
		if (err) {
			cfg->reuse_maps = 0;
			map_fd = -1;
		}
	}
	
	if (cfg->cmd == UNLOAD_FW) {
		if (cfg->ifindex == -1) {
			fprintf(stderr, "ERR: required option --networkif missing.\n\n");
			return EXIT_FAIL_OPTION;
		}
		err = xdp_link_detach(cfg->ifindex, cfg->xdp_flags, 0);
		if (err) {
			return EXIT_FAIL_BPF;
		} else {
			if (map_fd < 0) {
				fprintf(stderr, "cannot find map 'operating_dev' in %s.\n", pin_basedir);
				return EXIT_FAIL_BPF;
			}
			initval = 0;
			if (bpf_map_delete_elem(map_fd, &cfg->ifindex)) {
				fprintf(stderr, "ERR: updating 'operating_dev' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		return EXIT_OK;
	}

	len = snprintf(cfg->pin_dir, PATH_MAX, "%s", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname.\n");
		return EXIT_FAIL_OPTION;
	}

	if (cfg->xdp_flags & XDP_FLAGS_HW_MODE) {
		if (cfg->ifindex == -1) {
			fprintf(stderr, "ERR: required option --networkif missing.\n\n");
			return EXIT_FAIL_OPTION;
		}
		offload_ifindex = cfg->ifindex;
	}

	if (cfg->reuse_maps)
		bpf_obj = load_bpf_object_file_reuse_maps(cfg->filename,
							  offload_ifindex,
							  cfg->pin_dir);
	else
		bpf_obj = load_bpf_object_file(cfg->filename, offload_ifindex);

	if (!bpf_obj) {
		fprintf(stderr, "ERR: loading file: %s.\n", cfg->filename);
		return EXIT_FAIL_BPF;
	}

	if (verbose)
		printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
		       cfg->filename, cfg->progsec);

	/* Use the --dev name as subdir for exporting/pinning maps */
	if (!cfg->reuse_maps) {
		err = pin_maps_in_bpf_object(bpf_obj, cfg);
		if (err) {
			fprintf(stderr, "ERR: pinning maps\n");
			return err;
		}

		map_fd = open_bpf_map_file(cfg->pin_dir, "operating_dev", &info);
		if (map_fd < 0) {
			fprintf(stderr, "cannot find map 'operating_dev' in %s.\n", pin_basedir);
		}
		err = check_map_fd_info(&info, &map_expect);
		if (err) {
			fprintf(stderr, "ERR: map via FD not compatible.\n");
			return EXIT_FAIL_BPF;
		}

		err = fw_loader(0);
		if (err) {
			return err;
		}
	}

	if (cfg->ifindex != -1) {
		if (cfg->progsec[0])
			/* Find a matching BPF prog section name */
			bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg->progsec);
		else
			/* Find the first program */
			bpf_prog = bpf_program__next(NULL, bpf_obj);

		if (!bpf_prog) {
			fprintf(stderr, "ERR: couldn't find a program in ELF section '%s'\n", cfg->progsec);
			return EXIT_FAIL_BPF;
		}

		strncpy(cfg->progsec, bpf_program__title(bpf_prog, false), sizeof(cfg->progsec));

		prog_fd = bpf_program__fd(bpf_prog);
		if (prog_fd <= 0) {
			fprintf(stderr, "ERR: bpf_program__fd failed\n");
			return EXIT_FAIL_BPF;
		}

		err = xdp_link_attach(cfg->ifindex, cfg->xdp_flags, prog_fd);
		if (err)
			return err;

		if (verbose)
			printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg->ifname, cfg->ifindex);

		if (bpf_map_update_elem(map_fd, &cfg->ifindex, &initval, 0)) {
			fprintf(stderr, "ERR: updating 'operating_dev' map.\n");
			return EXIT_FAIL_BPF;
		}
		
	}


	return EXIT_OK;
}

int module_loader(struct config *cfg, int progarr_fd)
{
	struct bpf_object *bpf_obj;
	int err, len;
	struct bpf_program *bpf_prog;
	int offload_ifindex = 0;
	int prog_fd = -1;
	int module_exists = 0;

	int prog_map_fd = progarr_fd;
	char progarr_path[PATH_MAX];

	cfg->xdp_flags &= ~XDP_FLAGS_MODES;
	cfg->xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;

	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg->filename, module_filename, sizeof(cfg->filename));

	
	len = snprintf(cfg->pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	struct stat sb;
	if (stat(cfg->pin_dir, &sb) == 0 && S_ISDIR(sb.st_mode)) {
		module_exists = 1;
	}
	
	if (cfg->cmd == DELETE_MODULE) {
		if (!module_exists) {
			fprintf(stderr, "ERR: Module '%s' not exists.\n", cfg->module_name);
			return EXIT_FAIL_OPTION;
		} else if (strcmp(cfg->module_name, "MAIN") == 0) {
			fprintf(stderr, "ERR: Module 'MAIN' can't be deleted.\n");
			return EXIT_FAIL_OPTION;
		}

		bpf_obj = load_bpf_object_file(cfg->filename, offload_ifindex);
		if (!bpf_obj) {
			fprintf(stderr, "ERR: loading file: %s.\n", cfg->filename);
			return EXIT_FAIL_BPF;
		}

		err = unpin_maps_in_bpf_object(bpf_obj, cfg);
		if (err) {
			fprintf(stderr, "ERR: unpinning maps.\n");
			return err;
		}

		char cmd[10+PATH_MAX];
		sprintf(cmd, "rmdir %s", cfg->pin_dir);
		err = system(cmd);
		if (err) {
			fprintf(stderr, "ERR: Deleting module '%s' directory.\n", cfg->module_name);
			return err;
		}
			
		return EXIT_OK;
	}

	if (module_exists && !cfg->reuse_maps) {
		if (strcmp(cfg->module_name, "MAIN") == 0)
			return 0;
		else {
			fprintf(stderr, "ERR: Module already exists.\n");
			return EXIT_FAIL_OPTION;
		}
	}

	if (cfg->reuse_maps)
		bpf_obj = load_bpf_object_file_reuse_maps(cfg->filename,
							  offload_ifindex,
							  cfg->pin_dir);
	else
		bpf_obj = load_bpf_object_file(cfg->filename, offload_ifindex);

	if (!bpf_obj) {
		fprintf(stderr, "ERR: loading file: %s\n", cfg->filename);
		return EXIT_FAIL_BPF;
	}

	if (cfg->progsec[0])
		/* Find a matching BPF prog section name */
		bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg->progsec);
	else
		/* Find the first program */
		bpf_prog = bpf_program__next(NULL, bpf_obj);

	if (!bpf_prog) {
		fprintf(stderr, "ERR: couldn't find a program in ELF section '%s'\n", cfg->progsec);
		return EXIT_FAIL_BPF;
	}

	strncpy(cfg->progsec, bpf_program__title(bpf_prog, false), sizeof(cfg->progsec));

	prog_fd = bpf_program__fd(bpf_prog);
	if (prog_fd <= 0) {
		fprintf(stderr, "ERR: bpf_program__fd failed\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(progarr_path, PATH_MAX, "%s/classifier/firewall_modules", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: Creating firewall modules map path.\n");
		return EXIT_FAIL_OPTION;
	}

	if (prog_map_fd < 0) {
		prog_map_fd = bpf_obj_get(progarr_path);
		if (prog_map_fd < 0) {
			fprintf(stderr, "ERR: Opening firewall modules map.\n");
			return EXIT_FAIL_BPF;
		}
	}

	if (bpf_map_update_elem(prog_map_fd, &cfg->module_index, &prog_fd, 0)) {
		fprintf(stderr, "ERR: Adding module to firewall.\n");
		return EXIT_FAIL_BPF;
	}

	/* Use the --dev name as subdir for exporting/pinning maps */
	if (!cfg->reuse_maps) {
		err = pin_maps_in_bpf_object(bpf_obj, cfg);
		if (err) {
			fprintf(stderr, "ERR: pinning maps\n");
			return err;
		}
	}

	return EXIT_OK;
}

#endif