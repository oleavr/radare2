/* radare - LGPL - Copyright 2022 - pancake */

#include <r_lib.h>
#include <r_bin.h>

static RBinXtrData *extract(RBin *bin, int idx);

static bool check_buffer(RBinFile *bf, RBuffer *b) {
	if (r_buf_size (b) >= 0x20) {
		ut8 magic[4] = {0};
		if (r_buf_read_at (b, 0, magic, sizeof (magic)) != 4) {
			return false;
		}
		return !memcmp (magic, "XALZ", 4);
	}
	return false;
}

static void free_xtr(void *xtr_obj) {
	// r_bin_xalz_free ((struct r_bin_xalz_obj_t*)xtr_obj);
}

static void destroy(RBin *bin) {
	// free_xtr (bin->cur->xtr_obj);
}

static void *xalz_new(RBinFile *bf) {
	return strdup ("sentinel");
}

static bool load(RBin *bin) {
	eprintf ("load\n");
	return ((bin->cur->xtr_obj = xalz_new (NULL)));
}

static int size(RBin *bin) {
	// TODO
	return 0;
}

static RBinXtrData *extract(RBin* bin, int idx) {
	// XXX never called
	eprintf ("extract\n");
	return NULL;
}

#if 0
// XXX deprecate
static RBinXtrData *extract(RBin* bin, int idx) {
	int narch;
	struct r_bin_xalz_obj_t *fb = bin->cur->xtr_obj;
	struct r_bin_xalz_arch_t *arch = r_bin_xalz_extract (fb, idx, &narch);
	if (!arch) {
		return NULL;
	}
	RBinXtrMetadata *metadata = R_NEW0 (RBinXtrMetadata);
	if (!metadata) {
		r_buf_free (arch->b);
		free (arch);
		return NULL;
	}
	struct MACH0_(mach_header) *hdr = MACH0_(get_hdr) (arch->b);
	if (!hdr) {
		free (metadata);
		free (arch);
		free (hdr);
		return NULL;
	}
	fill_metadata_info_from_hdr (metadata, hdr);
	RBinXtrData * res = r_bin_xtrdata_new (arch->b, arch->offset, arch->size, narch, metadata);
	r_buf_free (arch->b);
	free (arch);
	free (hdr);
	return res;
}
#endif

static RBinXtrData *get_the_meta(RBin *bin, RBuffer *buf) {
	RBinXtrMetadata *meta = R_NEW0 (RBinXtrMetadata);
	meta->arch = strdup ("msil");
	meta->bits = 64;
	meta->machine = "mono";
	meta->type = "assembly";
	meta->libname = NULL;
	meta->xtr_type = "xalz";
	buf = r_buf_new_slurp ("/bin/ls");
	RBinXtrData *res = r_bin_xtrdata_new (buf, 0, r_buf_size (buf), 0, meta);
	// r_buf_free (buf);
	return res;
}

#if 0
// XXX this is never called
static RBinXtrData *oneshot_buffer(RBin *bin, RBuffer *b, int idx) {
	r_return_val_if_fail (bin && bin->cur, NULL);
	eprintf ("wanshot\n");
	RBuffer *buf = NULL;
	
	RBinXtrMetadata *meta = R_NEW0 (RBinXtrMetadata);
	meta->arch = strdup ("msil");
	meta->bits = 64;
	meta->machine = "mono";
	meta->type = "assembly";
	meta->libname = NULL;
	meta->xtr_type = "xalz";
	RBinXtrData *res = r_bin_xtrdata_new (buf, 0, r_buf_size (buf), 0, meta);
	r_buf_free (buf);
	return res;
	return NULL;
	if (!bin->cur->xtr_obj) {
		bin->cur->xtr_obj = r_bin_xalz_from_buffer_new (b);
	}
	int narch;
	struct r_bin_xalz_obj_t *fb = bin->cur->xtr_obj;
	struct r_bin_xalz_arch_t *arch = r_bin_xalz_extract (fb, idx, &narch);
	if (arch) {
		RBinXtrMetadata *metadata = R_NEW0 (RBinXtrMetadata);
		if (metadata) {
			struct MACH0_(mach_header) *hdr = MACH0_(get_hdr) (arch->b);
			if (hdr) {
				fill_metadata_info_from_hdr (metadata, hdr);
				RBinXtrData *res = r_bin_xtrdata_new (arch->b, arch->offset, arch->size, narch, metadata);
				r_buf_free (arch->b);
				free (arch);
				free (hdr);
				return res;
			}
			free (metadata);
		}
		free (arch);
	}
	return NULL;
}
#endif

static RList *oneshotall_buffer(RBin *bin, RBuffer *b) {
	eprintf ("THIS IS ALWAYS THERE\n");
	RList *list = r_list_newf (free);
	RBinXtrMetadata *meta = get_the_meta (bin, b);
	r_list_append (list, meta);
	return list;
}
#if 0
static RList *oneshotall_buffer(RBin *bin, RBuffer *b) {
	RBinXtrData *data = oneshot_buffer (bin, b, 0);
	if (data) {
		// XXX - how do we validate a valid narch?
		int  narch = data->file_count;
		RList *res = r_list_newf (r_bin_xtrdata_free);
		if (!res) {
			r_bin_xtrdata_free (data);
			return NULL;
		}
		r_list_append (res, data);
		int i = 0;
		for (i = 1; data && i < narch; i++) {
			data = oneshot_buffer (bin, b, i);
			if (data) {
				r_list_append (res, data);
			}
		}
		return res;
	}
	return NULL;
}
#endif

RBinXtrPlugin r_bin_xtr_plugin_xtr_xalz = {
	.name = "xtr.xalz",
	.desc = "XAmarin LZ4 assemblies",
	.license = "MIT",
	.load = &load,
	.size = &size,
	.extract = &extract,
	.destroy = &destroy,
	// .extract_from_buffer = &oneshot_buffer,
	.extractall_from_buffer = &oneshotall_buffer,
	.free_xtr = &free_xtr,
	.check_buffer = check_buffer,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN_XTR,
	.data = &r_bin_xtr_plugin_xtr_xalz,
	.version = R2_VERSION
};
#endif

#if 0
/* radare2 - LGPL - Copyright 2022 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_io.h>
#include <r_cons.h>
#define R_BIN_PE64 1
#include "../i/private.h"
#include "pe/pe.h"

static bool check_buffer(RBinFile *bf, RBuffer *b) {
	if (r_buf_size (b) >= 0x20) {
		ut8 magic[4];
		if (r_buf_read_at (b, 0, magic, sizeof (magic)) != 4) {
			return false;
		}
		return !memcmp (magic, "XALZ", 4);
	}
	return false;
}

static bool load_bytes(RBinFile *bf, void **bin_obj, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	if (sz < 32) {
		return false;
	}
	// ut32 off = r_buf_read_le32_at (bf->buf, 4); // unnecessary
	ut32 osz = r_buf_read_le32_at (bf->buf, 8);
	int consumed = 0;
	int outsize = 0;
	ut8 *obuf = r_inflate_lz4 ((const ut8*)buf + 0xc, (uint32_t) sz - 0xc, &consumed, &outsize);
	if (obuf) {
		if (outsize != osz) {
			eprintf ("Unexpected decompression size\n");
			// something wrong happend
		}
		RBuffer *ob = bf->buf;
		RBuffer *nb = r_buf_new_with_pointers (obuf, outsize, false);
		bf->buf = nb;
		bf->o = r_bin_object_new (bf, &r_bin_plugin_pe, 0,0,0,0);
		RBinPlugin *pe = &r_bin_plugin_pe;
		if (!pe->load_buffer (bf, bin_obj, nb, loadaddr, sdb)) {
			free (obuf);
			r_buf_free (nb);
			bf->buf = ob;
			return false;
		}
		pe->info (bf);
		struct Pe64_r_bin_pe_obj_t *res = *bin_obj;
		// info is not suposed to be set in here, but meh :D see bobj.c and grep for '"info"', same for bin_pe.inc
		sdb_ns_set (sdb, "info", res->kv);
		// hack the pointers in a very ugly way
		// memcpy (&r_bin_plugin_xalz, &r_bin_plugin_pe, sizeof (RBinPlugin));
		r_buf_free (ob);
		return true;
	}
	eprintf ("Decompression failed\n");
	return false;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	r_return_val_if_fail (bf && buf, false);
	const ut64 la = bf->loadaddr;
	ut64 sz = 0;
	const ut8 *bytes = r_buf_data (buf, &sz);
	return load_bytes (bf, bin_obj, bytes, sz, la, bf->sdb);
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (ret) {
		ret->file = strdup (bf->file);
		ret->rclass = strdup ("pe"); // XALZ"
		ret->os = strdup ("xamarin");
		ret->arch = strdup ("dotnet");
		ret->machine = strdup (".NET");
		ret->subsystem = strdup ("xamarin");
		ret->bclass = strdup ("program");
		ret->type = strdup ("LIBRARY");
		ret->bits = 64;
		ret->has_va = true;
		ret->has_lit = true;
		ret->big_endian = false;
		ret->dbg_info = false;
	}
	return ret;
}

// whats returned here goes into bin/cur/info/
static Sdb* get_sdb(RBinFile *bf) {
	RBinObject *o = bf? bf->o: NULL;
	return o? o->kv: NULL;
}

#if !R_BIN_XALZ

RBinPlugin r_bin_plugin_xtr_xalz = {
	.name = "xalz",
	.desc = "XAmarin LZ4 AOT Assemblies",
	.license = "MIT",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.get_sdb = &get_sdb,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_xtr_xalz,
	.version = R2_VERSION
};
#endif
#endif

#endif
