/*
 * Copyright (c) 2020 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "tests.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/types.h>
#include <linux/videodev2.h>

#include <sys/ioctl.h>

struct strval32 {
	uint32_t val;
	const char *str;
};

static bool
fill_fmt(struct v4l2_format *f)
{
	static struct v4l2_clip *clips;

	switch (f->type) {
	case V4L2_BUF_TYPE_VIDEO_CAPTURE:
	case V4L2_BUF_TYPE_VIDEO_OUTPUT:
		f->fmt.pix.width        = 0xdeadc0de;
		f->fmt.pix.height       = 0xfeedbeef;
		f->fmt.pix.pixelformat  = 0xb5315258; /* forurcc_be("XR15") */
		f->fmt.pix.field = f->type == V4L2_BUF_TYPE_VIDEO_CAPTURE
			? V4L2_FIELD_ALTERNATE : 0xdec0ded1;
		f->fmt.pix.bytesperline = 0xbadc0ded;
		f->fmt.pix.sizeimage    = 0xface1e55;
		f->fmt.pix.colorspace   = V4L2_COLORSPACE_REC709;
		break;

	case V4L2_BUF_TYPE_VIDEO_OVERLAY:
#if HAVE_DECL_V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY
	case V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY:
#endif
		f->fmt.win.w.left    = 0xa0a1a2a3;
		f->fmt.win.w.top     = 0xb0b1b2b3;
		f->fmt.win.w.width   = 0xc0c1c2c3;
		f->fmt.win.w.height  = 0xd0d1d2d3;
		f->fmt.win.field     = f->type == V4L2_BUF_TYPE_VIDEO_OVERLAY
			? V4L2_FIELD_ANY : 10;
		f->fmt.win.chromakey = 0xbeefface;

		if (!clips)
			clips = tail_alloc(sizeof(*clips) * 3);
		f->fmt.win.clips = clips;

		f->fmt.win.clips[0].c.left   = 0xa4a5a6a7;
		f->fmt.win.clips[0].c.top    = 0xb4b5b6b7;
		f->fmt.win.clips[0].c.width  = 0xc4c5c6c7;
		f->fmt.win.clips[0].c.height = 0xd4d5d6d7;
		f->fmt.win.clips[0].next     = clips;

		f->fmt.win.clips[1].c.left   = 0xa8a9aaab;
		f->fmt.win.clips[1].c.top    = 0xb8b9babb;
		f->fmt.win.clips[1].c.width  = 0xc8c9cacb;
		f->fmt.win.clips[1].c.height = 0xd8d9dadb;

		f->fmt.win.clips[2].c.left   = 0xacadaeaf;
		f->fmt.win.clips[2].c.top    = 0xbcbdbebf;
		f->fmt.win.clips[2].c.width  = 0xcccdcecf;
		f->fmt.win.clips[2].c.height = 0xdcdddedf;
		f->fmt.win.clips[2].next     = clips + 1;

		f->fmt.win.clipcount = f->type == V4L2_BUF_TYPE_VIDEO_OVERLAY
			? 4 : 0;
		f->fmt.win.bitmap    = f->type == V4L2_BUF_TYPE_VIDEO_OVERLAY
			? NULL : clips;
		break;

	case V4L2_BUF_TYPE_VBI_CAPTURE:
	case V4L2_BUF_TYPE_VBI_OUTPUT:
		f->fmt.vbi.sampling_rate    = 0xdecaffed;
		f->fmt.vbi.offset           = 0xcafefeed;
		f->fmt.vbi.samples_per_line = 0xbeefaced;
		f->fmt.vbi.sample_format    = V4L2_PIX_FMT_RGB555X;

		f->fmt.vbi.start[0] = 0xdec0ded0;
		f->fmt.vbi.start[1] = 0xdec0ded1;
		f->fmt.vbi.count[0] = 0xacceded2;
		f->fmt.vbi.count[1] = 0xacceded3;

		f->fmt.vbi.flags = f->type == V4L2_BUF_TYPE_VBI_CAPTURE
			? 0x3 : 0x1ce50d1c;
		break;

#if HAVE_DECL_V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE
	case V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE:
	case V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE:
		f->fmt.pix_mp.width        = 0xdeaffade;
		f->fmt.pix_mp.height       = 0xfadeb1a5;
		f->fmt.pix_mp.pixelformat  = 0x36314454;
		f->fmt.pix_mp.field        = V4L2_FIELD_NONE;
		f->fmt.pix_mp.colorspace   = 13;

		for (size_t i = 0; i < VIDEO_MAX_PLANES; i++) {
			f->fmt.pix_mp.plane_fmt[i].sizeimage = 0xd0decad0 ^ i;
			f->fmt.pix_mp.plane_fmt[i].bytesperline
				= 0xd0decad1 ^ i;
		}

		f->fmt.pix_mp.num_planes   = f->type ==
			V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE ? 0xbad5eed5 : 0;
		break;
#endif
#if HAVE_DECL_V4L2_BUF_TYPE_SLICED_VBI_CAPTURE
	case V4L2_BUF_TYPE_SLICED_VBI_CAPTURE:
	case V4L2_BUF_TYPE_SLICED_VBI_OUTPUT:
		f->fmt.sliced.service_set = 0xfeed;
		for (size_t i = 0; i < 2; i++) {
			for (size_t j = 0; j < 24; j++) {
				f->fmt.sliced.service_lines[i][j] =
					0xdead ^ (i << 8) ^ j;
			}
		}
		f->fmt.sliced.io_size = 0xdefaceed;
		break;
#endif
#if HAVE_DECL_V4L2_BUF_TYPE_SDR_CAPTURE
	case V4L2_BUF_TYPE_SDR_CAPTURE:
# if HAVE_DECL_V4L2_BUF_TYPE_SDR_OUTPUT
	case V4L2_BUF_TYPE_SDR_OUTPUT:
# endif
		f->fmt.sdr.pixelformat = V4L2_SDR_FMT_CU8;
		f->fmt.sdr.buffersize  = 0xbadc0ded;
		break;
#endif
	default:
		return false;
	}

	return true;
}

static void
print_fmt(const char *pfx, struct v4l2_format *f)
{
	switch (f->type) {
	case V4L2_BUF_TYPE_VIDEO_CAPTURE:
	case V4L2_BUF_TYPE_VIDEO_OUTPUT:
		printf("%s fmt.pix={width=3735929054, height=4276993775"
		       ", pixelformat=" RAW("0xb5315258")
		       NRAW("v4l2_fourcc('X', 'R', '1', '\\xb5')"
		            " /* V4L2_PIX_FMT_XRGB555X */")
		       ", field=%s, bytesperline=3134983661"
		       ", sizeimage=4207812181, colorspace="
		       XLAT_KNOWN(0x3, "V4L2_COLORSPACE_REC709") "}",
		       pfx, f->type == V4L2_BUF_TYPE_VIDEO_CAPTURE
			? XLAT_STR(V4L2_FIELD_ALTERNATE)
			: XLAT_UNKNOWN(0xdec0ded1, "V4L2_FIELD_???"));
		break;

	case V4L2_BUF_TYPE_VIDEO_OVERLAY:
#if HAVE_DECL_V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY
	case V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY:
#endif
		printf("%s fmt.win={w={left=-1600019805, top=-1330531661"
		       ", width=3233923779, height=3503411923}, field=%s"
		       ", chromakey=0xbeefface, clips=[",
		       pfx, f->type == V4L2_BUF_TYPE_VIDEO_OVERLAY
			? XLAT_STR(V4L2_FIELD_ANY)
			: XLAT_UNKNOWN(0xa, "V4L2_FIELD_???"));
		if (f->type == V4L2_BUF_TYPE_VIDEO_OVERLAY) {
			printf("{c={left=-1532647769, top=-1263159625"
			       ", width=3301295815, height=3570783959}}, "
			       "{c={left=-1465275733, top=-1195787589"
			       ", width=3368667851, height=3638155995}}, "
			       "{c={left=-1397903697, top=-1128415553"
			       ", width=3436039887, height=3705528031}}, "
			       "... /* %p */", f->fmt.win.clips + 3);
		}
		printf("], clipcount=%d, bitmap=",
		       f->type == V4L2_BUF_TYPE_VIDEO_OVERLAY ? 4 : 0);

		if (f->type == V4L2_BUF_TYPE_VIDEO_OVERLAY)
			printf("NULL");
		else
			printf("%p", f->fmt.win.bitmap);

#ifdef HAVE_STRUCT_V4L2_WINDOW_GLOBAL_ALPHA
		printf(", global_alpha=%#hhx}", f->fmt.win.global_alpha);
#endif
		break;

	case V4L2_BUF_TYPE_VBI_CAPTURE:
	case V4L2_BUF_TYPE_VBI_OUTPUT:
		printf("%s fmt.vbi={sampling_rate=3737845741, offset=3405709037"
		       ", samples_per_line=3203378413, sample_format="
		       RAW("0x51424752") NRAW("v4l2_fourcc('R', 'G', 'B', 'Q')"
		       " /* V4L2_PIX_FMT_RGB555X */")
		       ", start=[-557785392, -557785391]"
		       ", count=[2899238610, 2899238611], flags=%s}",
		       pfx, f->type == V4L2_BUF_TYPE_VBI_CAPTURE
			? XLAT_KNOWN(0x3, "V4L2_VBI_UNSYNC|V4L2_VBI_INTERLACED")
			: XLAT_UNKNOWN(0x1ce50d1c, "V4L2_VBI_???"));
		break;

#if HAVE_DECL_V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE
	case V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE:
	case V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE:
		printf("%s fmt.pix_mp={width=3736074974, height=4208898469"
		       ", pixelformat=" RAW("0x36314454")
		       NRAW("v4l2_fourcc('T', 'D', '1', '6')"
			    " /* V4L2_TCH_FMT_DELTA_TD16 */")
		       ", field=%s, colorspace=0xd"
		       NRAW(" /* V4L2_COLORSPACE_??? */") ", plane_fmt=[",
		       pfx, XLAT_STR(V4L2_FIELD_NONE));
		if (f->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
			printf("{sizeimage=3504261840, bytesperline=3504261841}"
			", "
			       "{sizeimage=3504261841, bytesperline=3504261840}"
			       ", "
			       "{sizeimage=3504261842, bytesperline=3504261843}"
			       ", "
			       "{sizeimage=3504261843, bytesperline=3504261842}"
			       ", "
			       "{sizeimage=3504261844, bytesperline=3504261845}"
			       ", "
			       "{sizeimage=3504261845, bytesperline=3504261844}"
			       ", "
			       "{sizeimage=3504261846, bytesperline=3504261847}"
			       ", "
			       "{sizeimage=3504261847, bytesperline=3504261846}"
			       "], num_planes=213}");
		} else {
			printf("], num_planes=0}");
		}
		break;
#endif
#if HAVE_DECL_V4L2_BUF_TYPE_SLICED_VBI_CAPTURE
	case V4L2_BUF_TYPE_SLICED_VBI_CAPTURE:
	case V4L2_BUF_TYPE_SLICED_VBI_OUTPUT:
		printf("%s fmt.sliced={service_set="
		       XLAT_UNKNOWN(0xfeed, "V4L2_SLICED_???")
		       ", io_size=3740978925, service_lines=[[0xdead, 0xdeac"
		       ", 0xdeaf, 0xdeae, 0xdea9, 0xdea8, 0xdeab, 0xdeaa"
		       ", 0xdea5, 0xdea4, 0xdea7, 0xdea6, 0xdea1, 0xdea0"
		       ", 0xdea3, 0xdea2, 0xdebd, 0xdebc, 0xdebf, 0xdebe"
		       ", 0xdeb9, 0xdeb8, 0xdebb, 0xdeba], [0xdfad, 0xdfac"
		       ", 0xdfaf, 0xdfae, 0xdfa9, 0xdfa8, 0xdfab, 0xdfaa"
		       ", 0xdfa5, 0xdfa4, 0xdfa7, 0xdfa6, 0xdfa1, 0xdfa0"
		       ", 0xdfa3, 0xdfa2, 0xdfbd, 0xdfbc, 0xdfbf, 0xdfbe"
		       ", 0xdfb9, 0xdfb8, 0xdfbb, 0xdfba]]}",
		       pfx);
		break;
#endif
#if HAVE_DECL_V4L2_BUF_TYPE_SDR_CAPTURE
	case V4L2_BUF_TYPE_SDR_CAPTURE:
# if HAVE_DECL_V4L2_BUF_TYPE_SDR_OUTPUT
	case V4L2_BUF_TYPE_SDR_OUTPUT:
# endif
		printf("%s fmt.sdr={pixelformat=" RAW("0x38305543")
		       NRAW("v4l2_fourcc('C', 'U', '0', '8')"
			    " /* V4L2_SDR_FMT_CU8 */")
		       ", buffersize=%u}",
		       pfx, f->fmt.sdr.buffersize);
		break;
#endif
	}
}

int
main(int argc, char **argv)
{
	unsigned long num_skip;
	long inject_retval;
	bool locked = false;

	if (argc == 1)
		return 0;

	if (argc < 3)
		error_msg_and_fail("Usage: %s NUM_SKIP INJECT_RETVAL", argv[0]);

	num_skip = strtoul(argv[1], NULL, 0);
	inject_retval = strtol(argv[2], NULL, 0);

	if (inject_retval < 0)
		error_msg_and_fail("Expected non-negative INJECT_RETVAL, "
				   "but got %ld", inject_retval);

	for (unsigned int i = 0; i < num_skip; i++) {
		long rc = ioctl(-1, VIDIOC_QUERYCAP, NULL);
		printf("ioctl(-1, %s, NULL) = %s%s\n",
		       XLAT_STR(VIDIOC_QUERYCAP), sprintrc(rc),
		       rc == inject_retval ? " (INJECTED)" : "");

		if (rc != inject_retval)
			continue;

		locked = true;
		break;
	}

	if (!locked)
		error_msg_and_fail("Hasn't locked on ioctl(-1"
				   ", VIDIOC_QUERYCAP, NULL) returning %lu",
				   inject_retval);


	/* VIDIOC_QUERYCAP */
	struct v4l2_capability *caps = tail_alloc(sizeof(*caps));

	fill_memory(caps, sizeof(*caps));
	caps->capabilities = 0xdeadbeef;
#ifdef HAVE_STRUCT_V4L2_CAPABILITY_DEVICE_CAPS
	caps->device_caps = 0xfacefeed;
#endif

	ioctl(-1, VIDIOC_QUERYCAP, 0);
	printf("ioctl(-1, %s, NULL) = %ld (INJECTED)\n",
	       XLAT_STR(VIDIOC_QUERYCAP), inject_retval);

	ioctl(-1, VIDIOC_QUERYCAP, (char *) caps + 1);
	printf("ioctl(-1, %s, %p) = %ld (INJECTED)\n",
	       XLAT_STR(VIDIOC_QUERYCAP), (char *) caps + 1, inject_retval);

	ioctl(-1, VIDIOC_QUERYCAP, caps);
	printf("ioctl(-1, %s, {driver=", XLAT_STR(VIDIOC_QUERYCAP));
	print_quoted_cstring((char *) caps->driver, sizeof(caps->driver));
	printf(", card=");
	print_quoted_cstring((char *) caps->card, sizeof(caps->card));
	printf(", bus_info=");
	print_quoted_cstring((char *) caps->bus_info, sizeof(caps->bus_info));
	printf(", version="
#ifdef WORDS_BIGENDIAN
	       XLAT_KNOWN(0xd0d1d2d3, "KERNEL_VERSION(53457, 210, 211)")
#else
	       XLAT_KNOWN(0xd3d2d1d0, "KERNEL_VERSION(54226, 209, 208)")
#endif
	       ", capabilities=" XLAT_KNOWN(0xdeadbeef,
	       "V4L2_CAP_VIDEO_CAPTURE|V4L2_CAP_VIDEO_OUTPUT"
	       "|V4L2_CAP_VIDEO_OVERLAY|V4L2_CAP_VBI_OUTPUT"
	       "|V4L2_CAP_SLICED_VBI_CAPTURE|V4L2_CAP_SLICED_VBI_OUTPUT"
	       "|V4L2_CAP_VIDEO_OUTPUT_OVERLAY|V4L2_CAP_HW_FREQ_SEEK"
	       "|V4L2_CAP_RDS_OUTPUT|V4L2_CAP_VIDEO_CAPTURE_MPLANE"
	       "|V4L2_CAP_VIDEO_OUTPUT_MPLANE|V4L2_CAP_VIDEO_M2M"
	       "|V4L2_CAP_TUNER|V4L2_CAP_RADIO|V4L2_CAP_MODULATOR"
	       "|V4L2_CAP_EXT_PIX_FORMAT|V4L2_CAP_META_CAPTURE|V4L2_CAP_ASYNCIO"
	       "|V4L2_CAP_STREAMING|V4L2_CAP_META_OUTPUT|V4L2_CAP_TOUCH"
	       "|V4L2_CAP_DEVICE_CAPS|0x40000008"));
#ifdef HAVE_STRUCT_V4L2_CAPABILITY_DEVICE_CAPS
	printf(", device_caps=" XLAT_KNOWN(0xfacefeed,
	       "V4L2_CAP_VIDEO_CAPTURE|V4L2_CAP_VIDEO_OVERLAY"
	       "|V4L2_CAP_VBI_OUTPUT|V4L2_CAP_SLICED_VBI_CAPTURE"
	       "|V4L2_CAP_SLICED_VBI_OUTPUT|V4L2_CAP_VIDEO_OUTPUT_OVERLAY"
	       "|V4L2_CAP_HW_FREQ_SEEK|V4L2_CAP_RDS_OUTPUT"
	       "|V4L2_CAP_VIDEO_CAPTURE_MPLANE|V4L2_CAP_VIDEO_OUTPUT_MPLANE"
	       "|V4L2_CAP_VIDEO_M2M_MPLANE|V4L2_CAP_VIDEO_M2M|V4L2_CAP_AUDIO"
	       "|V4L2_CAP_RADIO|V4L2_CAP_MODULATOR|V4L2_CAP_SDR_OUTPUT"
	       "|V4L2_CAP_META_CAPTURE|V4L2_CAP_ASYNCIO|V4L2_CAP_META_OUTPUT"
	       "|V4L2_CAP_TOUCH|V4L2_CAP_DEVICE_CAPS|0x60000008"));
#endif
	printf("}) = %ld (INJECTED)\n", inject_retval);


	/* VIDIOC_ENUM_FMT */
	static const struct strval32 buf_types[] = {
		{ ARG_XLAT_UNKNOWN(0, "V4L2_BUF_TYPE_???") },
		{ ARG_XLAT_KNOWN(0x1, "V4L2_BUF_TYPE_VIDEO_CAPTURE") },
		{ ARG_XLAT_KNOWN(0x2, "V4L2_BUF_TYPE_VIDEO_OUTPUT") },
		{ ARG_XLAT_KNOWN(0x3, "V4L2_BUF_TYPE_VIDEO_OVERLAY") },
		{ ARG_XLAT_KNOWN(0x4, "V4L2_BUF_TYPE_VBI_CAPTURE") },
		{ ARG_XLAT_KNOWN(0x5, "V4L2_BUF_TYPE_VBI_OUTPUT") },
		{ ARG_XLAT_KNOWN(0x6, "V4L2_BUF_TYPE_SLICED_VBI_CAPTURE") },
		{ ARG_XLAT_KNOWN(0x7, "V4L2_BUF_TYPE_SLICED_VBI_OUTPUT") },
		{ ARG_XLAT_KNOWN(0x8, "V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY") },
		{ ARG_XLAT_KNOWN(0x9, "V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE") },
		{ ARG_XLAT_KNOWN(0xa, "V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE") },
		{ ARG_XLAT_KNOWN(0xb, "V4L2_BUF_TYPE_SDR_CAPTURE") },
		{ ARG_XLAT_KNOWN(0xc, "V4L2_BUF_TYPE_SDR_OUTPUT") },
		{ ARG_XLAT_KNOWN(0xd, "V4L2_BUF_TYPE_META_CAPTURE") },
		{ ARG_XLAT_KNOWN(0xe, "V4L2_BUF_TYPE_META_OUTPUT") },
		{ ARG_XLAT_UNKNOWN(0x80, "V4L2_BUF_TYPE_???") },
		{ ARG_XLAT_UNKNOWN(0xbadc0ded, "V4L2_BUF_TYPE_???") },
	};
	static const struct strval32 fmtdesc_flags[] = {
		{ ARG_STR(0) },
		{ ARG_XLAT_KNOWN(0x1, "V4L2_FMT_FLAG_COMPRESSED") },
		{ ARG_XLAT_KNOWN(0x1e, "V4L2_FMT_FLAG_EMULATED"
				       "|V4L2_FMT_FLAG_CONTINUOUS_BYTESTREAM"
				       "|V4L2_FMT_FLAG_DYN_RESOLUTION|0x10") },
		{ ARG_XLAT_UNKNOWN(0xdead0000, "V4L2_FMT_FLAG_???") },
	};
	static const struct strval32 fmtdesc_fmts[] = {
		{ 0x4c47504a, RAW("0x4c47504a")
			      NRAW("v4l2_fourcc('J', 'P', 'G', 'L')"
			           " /* V4L2_PIX_FMT_JPGL */") },
		{ 0xbadc0ded, RAW("0xbadc0ded")
			      NRAW("v4l2_fourcc('\\xed', '\\x0d', '\\xdc',"
			           " '\\xba')") },
	};
	struct v4l2_fmtdesc *fmtdesc = tail_alloc(sizeof(*fmtdesc));

	fill_memory(fmtdesc, sizeof(*fmtdesc));
	fmtdesc->index = 0xdeac0de;

	ioctl(-1, VIDIOC_ENUM_FMT, 0);
	printf("ioctl(-1, %s, NULL) = %ld (INJECTED)\n",
	       XLAT_STR(VIDIOC_ENUM_FMT), inject_retval);

	ioctl(-1, VIDIOC_ENUM_FMT, (char *) fmtdesc + 1);
	printf("ioctl(-1, %s, %p) = %ld (INJECTED)\n",
	       XLAT_STR(VIDIOC_ENUM_FMT), (char *) fmtdesc + 1, inject_retval);

	for (size_t i = 0; i < ARRAY_SIZE(buf_types); i++) {
		for (size_t j = 0; j < ARRAY_SIZE(fmtdesc_flags); j++) {
			for (size_t k = 0; k < ARRAY_SIZE(fmtdesc_fmts); k++) {
				fmtdesc->type = buf_types[i].val;
				fmtdesc->flags = fmtdesc_flags[j].val;
				fmtdesc->pixelformat = fmtdesc_fmts[k].val;

				ioctl(-1, VIDIOC_ENUM_FMT, fmtdesc);
				printf("ioctl(-1, %s, {index=233488606, type=%s"
				       ", flags=%s, description=",
				       XLAT_STR(VIDIOC_ENUM_FMT),
				       buf_types[i].str,
				       fmtdesc_flags[j].str);
				print_quoted_cstring((char *) fmtdesc->description,
					sizeof(fmtdesc->description));
				printf(", pixelformat=%s}) = %ld (INJECTED)\n",
				       fmtdesc_fmts[k].str, inject_retval);

				fill_memory_ex(fmtdesc->description,
					       sizeof(fmtdesc->description),
					       (i * 9 + j) * 7 + k,
					       (k * 3 + j) * 11 + i + 5);
			}
		}
	}


	/* VIDIOC_REQBUFS */
	static const struct strval32 reqb_mems[] = {
		{ ARG_XLAT_UNKNOWN(0, "V4L2_MEMORY_???") },
		{ ARG_XLAT_KNOWN(0x1, "V4L2_MEMORY_MMAP") },
		{ ARG_XLAT_KNOWN(0x4, "V4L2_MEMORY_DMABUF") },
		{ ARG_XLAT_UNKNOWN(0x5, "V4L2_MEMORY_???") },
		{ ARG_XLAT_UNKNOWN(0xbadc0ded, "V4L2_MEMORY_???") },
	};
	struct v4l2_requestbuffers *reqb = tail_alloc(sizeof(*reqb));

	fill_memory(reqb, sizeof(*reqb));
	reqb->count = 0xfeedface;

	ioctl(-1, VIDIOC_REQBUFS, 0);
	printf("ioctl(-1, %s, NULL) = %ld (INJECTED)\n",
	       XLAT_STR(VIDIOC_REQBUFS), inject_retval);

	ioctl(-1, VIDIOC_REQBUFS, (char *) reqb + 1);
	printf("ioctl(-1, %s, %p) = %ld (INJECTED)\n",
	       XLAT_STR(VIDIOC_REQBUFS), (char *) reqb + 1, inject_retval);

	for (size_t i = 0; i < MAX(ARRAY_SIZE(buf_types),
				   ARRAY_SIZE(reqb_mems)); i++) {
		reqb->type = buf_types[i % ARRAY_SIZE(buf_types)].val;
		reqb->memory = reqb_mems[i % ARRAY_SIZE(reqb_mems)].val;

		ioctl(-1, VIDIOC_REQBUFS, reqb);
		printf("ioctl(-1, %s, {type=%s, memory=%s"
		       ", count=4277009102 => 4277009102}) = %ld (INJECTED)\n",
		       XLAT_STR(VIDIOC_REQBUFS),
		       buf_types[i % ARRAY_SIZE(buf_types)].str,
		       reqb_mems[i % ARRAY_SIZE(reqb_mems)].str,
		       inject_retval);
	}


	/* VIDIOC_G_FMT, VIDIOC_S_FMT, VIDIOC_TRY_FMT */
	static const struct strval32 fmt_cmds[] = {
		{ ARG_STR(VIDIOC_G_FMT) },
		{ ARG_STR(VIDIOC_S_FMT) },
		{ ARG_STR(VIDIOC_TRY_FMT) },
	};

	struct v4l2_format *fmt = tail_alloc(sizeof(*fmt));

	for (size_t i = 0; i < ARRAY_SIZE(fmt_cmds); i++) {
		ioctl(-1, fmt_cmds[i].val, 0);
		printf("ioctl(-1, %s, NULL) = %ld (INJECTED)\n",
		       sprintxlat(fmt_cmds[i].str, fmt_cmds[i].val, NULL),
		       inject_retval);

		ioctl(-1, fmt_cmds[i].val, (char *) fmt + 1);
		printf("ioctl(-1, %s, %p) = %ld (INJECTED)\n",
		       sprintxlat(fmt_cmds[i].str, fmt_cmds[i].val, NULL),
		       (char *) fmt + 1, inject_retval);

		for (size_t j = 0; j < ARRAY_SIZE(buf_types); j++) {
			fill_memory(fmt, sizeof(*fmt));

			fmt->type = buf_types[j].val;
			fill_fmt(fmt);

			ioctl(-1, fmt_cmds[i].val, fmt);
			printf("ioctl(-1, %s, {type=%s",
			       sprintxlat(fmt_cmds[i].str, fmt_cmds[i].val,
					  NULL),
			       buf_types[j].str);
			print_fmt(",", fmt);
			if (fmt_cmds[i].val != VIDIOC_G_FMT &&
			    buf_types[j].val != V4L2_BUF_TYPE_VIDEO_OVERLAY &&
			    buf_types[j].val != 8)
				print_fmt(" =>", fmt);
			printf("}) = %ld (INJECTED)\n", inject_retval);
		}
	}

	puts("+++ exited with 0 +++");

	return 0;
}
