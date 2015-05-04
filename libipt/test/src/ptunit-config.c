/*
 * Copyright (c) 2015, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  * Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "ptunit.h"

#include "pt_config.h"

#include "intel-pt.h"

#include <stddef.h>


/* A global fake buffer to pacify static analyzers. */
static uint8_t buffer[8];

static struct ptunit_result from_user_null(void)
{
	struct pt_config config;
	int errcode;

	errcode = pt_config_from_user(NULL, &config);
	ptu_int_eq(errcode, -pte_internal);

	errcode = pt_config_from_user(&config, NULL);
	ptu_int_eq(errcode, -pte_invalid);

	return ptu_passed();
}

static struct ptunit_result from_user_too_small(void)
{
	struct pt_config config, user;
	int errcode;

	user.size = sizeof(config.size);

	errcode = pt_config_from_user(&config, &user);
	ptu_int_eq(errcode, -pte_bad_config);

	return ptu_passed();
}

static struct ptunit_result from_user_bad_buffer(void)
{
	struct pt_config config, user;
	int errcode;

	pt_config_init(&user);

	errcode = pt_config_from_user(&config, &user);
	ptu_int_eq(errcode, -pte_bad_config);

	user.begin = buffer;

	errcode = pt_config_from_user(&config, &user);
	ptu_int_eq(errcode, -pte_bad_config);

	user.begin = NULL;
	user.end = buffer;

	errcode = pt_config_from_user(&config, &user);
	ptu_int_eq(errcode, -pte_bad_config);

	user.begin = &buffer[1];
	user.end = buffer;

	errcode = pt_config_from_user(&config, &user);
	ptu_int_eq(errcode, -pte_bad_config);

	return ptu_passed();
}

static struct ptunit_result from_user(void)
{
	struct pt_config config, user;
	int errcode;

	user.size = sizeof(user);
	user.begin = buffer;
	user.end = &buffer[sizeof(buffer)];
	user.cpu.vendor = pcv_intel;
	user.errata.bdm70 = 1;

	errcode = pt_config_from_user(&config, &user);
	ptu_int_eq(errcode, 0);
	ptu_uint_eq(config.size, sizeof(config));
	ptu_ptr_eq(config.begin, buffer);
	ptu_ptr_eq(config.end, &buffer[sizeof(buffer)]);
	ptu_int_eq(config.cpu.vendor, pcv_intel);
	ptu_uint_eq(config.errata.bdm70, 1);

	return ptu_passed();
}

static struct ptunit_result from_user_small(void)
{
	struct pt_config config, user;
	int errcode;

	memset(&config, 0xcd, sizeof(config));

	user.size = offsetof(struct pt_config, cpu);
	user.begin = buffer;
	user.end = &buffer[sizeof(buffer)];

	errcode = pt_config_from_user(&config, &user);
	ptu_int_eq(errcode, 0);
	ptu_uint_eq(config.size, offsetof(struct pt_config, cpu));
	ptu_ptr_eq(config.begin, buffer);
	ptu_ptr_eq(config.end, &buffer[sizeof(buffer)]);
	ptu_int_eq(config.cpu.vendor, pcv_unknown);
	ptu_uint_eq(config.errata.bdm70, 0);

	return ptu_passed();
}

static struct ptunit_result from_user_big(void)
{
	struct pt_config config, user;
	int errcode;

	user.size = sizeof(user) + 4;
	user.begin = buffer;
	user.end = &buffer[sizeof(buffer)];
	user.cpu.vendor = pcv_intel;
	user.errata.bdm70 = 1;

	errcode = pt_config_from_user(&config, &user);
	ptu_int_eq(errcode, 0);
	ptu_uint_eq(config.size, sizeof(config));
	ptu_ptr_eq(config.begin, buffer);
	ptu_ptr_eq(config.end, &buffer[sizeof(buffer)]);
	ptu_int_eq(config.cpu.vendor, pcv_intel);
	ptu_uint_eq(config.errata.bdm70, 1);

	return ptu_passed();
}

int main(int argc, char **argv)
{
	struct ptunit_suite suite;

	suite = ptunit_mk_suite(argc, argv);

	ptu_run(suite, from_user_null);
	ptu_run(suite, from_user_too_small);
	ptu_run(suite, from_user_bad_buffer);
	ptu_run(suite, from_user);
	ptu_run(suite, from_user_small);
	ptu_run(suite, from_user_big);

	ptunit_report(&suite);
	return suite.nr_fails;
}
