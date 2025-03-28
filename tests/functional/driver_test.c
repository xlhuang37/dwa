// Copyright 2018-2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

#include "platform.h"

#include "test.h"

#include "poison.h"

#ifdef SGX_TEST
int
sgx_driver_test(int argc, char *argv[])
#else
int
main(int argc, char *argv[])
#endif
{
   return test_dispatcher(argc, argv);
}
