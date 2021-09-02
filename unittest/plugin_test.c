#include <stdio.h>
#include <string.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "mock_helper.h"
#include <libtac/support.h>

/* tacacs debug flag */
extern int tacacs_ctrl;

int clean_up() {
  return 0;
}

int start_up() {
  tacacs_ctrl = PAM_TAC_DEBUG;
  return 0;
}

/* Test plugin not exist scenario */
void testcase_tacacs_authorization() {
	char *testargv[2];
	testargv[0] = "arg1";
	testargv[1] = "arg2";
	
    initialize_tacacs_servers();
	
	// test connection failed case
	set_test_scenario(TEST_SCEANRIO_CONNECTION_ALL_FAILED);
	tacacs_authorization("test_user","tty0","test_host","test_command",testargv,2);

	CU_ASSERT_STRING_EQUAL(mock_syslog_message_buffer, "Failed to connect to TACACS server(s)\n");
}

int main(void) {
  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }

  CU_pSuite ste = CU_add_suite("plugin_test", start_up, clean_up);
  if (NULL == ste) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  if (CU_get_error() != CUE_SUCCESS) {
    fprintf(stderr, "Error creating suite: (%d)%s\n", CU_get_error(), CU_get_error_msg());
    return CU_get_error();
  }

  if (!CU_add_test(ste, "Test testcase_tacacs_authorization()...\n", testcase_tacacs_authorization)) {
    CU_cleanup_registry();
    return CU_get_error();
  }
  
  if (CU_get_error() != CUE_SUCCESS) {
    fprintf(stderr, "Error adding test: (%d)%s\n", CU_get_error(), CU_get_error_msg());
  }

  // run all test
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_ErrorCode run_errors = CU_basic_run_suite(ste);
  if (run_errors != CUE_SUCCESS) {
    fprintf(stderr, "Error running tests: (%d)%s\n", run_errors, CU_get_error_msg());
  }

  CU_basic_show_failures(CU_get_failure_list());
  CU_cleanup_registry();
  return CU_get_error();
}