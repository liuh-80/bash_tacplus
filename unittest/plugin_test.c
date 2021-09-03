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
  initialize_tacacs_servers();
  tacacs_ctrl = PAM_TAC_DEBUG;
  return 0;
}

/* Test tacacs_authorization all tacacs server connect failed case */
void testcase_tacacs_authorization_all_failed() {
	char *testargv[2];
	testargv[0] = "arg1";
	testargv[1] = "arg2";
	
	
	// test connection failed case
	set_test_scenario(TEST_SCEANRIO_CONNECTION_ALL_FAILED);
	int result = tacacs_authorization("test_user","tty0","test_host","test_command",testargv,2);

	CU_ASSERT_STRING_EQUAL(mock_syslog_message_buffer, "Failed to connect to TACACS server(s)\n");
	
	// check return value, -2 for all server not reachable
	CU_ASSERT_EQUAL(result, -2);
}

/* Test tacacs_authorization get failed result case */
void testcase_tacacs_authorization_faled() {
	char *testargv[2];
	testargv[0] = "arg1";
	testargv[1] = "arg2";
	
	// test connection failed case
	set_test_scenario(TEST_SCEANRIO_CONNECTION_SEND_FAILED_RESULT);
	int result = tacacs_authorization("test_user","tty0","test_host","test_command",testargv,2);

    // send auth message failed.
	CU_ASSERT_EQUAL(result, -1);
}

/* Test tacacs_authorization read failed case */
void testcase_tacacs_authorization_read_failed() {
	char *testargv[2];
	testargv[0] = "arg1";
	testargv[1] = "arg2";
	
	// test connection failed case
	set_test_scenario(TEST_SCEANRIO_CONNECTION_SEND_SUCCESS_READ_FAILED);
	int result = tacacs_authorization("test_user","tty0","test_host","test_command",testargv,2);

	CU_ASSERT_STRING_EQUAL(mock_syslog_message_buffer, "test_command not authorized from TestAddress2\n");

    // read auth message failed.
	CU_ASSERT_EQUAL(result, -1);
}

/* Test tacacs_authorization get denined case */
void testcase_tacacs_authorization_denined() {
	char *testargv[2];
	testargv[0] = "arg1";
	testargv[1] = "arg2";
	
	// test connection failed case
	set_test_scenario(TEST_SCEANRIO_CONNECTION_SEND_DENINED_RESULT);
	int result = tacacs_authorization("test_user","tty0","test_host","test_command",testargv,2);

	CU_ASSERT_STRING_EQUAL(mock_syslog_message_buffer, "test_command not authorized from TestAddress2\n");

    // send auth message failed.
	CU_ASSERT_EQUAL(result, 1);
}

/* Test tacacs_authorization get success case */
void testcase_tacacs_authorization_success() {
	char *testargv[2];
	testargv[0] = "arg1";
	testargv[1] = "arg2";
	
	// test connection failed case
	set_test_scenario(TEST_SCEANRIO_CONNECTION_SEND_SUCCESS_RESULT);
	int result = tacacs_authorization("test_user","tty0","test_host","test_command",testargv,2);

    // send auth message failed.
	CU_ASSERT_EQUAL(result, 0);
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

  if (!CU_add_test(ste, "Test testcase_tacacs_authorization_all_failed()...\n", testcase_tacacs_authorization_all_failed)
	  || !CU_add_test(ste, "Test testcase_tacacs_authorization_faled()...\n", testcase_tacacs_authorization_faled)
	  || !CU_add_test(ste, "Test testcase_tacacs_authorization_read_failed()...\n", testcase_tacacs_authorization_read_failed)
	  || !CU_add_test(ste, "Test testcase_tacacs_authorization_denined()...\n", testcase_tacacs_authorization_denined)
	  || !CU_add_test(ste, "Test testcase_tacacs_authorization_success()...\n", testcase_tacacs_authorization_success)) {
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