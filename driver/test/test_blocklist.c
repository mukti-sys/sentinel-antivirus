/*
 * test_blocklist.c — User-mode test for the portable blocklist.
 *
 * Compiles as a plain user-mode .exe (no WDK needed):
 *   cl.exe /W4 /Fe:test_blocklist.exe test_blocklist.c ..\SentinelFilter\blocklist.c
 *
 * Provides malloc/free as alloc/free and no-op lock/unlock for
 * single-threaded testing.
 *
 * Tests:
 *   1. Init with valid args
 *   2. Init with NULL args fails
 *   3. Add single path
 *   4. Contains returns 1 for added path
 *   5. Contains returns 0 for non-added path
 *   6. Case-insensitive matching (path normalization)
 *   7. Forward-slash normalization
 *   8. Duplicate add returns BL_ERR_DUPLICATE
 *   9. Remove existing path
 *  10. Remove non-existing returns BL_ERR_NOT_FOUND
 *  11. Contains after remove returns 0
 *  12. Empty blocklist: contains returns 0
 *  13. Path too long returns BL_ERR_PATH_TOO_LONG
 *  14. Multiple entries maintained in sorted order
 *  15. Stress: add 500 entries, verify all, remove all
 *  16. Destroy frees all entries
 *
 * Copyright (c) 2026 Sentinel Project. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* We are user-mode, not kernel. */
#ifdef _KERNEL_MODE
#undef _KERNEL_MODE
#endif

#include "../SentinelFilter/blocklist.h"

/* ----------------------------------------------------------------------- */
/* Test infrastructure                                                     */
/* ----------------------------------------------------------------------- */

static int g_passed = 0;
static int g_failed = 0;
static int g_alloc_count = 0;  /* Track allocations for leak checking. */

#define TEST(name) \
    do { printf("  [TEST] %s ... ", name); } while(0)

#define PASS() \
    do { printf("PASS\n"); g_passed++; } while(0)

#define FAIL(msg) \
    do { printf("FAIL: %s\n", msg); g_failed++; } while(0)

#define ASSERT_EQ(a, b, msg) \
    do { if ((a) != (b)) { FAIL(msg); return; } } while(0)

#define ASSERT_NEQ(a, b, msg) \
    do { if ((a) == (b)) { FAIL(msg); return; } } while(0)

/* ----------------------------------------------------------------------- */
/* Caller-provided hooks for user-mode testing                             */
/* ----------------------------------------------------------------------- */

static void* test_alloc(void *ctx, size_t size)
{
    void *p;
    (void)ctx;
    p = malloc(size);
    if (p) g_alloc_count++;
    return p;
}

static void test_free(void *ctx, void *ptr)
{
    (void)ctx;
    if (ptr) {
        g_alloc_count--;
        free(ptr);
    }
}

/* No-op lock/unlock for single-threaded tests. */
static void test_lock(void *ctx)   { (void)ctx; }
static void test_unlock(void *ctx) { (void)ctx; }

/* ----------------------------------------------------------------------- */
/* Helper: create a fresh blocklist for each test                          */
/* ----------------------------------------------------------------------- */

static BLOCKLIST* make_bl(void)
{
    BLOCKLIST *bl = (BLOCKLIST *)malloc(sizeof(BLOCKLIST));
    if (!bl) return NULL;
    if (blocklist_init(bl, test_alloc, test_free, NULL,
                       test_lock, test_unlock, NULL) != BL_SUCCESS) {
        free(bl);
        return NULL;
    }
    return bl;
}

static void free_bl(BLOCKLIST *bl)
{
    if (bl) {
        blocklist_destroy(bl);
        free(bl);
    }
}

/* ----------------------------------------------------------------------- */
/* Tests                                                                   */
/* ----------------------------------------------------------------------- */

static void test_init_valid(void)
{
    BLOCKLIST bl;
    int rc;
    TEST("init with valid args");
    rc = blocklist_init(&bl, test_alloc, test_free, NULL,
                        test_lock, test_unlock, NULL);
    ASSERT_EQ(rc, BL_SUCCESS, "init should return BL_SUCCESS");
    ASSERT_EQ(bl.count, 0, "count should be 0");
    ASSERT_EQ(bl.head, NULL, "head should be NULL");
    PASS();
}

static void test_init_null_args(void)
{
    BLOCKLIST bl;
    int rc;
    TEST("init with NULL args fails");
    rc = blocklist_init(NULL, test_alloc, test_free, NULL,
                        test_lock, test_unlock, NULL);
    ASSERT_EQ(rc, BL_ERR_NULL_ARG, "NULL bl should fail");
    rc = blocklist_init(&bl, NULL, test_free, NULL,
                        test_lock, test_unlock, NULL);
    ASSERT_EQ(rc, BL_ERR_NULL_ARG, "NULL alloc should fail");
    rc = blocklist_init(&bl, test_alloc, NULL, NULL,
                        test_lock, test_unlock, NULL);
    ASSERT_EQ(rc, BL_ERR_NULL_ARG, "NULL free should fail");
    rc = blocklist_init(&bl, test_alloc, test_free, NULL,
                        NULL, test_unlock, NULL);
    ASSERT_EQ(rc, BL_ERR_NULL_ARG, "NULL lock should fail");
    rc = blocklist_init(&bl, test_alloc, test_free, NULL,
                        test_lock, NULL, NULL);
    ASSERT_EQ(rc, BL_ERR_NULL_ARG, "NULL unlock should fail");
    PASS();
}

static void test_add_single(void)
{
    BLOCKLIST *bl = make_bl();
    int rc;
    TEST("add single path");
    ASSERT_NEQ(bl, NULL, "make_bl failed");
    rc = blocklist_add(bl, L"C:\\Windows\\System32\\evil.exe");
    ASSERT_EQ(rc, BL_SUCCESS, "add should succeed");
    ASSERT_EQ(blocklist_count(bl), 1, "count should be 1");
    free_bl(bl);
    PASS();
}

static void test_contains_added(void)
{
    BLOCKLIST *bl = make_bl();
    TEST("contains returns 1 for added path");
    ASSERT_NEQ(bl, NULL, "make_bl failed");
    blocklist_add(bl, L"C:\\Temp\\malware.exe");
    ASSERT_EQ(blocklist_contains(bl, L"C:\\Temp\\malware.exe"), 1,
              "should find added path");
    free_bl(bl);
    PASS();
}

static void test_contains_not_added(void)
{
    BLOCKLIST *bl = make_bl();
    TEST("contains returns 0 for non-added path");
    ASSERT_NEQ(bl, NULL, "make_bl failed");
    blocklist_add(bl, L"C:\\Temp\\malware.exe");
    ASSERT_EQ(blocklist_contains(bl, L"C:\\Temp\\benign.exe"), 0,
              "should not find non-added path");
    free_bl(bl);
    PASS();
}

static void test_case_insensitive(void)
{
    BLOCKLIST *bl = make_bl();
    TEST("case-insensitive matching");
    ASSERT_NEQ(bl, NULL, "make_bl failed");
    blocklist_add(bl, L"C:\\Temp\\Malware.EXE");
    /* Different case should still match after normalization. */
    ASSERT_EQ(blocklist_contains(bl, L"c:\\temp\\malware.exe"), 1,
              "lowercase should match");
    ASSERT_EQ(blocklist_contains(bl, L"C:\\TEMP\\MALWARE.EXE"), 1,
              "uppercase should match");
    free_bl(bl);
    PASS();
}

static void test_forward_slash_normalization(void)
{
    BLOCKLIST *bl = make_bl();
    TEST("forward-slash normalization");
    ASSERT_NEQ(bl, NULL, "make_bl failed");
    blocklist_add(bl, L"C:/Temp/malware.exe");
    /* Should match with backslashes. */
    ASSERT_EQ(blocklist_contains(bl, L"C:\\Temp\\malware.exe"), 1,
              "forward-slash add should match backslash query");
    free_bl(bl);
    PASS();
}

static void test_duplicate_add(void)
{
    BLOCKLIST *bl = make_bl();
    int rc;
    TEST("duplicate add returns BL_ERR_DUPLICATE");
    ASSERT_NEQ(bl, NULL, "make_bl failed");
    blocklist_add(bl, L"C:\\Temp\\evil.exe");
    rc = blocklist_add(bl, L"C:\\Temp\\evil.exe");
    ASSERT_EQ(rc, BL_ERR_DUPLICATE, "second add should be duplicate");
    /* Case-different duplicate should also fail. */
    rc = blocklist_add(bl, L"c:\\temp\\evil.exe");
    ASSERT_EQ(rc, BL_ERR_DUPLICATE, "case-different add should be duplicate");
    ASSERT_EQ(blocklist_count(bl), 1, "count should still be 1");
    free_bl(bl);
    PASS();
}

static void test_remove_existing(void)
{
    BLOCKLIST *bl = make_bl();
    int rc;
    TEST("remove existing path");
    ASSERT_NEQ(bl, NULL, "make_bl failed");
    blocklist_add(bl, L"C:\\Temp\\evil.exe");
    ASSERT_EQ(blocklist_count(bl), 1, "count should be 1 before remove");
    rc = blocklist_remove(bl, L"C:\\Temp\\evil.exe");
    ASSERT_EQ(rc, BL_SUCCESS, "remove should succeed");
    ASSERT_EQ(blocklist_count(bl), 0, "count should be 0 after remove");
    free_bl(bl);
    PASS();
}

static void test_remove_nonexistent(void)
{
    BLOCKLIST *bl = make_bl();
    int rc;
    TEST("remove non-existing returns BL_ERR_NOT_FOUND");
    ASSERT_NEQ(bl, NULL, "make_bl failed");
    rc = blocklist_remove(bl, L"C:\\nothing\\here.exe");
    ASSERT_EQ(rc, BL_ERR_NOT_FOUND, "remove should fail");
    free_bl(bl);
    PASS();
}

static void test_contains_after_remove(void)
{
    BLOCKLIST *bl = make_bl();
    TEST("contains after remove returns 0");
    ASSERT_NEQ(bl, NULL, "make_bl failed");
    blocklist_add(bl, L"C:\\Temp\\evil.exe");
    blocklist_remove(bl, L"C:\\Temp\\evil.exe");
    ASSERT_EQ(blocklist_contains(bl, L"C:\\Temp\\evil.exe"), 0,
              "removed path should not be found");
    free_bl(bl);
    PASS();
}

static void test_empty_contains(void)
{
    BLOCKLIST *bl = make_bl();
    TEST("empty blocklist: contains returns 0");
    ASSERT_NEQ(bl, NULL, "make_bl failed");
    ASSERT_EQ(blocklist_contains(bl, L"C:\\anything.exe"), 0,
              "empty list should have nothing");
    free_bl(bl);
    PASS();
}

static void test_path_too_long(void)
{
    WCHAR longpath[SENTINEL_MAX_PATH + 10];
    BLOCKLIST *bl = make_bl();
    int rc;
    size_t i;
    TEST("path too long returns BL_ERR_PATH_TOO_LONG");
    ASSERT_NEQ(bl, NULL, "make_bl failed");
    /* Fill with 'A' characters beyond max. */
    for (i = 0; i < SENTINEL_MAX_PATH + 5; i++)
        longpath[i] = L'A';
    longpath[SENTINEL_MAX_PATH + 5] = L'\0';
    rc = blocklist_add(bl, longpath);
    ASSERT_EQ(rc, BL_ERR_PATH_TOO_LONG, "should reject too-long path");
    free_bl(bl);
    PASS();
}

static void test_sorted_order(void)
{
    BLOCKLIST *bl = make_bl();
    BL_ENTRY *cur;
    TEST("multiple entries maintained in sorted order");
    ASSERT_NEQ(bl, NULL, "make_bl failed");
    /* Add in reverse order — they should be stored sorted. */
    blocklist_add(bl, L"C:\\Zzz\\last.exe");
    blocklist_add(bl, L"C:\\Aaa\\first.exe");
    blocklist_add(bl, L"C:\\Mmm\\middle.exe");
    ASSERT_EQ(blocklist_count(bl), 3, "count should be 3");
    /* Verify sorted order. */
    cur = bl->head;
    ASSERT_NEQ(cur, NULL, "head should not be NULL");
    /* After normalization: C:\AAA\FIRST.EXE < C:\MMM\MIDDLE.EXE < C:\ZZZ\LAST.EXE */
    ASSERT_EQ(cur->path[2], L'A', "first entry should start with A");
    cur = cur->next;
    ASSERT_NEQ(cur, NULL, "second entry should exist");
    ASSERT_EQ(cur->path[2], L'M', "second entry should start with M");
    cur = cur->next;
    ASSERT_NEQ(cur, NULL, "third entry should exist");
    ASSERT_EQ(cur->path[2], L'Z', "third entry should start with Z");
    free_bl(bl);
    PASS();
}

static void test_stress(void)
{
    BLOCKLIST *bl = make_bl();
    WCHAR path[SENTINEL_MAX_PATH];
    int i, rc;
    TEST("stress: add 500 entries, verify all, remove all");
    ASSERT_NEQ(bl, NULL, "make_bl failed");

    for (i = 0; i < 500; i++) {
        swprintf(path, SENTINEL_MAX_PATH, L"C:\\Stress\\File_%04d.exe", i);
        rc = blocklist_add(bl, path);
        ASSERT_EQ(rc, BL_SUCCESS, "add should succeed in stress");
    }
    ASSERT_EQ(blocklist_count(bl), 500, "count should be 500");

    /* Verify all present. */
    for (i = 0; i < 500; i++) {
        swprintf(path, SENTINEL_MAX_PATH, L"C:\\Stress\\File_%04d.exe", i);
        ASSERT_EQ(blocklist_contains(bl, path), 1, "should find stress entry");
    }

    /* Remove all. */
    for (i = 0; i < 500; i++) {
        swprintf(path, SENTINEL_MAX_PATH, L"C:\\Stress\\File_%04d.exe", i);
        rc = blocklist_remove(bl, path);
        ASSERT_EQ(rc, BL_SUCCESS, "remove should succeed in stress");
    }
    ASSERT_EQ(blocklist_count(bl), 0, "count should be 0 after removing all");

    free_bl(bl);
    PASS();
}

static void test_destroy_frees_all(void)
{
    BLOCKLIST *bl = make_bl();
    TEST("destroy frees all entries");
    ASSERT_NEQ(bl, NULL, "make_bl failed");
    g_alloc_count = 0;
    blocklist_add(bl, L"C:\\A.exe");
    blocklist_add(bl, L"C:\\B.exe");
    blocklist_add(bl, L"C:\\C.exe");
    ASSERT_EQ(g_alloc_count, 3, "should have 3 allocations");
    blocklist_destroy(bl);
    ASSERT_EQ(g_alloc_count, 0, "all allocations should be freed");
    free(bl);  /* Free the struct itself (not tracked). */
    PASS();
}

/* ----------------------------------------------------------------------- */
/* Main                                                                    */
/* ----------------------------------------------------------------------- */

int main(void)
{
    printf("=== Sentinel Blocklist User-Mode Tests ===\n\n");

    test_init_valid();
    test_init_null_args();
    test_add_single();
    test_contains_added();
    test_contains_not_added();
    test_case_insensitive();
    test_forward_slash_normalization();
    test_duplicate_add();
    test_remove_existing();
    test_remove_nonexistent();
    test_contains_after_remove();
    test_empty_contains();
    test_path_too_long();
    test_sorted_order();
    test_stress();
    test_destroy_frees_all();

    printf("\n=== Results ===\n");
    printf("  PASSED: %d\n", g_passed);
    printf("  FAILED: %d\n", g_failed);

    if (g_failed) {
        printf("\n=== %d FAILURE(S) ===\n", g_failed);
        return 1;
    }
    printf("\n=== ALL PASS ===\n");
    return 0;
}
